# load_epss_incremental.py
import json
import math
from decimal import Decimal
from typing import List, Dict, Any, Optional, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
import threading

DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-epss-data",
    "S3_PREFIX": "vuln-raw-source/epss/",
    "BASELINE_FILENAME": "epss_baseline.json",
    "BATCH_PROGRESS_INTERVAL": 500,
    "BATCH_WRITE_CHUNK_SIZE": 100,  # smaller to control throughput
    "PARALLEL_THREADS": 5,  # fewer threads = fewer ProvisionedThroughput errors
    "S3_FLUSH_INTERVAL": 1000,  # flush every 1000 records
    "AWS_REGION": "us-east-1",
    "DDB_ENDPOINT": "",
}


def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg.get("S3_PREFIX") and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] += "/"
    return cfg


def _chunks(iterable: Iterable, n: int):
    chunk = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= n:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def _to_ddb_safe(v):
    if v is None:
        return None
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        return Decimal(str(v))
    if isinstance(v, (int, Decimal)):
        return v
    if isinstance(v, (list, dict)):
        try:
            return json.dumps(v, sort_keys=True, ensure_ascii=False)
        except Exception:
            return str(v)
    s = str(v).strip()
    if s == "" or s.lower() in ("none", "nan"):
        return None
    return s


VOLATILE_FIELDS = {"date_updated"}


def _canonical_for_compare(obj):
    if obj is None:
        return None
    if isinstance(obj, dict):
        return {k: _canonical_for_compare(v) for k, v in sorted(obj.items()) if k not in VOLATILE_FIELDS}
    if isinstance(obj, list):
        return [_canonical_for_compare(i) for i in obj]
    return obj


def _serialize_canonical(obj):
    try:
        return json.dumps(_canonical_for_compare(obj), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return json.dumps(obj, default=str, sort_keys=True, ensure_ascii=False)


def _s3_get_text_if_exists(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read().decode("utf-8")
    except ClientError as e:
        if e.response.get("Error", {}).get("Code", "") in ("NoSuchKey", "404", "NotFound"):
            return None
        raise


def _s3_put_bytes(s3_client, bucket: str, key: str, bts: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=bts)


def _write_chunk(ddb_table, chunk: List[Dict[str, Any]]):
    with ddb_table.batch_writer() as batch:
        for rec in chunk:
            item = {}
            for k, v in rec.items():
                val = _to_ddb_safe(v)
                if val is not None:
                    item[k] = val
            item["cve"] = str(item.get("cve") or rec.get("cve")).upper()
            batch.put_item(Item=item)
    return len(chunk)


def sync_epss_records_to_dynamodb_and_s3(records: List[Dict[str, Any]], json_bytes: bytes, user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _resolve_cfg(user_cfg)
    s3_bucket = cfg.get("S3_BUCKET")
    s3_prefix = cfg.get("S3_PREFIX")
    baseline_key = f"{s3_prefix}{cfg['BASELINE_FILENAME']}"

    if not s3_bucket:
        raise RuntimeError("S3_BUCKET must be set in config/env")

    botocfg = Config(connect_timeout=10, read_timeout=60, retries={"max_attempts": 3, "mode": "standard"})
    s3 = boto3.client("s3", region_name=cfg["AWS_REGION"], config=botocfg)
    ddb_kwargs = {"region_name": cfg["AWS_REGION"]}
    if cfg.get("DDB_ENDPOINT"):
        ddb_kwargs["endpoint_url"] = cfg.get("DDB_ENDPOINT")
    ddb = boto3.resource("dynamodb", **ddb_kwargs)
    table = ddb.Table(cfg["TABLE_NAME"])

    # Load existing baseline
    print(f"🔁 Fetching baseline from s3://{s3_bucket}/{baseline_key}")
    baseline_text = _s3_get_text_if_exists(s3, s3_bucket, baseline_key)
    baseline_map = {}
    if baseline_text:
        try:
            baseline_list = json.loads(baseline_text)
            for item in baseline_list:
                k = item.get("cve")
                if k:
                    baseline_map[k.upper()] = item
            print(f"ℹ️ Loaded {len(baseline_map)} entries from baseline")
        except Exception as e:
            print(f"⚠️ Failed to parse baseline JSON: {e}")

    # Build current map and detect differences
    current_map = {r["cve"].upper(): r for r in records if r.get("cve")}
    baseline_serial = {k: _serialize_canonical(v) for k, v in baseline_map.items()}
    current_serial = {k: _serialize_canonical(v) for k, v in current_map.items()}
    to_write = [rec for k, rec in current_map.items() if current_serial.get(k) != baseline_serial.get(k)]

    print(f"🚀 Writing {len(to_write)} new/updated records...")

    written = 0
    chunk_size = cfg["BATCH_WRITE_CHUNK_SIZE"]
    flush_every = cfg["S3_FLUSH_INTERVAL"]

    lock = threading.Lock()

    def flush_to_s3():
        baseline_bytes = json.dumps(list(baseline_map.values()), ensure_ascii=False, indent=2).encode("utf-8")
        try:
            _s3_put_bytes(s3, s3_bucket, baseline_key, baseline_bytes)
            print(f"💾 Flushed {len(baseline_map)} baseline records to S3")
        except Exception as e:
            print(f"⚠️ Failed to flush to S3: {e}")

    for chunk in _chunks(to_write, chunk_size):
        _write_chunk(table, chunk)
        with lock:
            for rec in chunk:
                baseline_map[rec["cve"].upper()] = rec
            written += len(chunk)
            if written % flush_every == 0:
                flush_to_s3()
            if written % cfg["BATCH_PROGRESS_INTERVAL"] == 0 or written == len(to_write):
                print(f"⬆️ Wrote {written}/{len(to_write)} items")

    flush_to_s3()
    print(f"✅ Completed sync: {written} written, {len(baseline_map)} total baseline records")
    return {"written": written, "total_baseline": len(baseline_map)}
