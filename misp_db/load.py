# load.py
import os
import json
import math
import time
from decimal import Decimal
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

# Default config keys used by misp_main.py
DEFAULT_CONFIG = {
    "TABLE_NAME": "misp_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "S3_BUCKET": None,
    "S3_PREFIX": "vuln-raw-source/misp/",
    "BASELINE_FILENAME": "misp_baseline.json",
    "BATCH_PROGRESS_INTERVAL": 100,
    "AWS_ACCESS_KEY_ID": None,
    "AWS_SECRET_ACCESS_KEY": None,
}

def _resolve_cfg(user_cfg: Optional[Dict[str,Any]]) -> Dict[str,Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] = cfg["S3_PREFIX"] + "/"
    return cfg

# ---- S3 helpers ----
def _s3_get_text_if_exists(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read().decode("utf-8")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NoSuchBucket", "NoSuchKey"):
            return None
        raise

def _s3_put_bytes(s3_client, bucket: str, key: str, bts: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=bts)

# ---- DynamoDB-safe normalization ----
def _to_ddb_safe(v):
    """
    Convert Python value to a DynamoDB-safe type:
      - float -> Decimal
      - int/Decimal -> as-is
      - list/dict -> JSON string (stable)
      - None -> None
      - other -> trimmed string
    We stringify lists/dicts to preserve full structure while maintaining deterministic comparisons.
    """
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
    if s == "" or s.lower() in {"nan", "none"}:
        return None
    return s

# ---- main sync function ----
def sync_misp_records_to_dynamodb_and_s3(records: List[Dict[str,Any]], json_bytes: bytes, user_cfg: Dict[str,Any]) -> Dict[str,Any]:
    """
    records: list of dicts (must contain 'uuid')
    json_bytes: transformed JSON bytes (we will upload baseline_bytes to S3)
    user_cfg: overrides (S3_BUCKET required)
    """
    cfg = _resolve_cfg(user_cfg)
    s3_bucket = cfg["S3_BUCKET"]
    s3_prefix = cfg["S3_PREFIX"]
    baseline_key = f"{s3_prefix}{cfg['BASELINE_FILENAME']}"

    if not s3_bucket:
        raise RuntimeError("S3_BUCKET missing in config")

    # boto3 clients
    s3 = boto3.client(
        "s3",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID") or None,
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY") or None,
        region_name=cfg.get("AWS_REGION")
    )
    ddb = boto3.resource(
        "dynamodb",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID") or None,
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY") or None,
        region_name=cfg.get("AWS_REGION"),
        endpoint_url=cfg.get("DDB_ENDPOINT")
    )

    # Ensure table exists (create if missing)
    table_name = cfg["TABLE_NAME"]
    existing_tables = ddb.meta.client.list_tables().get("TableNames", [])
    if table_name not in existing_tables:
        print(f"⚡ Creating DynamoDB table '{table_name}'...")
        t = ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "uuid", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "uuid", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        )
        t.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    table = ddb.Table(table_name)

    # Fetch baseline from S3 (if exists)
    print(f"🔁 Fetching baseline from s3://{s3_bucket}/{baseline_key}")
    baseline_text = _s3_get_text_if_exists(s3, s3_bucket, baseline_key)
    baseline_map: Dict[str, Dict[str,Any]] = {}
    if baseline_text:
        try:
            baseline_list = json.loads(baseline_text)
            for item in baseline_list:
                uid = item.get("uuid")
                if uid:
                    baseline_map[str(uid)] = item
            print(f"ℹ️ Baseline loaded with {len(baseline_map)} entries")
        except Exception as e:
            print(f"⚠️ Failed to parse baseline JSON from S3: {e}")
            baseline_map = {}
    else:
        print("ℹ️ No baseline found (first run)")

    # Build current_map keyed by uuid
    current_map: Dict[str, Dict[str,Any]] = {}
    for rec in records:
        uid = rec.get("uuid") or rec.get("id") or rec.get("value")
        if not uid:
            continue
        current_map[str(uid)] = rec

    total_current = len(current_map)
    print(f"ℹ️ Total current records discovered: {total_current}")

    # Determine new/changed by canonicalized JSON comparison
    to_write = []
    for uid, rec in current_map.items():
        base = baseline_map.get(uid)
        try:
            def canonical(obj):
                if obj is None:
                    return None
                if isinstance(obj, (list, dict)):
                    return json.loads(json.dumps(obj, sort_keys=True, ensure_ascii=False))
                return obj
            rec_canon = {k: canonical(rec.get(k)) for k in sorted(rec.keys())}
            base_canon = None
            if base is not None:
                base_canon = {k: canonical(base.get(k)) for k in sorted(base.keys())}
            rec_serial = json.dumps(rec_canon, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            base_serial = json.dumps(base_canon, sort_keys=True, ensure_ascii=False, separators=(",", ":")) if base_canon is not None else ""
        except Exception:
            rec_serial = json.dumps(rec, default=str, sort_keys=True, ensure_ascii=False)
            base_serial = json.dumps(base, default=str, sort_keys=True, ensure_ascii=False) if base else ""

        if base is None or rec_serial != base_serial:
            to_write.append(rec)

    print(f"ℹ️ New/changed records to write: {len(to_write)}")

    # Write only new/changed items to DynamoDB (batch_writer)
    written = 0
    if to_write:
        print(f"⬆️ Writing {len(to_write)} items to DynamoDB...")
        with table.batch_writer() as batch:
            for i, rec in enumerate(to_write, start=1):
                safe_item = {}
                # flatten meta dict into meta.* keys (if still present) and convert nested types to JSON strings
                for k, v in rec.items():
                    # if a nested dict under top-level 'meta' still exists, expand it
                    if k == "meta" and isinstance(v, dict):
                        for mk, mv in v.items():
                            safe_item[f"meta.{mk}"] = _to_ddb_safe(mv)
                        # optional: keep original meta as JSON string too
                        safe_item["meta"] = _to_ddb_safe(v)
                    else:
                        safe_item[k] = _to_ddb_safe(v)
                # ensure uuid is string
                safe_item["uuid"] = str(safe_item.get("uuid") or rec.get("uuid") or rec.get("id") or rec.get("value"))
                try:
                    batch.put_item(Item=safe_item)
                    written += 1
                except ClientError as e:
                    print(f"❌ Failed to write uuid={safe_item.get('uuid')}: {e}")
                if i % cfg.get("BATCH_PROGRESS_INTERVAL", 100) == 0 or i == len(to_write):
                    print(f"⬆️ Batch wrote {i}/{len(to_write)} items")
        print(f"✅ DynamoDB writes complete: uploaded={written}")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Merge baseline_map with current_map (current wins)
    merged = baseline_map.copy()
    for uid, rec in current_map.items():
        merged[uid] = rec

    baseline_list = list(merged.values())
    baseline_bytes = json.dumps(baseline_list, ensure_ascii=False, indent=2).encode("utf-8")

    # Upload baseline to S3 (single canonical file)
    print(f"⬆️ Uploading baseline JSON to s3://{s3_bucket}/{baseline_key}")
    _s3_put_bytes(s3, s3_bucket, baseline_key, baseline_bytes)
    print("✅ Baseline uploaded")

    summary = {
        "total_current": total_current,
        "to_write": len(to_write),
        "written": written,
        "s3_baseline": f"s3://{s3_bucket}/{baseline_key}"
    }
    print("ℹ️ Sync summary:", summary)
    return summary
