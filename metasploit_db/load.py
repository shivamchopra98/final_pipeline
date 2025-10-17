# load.py
import re
import time
import json
import hashlib
import math
from decimal import Decimal
from typing import List, Dict, Optional
import boto3
from botocore.exceptions import ClientError

# Config defaults (override via user_cfg)
DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-vuln-metasploit-data",
    "S3_PREFIX": "vuln-raw-source/metasploit/",
    "BASELINE_FILENAME": "metasploit_baseline.json",
    "BATCH_PROGRESS_INTERVAL": 500,
    "BATCH_WRITE_CHUNK_SIZE": 500,
    "AWS_REGION": "us-east-1",
    "SKIP_S3_UPLOAD": False,   # set True to avoid uploading merged baseline to S3
}

META_ID_PREFIX = "META"
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def _resolve_config(user_cfg: Dict) -> Dict:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg.get("S3_PREFIX") and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] += "/"
    return cfg


def _clean_for_hash(v) -> str:
    if v is None:
        return ""
    s = str(v)
    # normalize whitespace and remove newlines
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _compute_content_hash_for_record(rec: Dict, canonical_fields: List[str]) -> str:
    # create stable string of canonical fields joined by '|'
    parts = []
    for f in canonical_fields:
        parts.append(_clean_for_hash(rec.get(f, "")))
    joined = "|".join(parts).encode("utf-8")
    return hashlib.sha256(joined).hexdigest()


def _extract_cve(refs):
    if not refs:
        return None
    m = CVE_RE.search(str(refs))
    return m.group(1).upper() if m else None


def _normalize_for_ddb(v):
    if v is None:
        return None
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        return Decimal(str(v))
    if isinstance(v, Decimal):
        return v
    if isinstance(v, str):
        s = v.strip()
        if s.lower() in {"none", "nan", ""}:
            return None
        # try numeric conversion if numeric string
        try:
            if re.fullmatch(r"-?\d+(\.\d+)?", s):
                return Decimal(s)
        except Exception:
            pass
        return s
    # fallback to string representation
    return str(v)


def _s3_put_bytes(s3_client, bucket: str, key: str, data: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=data)


def _s3_get_text_if_exists(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        res = s3_client.get_object(Bucket=bucket, Key=key)
        return res["Body"].read().decode("utf-8")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NoSuchBucket", "NoSuchKey"):
            return None
        raise


def _next_meta_id_for_year(existing_ids_set, year: int) -> str:
    max_seq = 0
    pattern = re.compile(rf"^{META_ID_PREFIX}-(\d{{4}})-0*(\d+)$")
    for mid in existing_ids_set:
        m = pattern.match(str(mid))
        if not m:
            continue
        try:
            y, seq = int(m.group(1)), int(m.group(2))
            if y == year and seq > max_seq:
                max_seq = seq
        except Exception:
            continue
    return f"{META_ID_PREFIX}-{year}-{str(max_seq + 1).zfill(6)}"


def _write_chunk(table, chunk: List[Dict], progress_fn=None):
    # uses batch_writer - let boto3 handle retries
    written = 0
    with table.batch_writer() as batch:
        for rec in chunk:
            safe_item = {k: _normalize_for_ddb(v) for k, v in rec.items()}
            # ensure id exists as string (DDB hash key)
            if safe_item.get("id") is None:
                safe_item["id"] = str(rec.get("id") or "")
            try:
                batch.put_item(Item=safe_item)
                written += 1
            except Exception as e:
                # log and continue for resilience
                print(f"❌ Failed to write id={safe_item.get('id')}: {e}")
            if progress_fn:
                progress_fn(1)
    return written


def sync_records_to_dynamodb_and_store_baseline(records: List[Dict], json_bytes: bytes, user_cfg: Dict) -> Dict:
    """
    Compare incoming metasploit records against DynamoDB table contents (not S3 baseline).
    Only writes new/changed modules. Merges baseline and uploads to S3 (unless SKIP_S3_UPLOAD).
    """
    cfg = _resolve_config(user_cfg)
    s3_bucket = cfg.get("S3_BUCKET")
    s3_prefix = cfg.get("S3_PREFIX")
    baseline_key = f"{s3_prefix}{cfg['BASELINE_FILENAME']}"
    table_name = cfg["TABLE_NAME"]

    if not s3_bucket:
        raise RuntimeError("S3_BUCKET must be set in config/env")

    # boto3 clients
    s3 = boto3.client(
        "s3",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY"),
        region_name=cfg.get("AWS_REGION")
    )
    ddb = boto3.resource(
        "dynamodb",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY"),
        region_name=cfg.get("AWS_REGION")
    )

    # Ensure DDB table exists (create if missing)
    existing_tables = ddb.meta.client.list_tables().get("TableNames", [])
    first_run = False
    if table_name not in existing_tables:
        print(f"⚡ Creating DynamoDB table '{table_name}'...")
        t = ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        )
        t.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
        first_run = True
    table = ddb.Table(table_name)

    # Build canonical_fields from incoming records (exclude volatile fields)
    volatile = {"id", "module_id", "uploaded_date", "cve_id", "content_hash"}
    canonical_fields = []
    if records:
        canonical_fields = [k for k in records[0].keys() if k not in volatile]
    # Make deterministic order
    canonical_fields = sorted(canonical_fields)

    # Scan DynamoDB table and construct baseline_map with computed content_hash
    print(f"🔁 Scanning existing records from DynamoDB table '{table_name}' ...")
    baseline_map: Dict[str, Dict] = {}           # keyed by module_key
    existing_generated_ids = set()
    try:
        paginator = table.meta.client.get_paginator("scan")
        scan_kwargs = {"TableName": table_name}
        # We'll request all attributes; if table large consider limiting ProjectionExpression
        for page in paginator.paginate(**scan_kwargs):
            for item in page.get("Items", []):
                # item may be missing module_key (older rows) - try common keys
                mk = item.get("module_key") or item.get("module_id") or item.get("moduleKey") or item.get("module")
                if not mk:
                    # store under synthetic key using id to avoid losing it
                    mk = f"_id_{item.get('id')}"
                # normalize keys to strings
                mk = str(mk)
                baseline_map[mk] = dict(item)  # keep raw item
                if "id" in item:
                    existing_generated_ids.add(item["id"])
    except Exception as e:
        print(f"⚠️ Warning: DynamoDB scan error: {e}. Proceeding with empty baseline.")
        baseline_map = {}

    print(f"ℹ️ Found {len(baseline_map)} modules in DynamoDB and {len(existing_generated_ids)} existing generated ids")

    # Compute content_hash for baseline items using same canonical_fields
    baseline_hashes = {}
    for mk, item in baseline_map.items():
        # build a normalized dict with canonical_fields only
        try:
            # ensure keys exist even if missing
            normalized = {k: item.get(k) for k in canonical_fields}
            baseline_hashes[mk] = _compute_content_hash_for_record(normalized, canonical_fields)
        except Exception:
            baseline_hashes[mk] = ""

    # Build incoming current_map keyed by module_key
    current_map: Dict[str, Dict] = {}
    for rec in records:
        mk = rec.get("module_key") or rec.get("module_id")
        if not mk:
            continue
        mk = str(mk)
        current_map[mk] = dict(rec)

    print(f"ℹ️ Incoming records to evaluate: {len(current_map)} modules")

    # Compute content_hash for incoming records
    current_hashes = {}
    for mk, rec in current_map.items():
        current_hashes[mk] = _compute_content_hash_for_record(rec, canonical_fields)

    # Determine which modules changed or are new
    changed_keys = []
    for mk, rec in current_map.items():
        base_hash = baseline_hashes.get(mk)
        cur_hash = current_hashes.get(mk)
        if base_hash != cur_hash:
            changed_keys.append(mk)

    print(f"ℹ️ Modules to write: {len(changed_keys)} (out of {len(current_map)})")

    # Prepare items to write: set id (preserve existing id if any), module_id/module_key, uploaded_date, cve_id
    to_write = []
    existing_ids = set(existing_generated_ids)  # copy
    for mk in changed_keys:
        rec = dict(current_map[mk])
        # preserve id if baseline had it
        base = baseline_map.get(mk, {}) or {}
        existing_id = base.get("id")
        if existing_id:
            gen_id = existing_id
        else:
            # generate new id for this year
            year = int(str(rec.get("uploaded_date") or time.strftime("%Y"))[:4])
            gen_id = _next_meta_id_for_year(existing_ids, year)
            existing_ids.add(gen_id)
        rec["id"] = gen_id
        # keep both module_key and module_id for compatibility
        rec["module_key"] = mk
        rec["module_id"] = mk
        rec["uploaded_date"] = rec.get("uploaded_date") or time.strftime("%Y-%m-%d")
        if not rec.get("cve_id"):
            rec["cve_id"] = _extract_cve(rec.get("references"))
        # include computed content_hash for reference (stored in baseline but not strictly required in DDB)
        rec["content_hash"] = current_hashes.get(mk, "")
        to_write.append(rec)

    # Batch write changed items to DynamoDB (respect chunk size)
    written = 0
    if to_write:
        chunk_size = int(cfg.get("BATCH_WRITE_CHUNK_SIZE", 500))
        total = len(to_write)
        def progress_fn(n):
            nonlocal written
            written += n
            if written % cfg.get("BATCH_PROGRESS_INTERVAL", 500) == 0 or written == total:
                print(f"⬆️ Batch wrote {written}/{total}")
        # chunk and write
        chunk = []
        for rec in to_write:
            chunk.append(rec)
            if len(chunk) >= chunk_size:
                _write_chunk(table, chunk, progress_fn)
                chunk = []
        if chunk:
            _write_chunk(table, chunk, progress_fn)

        print(f"✅ Uploaded {written} item(s) to DynamoDB")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Build merged baseline (map of module_key -> merged entry)
    merged = {}
    # start with baseline entries (existing ones)
    for mk, item in baseline_map.items():
        merged[mk] = dict(item)
    # overwrite / add with current_map entries (preserve id where present)
    for mk, rec in current_map.items():
        entry = dict(rec)
        base_entry = merged.get(mk, {}) or {}
        # prefer existing id
        if not entry.get("id") and base_entry.get("id"):
            entry["id"] = base_entry.get("id")
        # ensure module_key present
        entry["module_key"] = mk
        if not entry.get("cve_id"):
            entry["cve_id"] = base_entry.get("cve_id") or _extract_cve(entry.get("references"))
        # include content_hash for stable S3 baseline if you want to keep hashing
        entry["content_hash"] = current_hashes.get(mk, baseline_hashes.get(mk, ""))
        merged[mk] = entry

    # Upload merged baseline to S3 (unless skipped)
    if not cfg.get("SKIP_S3_UPLOAD", False):
        try:
            baseline_list = list(merged.values())
            baseline_bytes = json.dumps(baseline_list, ensure_ascii=False, indent=2).encode("utf-8")
            print(f"⬆️ Uploading baseline JSON to s3://{s3_bucket}/{baseline_key}")
            _s3_put_bytes(s3, s3_bucket, baseline_key, baseline_bytes)
            print("✅ Baseline upload complete")
            s3_uploaded = True
        except Exception as e:
            print(f"⚠️ Failed to upload baseline JSON to S3: {e}")
            s3_uploaded = False
    else:
        print("ℹ️ SKIP_S3_UPLOAD set. Not uploading baseline to S3.")
        s3_uploaded = False

    return {
        "uploaded": written,
        "changed_keys": len(changed_keys),
        "total_current": len(current_map),
        "s3_baseline_uploaded": s3_uploaded,
        "s3_baseline": f"s3://{s3_bucket}/{baseline_key}" if s3_uploaded else None
    }
