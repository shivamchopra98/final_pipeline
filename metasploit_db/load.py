# load_metasploit.py
import re
import time
import json
import hashlib
import math
from decimal import Decimal
from typing import List, Dict
import boto3
from botocore.exceptions import ClientError

# Config defaults (override via user_cfg)
DEFAULT_CONFIG = {
    "TABLE_NAME": "metasploit_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "S3_BUCKET": None,
    "S3_PREFIX": "vuln-raw-source/metasploit/",
    "BASELINE_FILENAME": "metasploit_baseline.json",  # this will be the single canonical file on S3
    "BATCH_PROGRESS_INTERVAL": 100,
    "AWS_ACCESS_KEY_ID": None,
    "AWS_SECRET_ACCESS_KEY": None,
}

META_ID_PREFIX = "META"
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)


def _resolve_config(user_cfg: Dict) -> Dict:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] = cfg["S3_PREFIX"] + "/"
    return cfg

def _clean_for_hash(v) -> str:
    """Canonicalize a field value for hashing: None -> '', collapse whitespace, strip."""
    if v is None:
        return ""
    s = str(v)
    s = s.replace("\r", " ").replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _compute_content_hash_for_record(rec: Dict, canonical_fields: List[str]) -> str:
    pieces = []
    for f in canonical_fields:
        pieces.append(_clean_for_hash(rec.get(f)))
    joined = "|".join(pieces)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()

def _extract_cve(refs):
    if not refs:
        return None
    m = CVE_RE.search(str(refs))
    return m.group(1).upper() if m else None

def _normalize_for_ddb(v):
    """Prepare value for DynamoDB: floats/number-strings -> Decimal, None -> None, else string."""
    if v is None:
        return None
    # floats
    if isinstance(v, float):
        if math.isnan(v) or math.isinf(v):
            return None
        try:
            return Decimal(str(v))
        except Exception:
            return str(v)
    # Decimal pass-through
    if isinstance(v, Decimal):
        return v
    # strings: numeric check
    if isinstance(v, str):
        s = v.strip()
        if s == "" or s.lower() in {"none", "nan"}:
            return None
        if re.fullmatch(r"-?\d+(\.\d+)?", s):
            try:
                return Decimal(s)
            except Exception:
                return s
        return s
    # fallback
    try:
        return str(v)
    except Exception:
        return None

def _s3_put_bytes(s3_client, bucket: str, key: str, data: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=data)

def _s3_get_text_if_exists(s3_client, bucket: str, key: str):
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
    for mid in existing_ids_set:
        m = re.match(rf"^{META_ID_PREFIX}-(\d{{4}})-0*(\d+)$", str(mid))
        if not m:
            continue
        try:
            y = int(m.group(1)); seq = int(m.group(2))
        except Exception:
            continue
        if y == year and seq > max_seq:
            max_seq = seq
    return f"{META_ID_PREFIX}-{year}-{str(max_seq + 1).zfill(6)}"

def sync_records_to_dynamodb_and_store_baseline(records: List[Dict], json_bytes: bytes, user_cfg: Dict) -> Dict:
    """
    records: list of normalized dicts (each must include 'module_key' and canonical fields)
    json_bytes: transformed JSON bytes (not uploaded directly anymore)
    user_cfg: config overrides; must include S3_BUCKET
    """
    cfg = _resolve_config(user_cfg)
    s3_bucket = cfg["S3_BUCKET"]
    s3_prefix = cfg["S3_PREFIX"]
    baseline_key = f"{s3_prefix}{cfg['BASELINE_FILENAME']}"
    canonical_key = baseline_key  # single canonical = baseline

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
        region_name=cfg.get("AWS_REGION"),
        endpoint_url=cfg.get("DDB_ENDPOINT")
    )

    # NOTE: we no longer upload json_bytes separately.
    # We will upload the merged baseline JSON (which becomes the single canonical S3 object).

    # Fetch baseline JSON from S3 if exists
    print(f"🔁 Fetching baseline from s3://{s3_bucket}/{baseline_key}")
    baseline_text = _s3_get_text_if_exists(s3, s3_bucket, baseline_key)
    baseline_map = {}
    if baseline_text:
        try:
            baseline_list = json.loads(baseline_text)
            for b in baseline_list:
                mk = b.get("module_key")
                if mk:
                    baseline_map[str(mk)] = b
            print(f"ℹ️ Baseline loaded with {len(baseline_map)} modules")
        except Exception as e:
            print(f"❌ Failed to parse baseline JSON from S3: {e}")
            baseline_map = {}
    else:
        print("ℹ️ No baseline found (first run)")

    # Ensure DDB table exists (create if missing)
    table_name = cfg["TABLE_NAME"]
    existing_tables = ddb.meta.client.list_tables().get("TableNames", [])
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
    table = ddb.Table(table_name)

    # scan existing ids from DDB to avoid META id collisions
    existing_generated_ids = set()
    try:
        paginator = table.meta.client.get_paginator("scan")
        for page in paginator.paginate(TableName=table_name, ProjectionExpression="id"):
            for it in page.get("Items", []):
                if "id" in it:
                    existing_generated_ids.add(it["id"])
    except Exception:
        pass

    # canonical fields: infer from records (exclude generated fields)
    if records:
        sample = records[0]
        excluded = {"id", "module_id", "uploaded_date", "cve_id", "content_hash"}
        canonical_fields = [k for k in sample.keys() if k not in excluded]
        if "module_key" in canonical_fields:
            canonical_fields.remove("module_key")
    else:
        canonical_fields = []

    # Build current_map and compute content_hash
    current_map = {}
    for rec in records:
        mk = rec.get("module_key")
        if not mk:
            continue
        rec_hash = _compute_content_hash_for_record(rec, canonical_fields) if canonical_fields else ""
        rec["content_hash"] = rec_hash
        current_map[str(mk)] = rec

    # Determine changed keys by content_hash comparison
    changed_keys = []
    for mk, rec in current_map.items():
        base = baseline_map.get(mk)
        if base is None:
            changed_keys.append(mk)
            continue
        base_hash = base.get("content_hash") or ""
        if rec.get("content_hash") != base_hash:
            changed_keys.append(mk)

    # If baseline empty -> first run: write all
    if not baseline_map:
        changed_keys = list(current_map.keys())

    print(f"ℹ️ Changed/new modules to write: {len(changed_keys)}")

    # Prepare items to write
    to_write = []
    for mk in changed_keys:
        rec = dict(current_map.get(mk) or {})
        rec["cve_id"] = _extract_cve(rec.get("references"))
        # year from uploaded_date or current year
        ud = rec.get("uploaded_date")
        year = None
        if ud:
            try:
                year = int(str(ud)[:4])
            except Exception:
                year = None
        if year is None:
            year = int(time.strftime("%Y"))
        # reuse baseline id if present
        baseline_entry = baseline_map.get(mk, {}) or {}
        existing_id = baseline_entry.get("id")
        if existing_id and existing_id in existing_generated_ids:
            gen_id = existing_id
        else:
            gen_id = _next_meta_id_for_year(existing_generated_ids, year)
            existing_generated_ids.add(gen_id)
        rec["id"] = gen_id
        rec["module_id"] = mk
        rec["uploaded_date"] = rec.get("uploaded_date") or time.strftime("%Y-%m-%d")
        to_write.append(rec)

    # Batch write with safe conversion
    uploaded = []
    if to_write:
        print(f"⬆️ Writing {len(to_write)} item(s) to DynamoDB...")
        with table.batch_writer() as batch:
            cnt = 0
            for item in to_write:
                safe_item = {}
                for k, v in item.items():
                    safe_item[k] = _normalize_for_ddb(v)
                try:
                    batch.put_item(Item=safe_item)
                    uploaded.append(safe_item.get("id"))
                except Exception as e:
                    print(f"❌ Failed to write id={safe_item.get('id')}: {e}")
                cnt += 1
                if cnt % cfg.get("BATCH_PROGRESS_INTERVAL", 100) == 0 or cnt == len(to_write):
                    print(f"⬆️ Batch wrote {cnt}/{len(to_write)}")
        print(f"✅ Uploaded {len(uploaded)} items")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Merge baseline_map and current_map; ensure content_hash and id present
    merged = baseline_map.copy()
    for mk, rec in current_map.items():
        entry = dict(rec)  # contains content_hash
        base_entry = baseline_map.get(mk, {}) or {}
        if not entry.get("id") and base_entry.get("id"):
            entry["id"] = base_entry.get("id")
        entry["module_key"] = mk
        if not entry.get("cve_id"):
            entry["cve_id"] = _extract_cve(entry.get("references"))
        merged[mk] = entry

    baseline_list = list(merged.values())
    baseline_bytes = json.dumps(baseline_list, ensure_ascii=False, indent=2).encode("utf-8")

    # Upload baseline JSON as the single canonical object on S3
    print(f"⬆️ Uploading baseline JSON to s3://{s3_bucket}/{canonical_key}")
    _s3_put_bytes(s3, s3_bucket, canonical_key, baseline_bytes)
    print("✅ Baseline upload complete (this is the only S3 object kept)")

    summary = {
        "uploaded": len(uploaded),
        "changed_keys": len(changed_keys),
        "total_current": len(current_map),
        "s3_baseline": f"s3://{s3_bucket}/{canonical_key}"
    }
    print("ℹ️ Sync summary:", summary)
    return summary
