# load.py
import json
import math
import hashlib
from decimal import Decimal
from typing import List, Dict, Any, Optional, Iterable
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# ===========================
# Default Configuration
# ===========================
DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-cisa-data",
    "BATCH_PROGRESS_INTERVAL": 200,
    "BATCH_WRITE_CHUNK_SIZE": 200,
    "AWS_REGION": "us-east-1",
    "DDB_ENDPOINT": "",
}

# ===========================
# Utility Functions
# ===========================

def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
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


def _record_hash(rec: Dict[str, Any]) -> str:
    """Generate a stable hash of key fields for comparison."""
    if not rec:
        return ""
    key_fields = [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "notes",
    ]
    normalized = {k: str(rec.get(k, "")).strip() for k in key_fields}
    encoded = json.dumps(normalized, sort_keys=True).encode("utf-8")
    return hashlib.md5(encoded).hexdigest()


def _write_chunk(ddb_table, chunk: List[Dict[str, Any]], progress_fn=None):
    written = 0
    with ddb_table.batch_writer() as batch:
        for rec in chunk:
            item = {}
            for k, v in rec.items():
                val = _to_ddb_safe(v)
                if val is not None:
                    item[k] = val
            item["cveID"] = str(item.get("cveID") or rec.get("cveID")).upper()
            batch.put_item(Item=item)
            written += 1
            if progress_fn:
                progress_fn(1)
    return written


# ===========================
# Core Sync Logic
# ===========================

def sync_cisa_records_to_dynamodb(records: List[Dict[str, Any]], json_bytes: bytes, user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Syncs CISA records to DynamoDB by comparing with existing CVEs in the table directly.
    Skips S3 baseline upload entirely.
    """
    cfg = _resolve_cfg(user_cfg)
    botocfg = Config(connect_timeout=10, read_timeout=60, retries={"max_attempts": 3, "mode": "standard"})

    # DynamoDB setup
    ddb_kwargs = {"region_name": cfg["AWS_REGION"]}
    if cfg.get("DDB_ENDPOINT"):
        ddb_kwargs["endpoint_url"] = cfg["DDB_ENDPOINT"]
    ddb = boto3.resource("dynamodb", **ddb_kwargs)
    table = ddb.Table(cfg["TABLE_NAME"])

    # Step 1: Get existing CVE IDs from DynamoDB
    print(f"🔍 Scanning existing CVEs from DynamoDB table '{cfg['TABLE_NAME']}' ...")
    existing_cves = {}
    try:
        response = table.scan(ProjectionExpression="cveID")
        while True:
            for item in response.get("Items", []):
                existing_cves[item["cveID"].upper()] = True
            if "LastEvaluatedKey" in response:
                response = table.scan(
                    ProjectionExpression="cveID",
                    ExclusiveStartKey=response["LastEvaluatedKey"]
                )
            else:
                break
    except ClientError as e:
        print(f"❌ DynamoDB scan error: {e}")
        return {"error": str(e)}

    print(f"ℹ️ Found {len(existing_cves)} existing CVEs in DynamoDB")

    # Step 2: Determine which records are new
    new_records = [r for r in records if str(r.get("cveID", "")).upper() not in existing_cves]
    print(f"🟡 New records to insert: {len(new_records)}")

    # Step 3: Write new records
    written = 0
    if new_records:
        chunks = list(_chunks(new_records, cfg["BATCH_WRITE_CHUNK_SIZE"]))
        total = len(new_records)
        finished = 0

        def progress_fn(n):
            nonlocal finished, written
            finished += n
            written = finished
            if finished % cfg["BATCH_PROGRESS_INTERVAL"] == 0 or finished == total:
                print(f"⬆️ Batch wrote {finished}/{total} items")

        for chunk in chunks:
            _write_chunk(table, chunk, progress_fn)

        print(f"✅ Successfully added {written} new CVEs to DynamoDB")
    else:
        print("ℹ️ No new records to write. Skipping DynamoDB update.")

    summary = {
        "total_feed": len(records),
        "new_records": len(new_records),
    }

    print(f"ℹ️ Summary: {summary}")
    return summary
