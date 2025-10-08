# load.py
import os
import json
import math
from decimal import Decimal
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-vuln-misp-data",
    "BASELINE_FILENAME": "misp_baseline.json",
    "BATCH_PROGRESS_INTERVAL": 100,
}

def _resolve_cfg(user_cfg: Optional[Dict[str,Any]]) -> Dict[str,Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg.get("S3_PREFIX") and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] = cfg["S3_PREFIX"] + "/"
    return cfg

def _s3_get_text_if_exists(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        resp = s3_client.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read().decode("utf-8")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404", "NoSuchBucket"):
            return None
        raise

def _s3_put_bytes(s3_client, bucket: str, key: str, bts: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=bts)

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
    if s == "" or s.lower() in {"nan", "none"}:
        return None
    return s

def sync_misp_records_to_dynamodb_and_s3(records: List[Dict[str,Any]], json_bytes: bytes, user_cfg: Dict[str,Any]) -> Dict[str,Any]:
    cfg = _resolve_cfg(user_cfg)
    s3_bucket = cfg["S3_BUCKET"]
    s3_prefix = cfg.get("S3_PREFIX", "")
    baseline_key = f"{s3_prefix}{cfg['BASELINE_FILENAME']}"

    if not s3_bucket:
        raise RuntimeError("S3_BUCKET missing in config")

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

    # Force write if table empty
    try:
        table_items = table.scan(Limit=1).get('Items', [])
        force_write = len(table_items) == 0
    except Exception:
        force_write = True

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
    else:
        print("ℹ️ No baseline found, first run")

    current_map: Dict[str, Dict[str,Any]] = {}
    for rec in records:
        uid = rec.get("uuid") or rec.get("id") or rec.get("value")
        if uid:
            current_map[str(uid)] = rec

    total_current = len(current_map)
    print(f"ℹ️ Total current records discovered: {total_current}")

    # Write all records if first run
    to_write = []
    for uid, rec in current_map.items():
        base = baseline_map.get(uid)
        if force_write or base is None:
            to_write.append(rec)
        else:
            # Compare and add only changed records
            rec_serial = json.dumps(rec, sort_keys=True, ensure_ascii=False)
            base_serial = json.dumps(base, sort_keys=True, ensure_ascii=False)
            if rec_serial != base_serial:
                to_write.append(rec)

    print(f"ℹ️ Records to write: {len(to_write)}")
    written = 0
    if to_write:
        with table.batch_writer() as batch:
            for i, rec in enumerate(to_write, start=1):
                item = {k: _to_ddb_safe(v) for k, v in rec.items()}
                item["uuid"] = str(item.get("uuid") or rec.get("uuid") or rec.get("id") or rec.get("value"))
                batch.put_item(Item=item)
                written += 1
                if i % cfg.get("BATCH_PROGRESS_INTERVAL", 100) == 0 or i == len(to_write):
                    print(f"⬆️ Batch wrote {i}/{len(to_write)} items")
        print(f"✅ DynamoDB writes complete: {written}")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Update S3 baseline
    merged = baseline_map.copy()
    merged.update(current_map)
    baseline_bytes = json.dumps(list(merged.values()), ensure_ascii=False, indent=2).encode("utf-8")
    _s3_put_bytes(s3, s3_bucket, baseline_key, baseline_bytes)
    print(f"✅ Baseline updated to S3: {baseline_key}")

    return {
        "total_current": total_current,
        "to_write": len(to_write),
        "written": written,
        "s3_baseline": f"s3://{s3_bucket}/{baseline_key}"
    }
