import json
import math
import boto3
from decimal import Decimal
from typing import Dict, Any, List, Optional
from botocore.exceptions import ClientError

DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-cisa-data",
    "AWS_REGION": "us-east-1",
    "S3_BUCKET": None,
    "S3_PREFIX": "vuln-raw-source/cisa/",
    "BASELINE_FILENAME": "cisa_baseline.json",
    "BATCH_PROGRESS_INTERVAL": 200,
    "AWS_ACCESS_KEY_ID": None,
    "AWS_SECRET_ACCESS_KEY": None,
}


def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]):
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] += "/"
    return cfg


def _s3_get_text_if_exists(s3_client, bucket: str, key: str) -> Optional[str]:
    try:
        obj = s3_client.get_object(Bucket=bucket, Key=key)
        return obj["Body"].read().decode("utf-8")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("NoSuchKey", "404"):
            return None
        raise


def _s3_put_bytes(s3_client, bucket: str, key: str, data: bytes):
    s3_client.put_object(Bucket=bucket, Key=key, Body=data)


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
        return json.dumps(v, sort_keys=True, ensure_ascii=False)
    s = str(v).strip()
    return s if s else None


def sync_cisa_records_to_dynamodb_and_s3(records: List[Dict[str, Any]], user_cfg: Dict[str, Any]):
    cfg = _resolve_cfg(user_cfg)
    s3_bucket = cfg["S3_BUCKET"]
    if not s3_bucket:
        raise RuntimeError("S3_BUCKET must be set in config")

    s3 = boto3.client(
        "s3",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY"),
        region_name=cfg["AWS_REGION"],
    )
    ddb = boto3.resource(
        "dynamodb",
        aws_access_key_id=cfg.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=cfg.get("AWS_SECRET_ACCESS_KEY"),
        region_name=cfg["AWS_REGION"],
        endpoint_url=cfg.get("DDB_ENDPOINT"),
    )

    table_name = cfg["TABLE_NAME"]
    if table_name not in ddb.meta.client.list_tables()["TableNames"]:
        print(f"⚡ Creating DynamoDB table '{table_name}'...")
        t = ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "cveID", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "cveID", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        t.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    table = ddb.Table(table_name)

    # Load baseline
    baseline_key = f"{cfg['S3_PREFIX']}{cfg['BASELINE_FILENAME']}"
    print(f"🔁 Fetching baseline from s3://{s3_bucket}/{baseline_key}")
    baseline_text = _s3_get_text_if_exists(s3, s3_bucket, baseline_key)
    baseline_map = {}
    if baseline_text:
        try:
            baseline = json.loads(baseline_text)
            for item in baseline:
                if item.get("cveID"):
                    baseline_map[item["cveID"]] = item
            print(f"ℹ️ Baseline loaded: {len(baseline_map)} items")
        except Exception as e:
            print(f"⚠️ Failed to parse baseline: {e}")
    else:
        print("ℹ️ No baseline found (first run)")

    # Build map for current data
    current_map = {r["cveID"]: r for r in records if r.get("cveID")}
    total = len(current_map)
    print(f"ℹ️ Total current records: {total}")

    # Compare baseline vs new
    to_write = []
    for cve, rec in current_map.items():
        base = baseline_map.get(cve)
        if base != rec:
            to_write.append(rec)
    print(f"ℹ️ New/changed to write: {len(to_write)}")

    # Write new items
    written = 0
    if to_write:
        print(f"⬆️ Writing {len(to_write)} items to DynamoDB...")
        with table.batch_writer() as batch:
            for i, rec in enumerate(to_write, start=1):
                safe = {k: _to_ddb_safe(v) for k, v in rec.items()}
                safe["cveID"] = str(safe.get("cveID"))
                batch.put_item(Item=safe)
                written += 1
                if i % cfg.get("BATCH_PROGRESS_INTERVAL", 200) == 0 or i == len(to_write):
                    print(f"⬆️ Batch wrote {i}/{len(to_write)} items")
        print(f"✅ DynamoDB writes complete: {written}")
    else:
        print("ℹ️ No new/changed records to write")

    # Upload new baseline
    merged = baseline_map.copy()
    merged.update(current_map)
    merged_bytes = json.dumps(list(merged.values()), ensure_ascii=False, indent=2).encode("utf-8")
    print(f"⬆️ Uploading baseline JSON to s3://{s3_bucket}/{baseline_key}")
    _s3_put_bytes(s3, s3_bucket, baseline_key, merged_bytes)
    print("✅ Baseline uploaded")

    summary = {
        "total_current": total,
        "to_write": len(to_write),
        "written": written,
        "s3_baseline": f"s3://{s3_bucket}/{baseline_key}",
    }
    print("ℹ️ Sync summary:", summary)
    return summary
