import json
from datetime import datetime
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError

DEFAULT_CONFIG = {
    "TABLE_NAME": "infoservices-cybersecurity-vuln-nvd-data",
    "BATCH_PROGRESS_INTERVAL": 200,
    "BATCH_WRITE_CHUNK_SIZE": 200,
    "AWS_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": None,
    "AWS_SECRET_ACCESS_KEY": None,
    "DDB_ENDPOINT": "",
}


def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    return cfg


def _to_ddb_safe(v):
    """Convert value into DynamoDB-storable format."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _parse_date_obj(s: Optional[str]):
    """Parse ISO date string safely."""
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%MZ")
    except Exception:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None


def _max_date_from_ddb_table(table, date_field="lastModified") -> Optional[datetime]:
    """Scan DynamoDB for max 'lastModified'."""
    paginator = table.meta.client.get_paginator("scan")
    max_dt = None
    try:
        for page in paginator.paginate(TableName=table.name, ProjectionExpression=date_field):
            for itm in page.get("Items", []):
                val = itm.get(date_field)
                if not val:
                    continue
                dt = _parse_date_obj(val)
                if dt and (max_dt is None or dt > max_dt):
                    max_dt = dt
    except ClientError as e:
        print(f"⚠️ DynamoDB scan error when computing max date: {e}")
        raise
    return max_dt


def sync_nvd_records_to_dynamodb(records: List[Dict[str, Any]], json_bytes: bytes, user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Sync NVD feed data into DynamoDB, adding 'weakness' for all matching IDs."""
    cfg = _resolve_cfg(user_cfg)

    ddb_kwargs = {"region_name": cfg.get("AWS_REGION")}
    if cfg.get("DDB_ENDPOINT"):
        ddb_kwargs["endpoint_url"] = cfg.get("DDB_ENDPOINT")
    ddb = boto3.resource("dynamodb", **ddb_kwargs)

    table_name = cfg.get("TABLE_NAME")
    existing_tables = ddb.meta.client.list_tables().get("TableNames", [])
    if table_name not in existing_tables:
        print(f"⚡ Creating DynamoDB table '{table_name}'...")
        table = ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    table = ddb.Table(table_name)

    print(f"🔁 Scanning DynamoDB table '{table_name}' for max 'lastModified' ...")
    max_date = _max_date_from_ddb_table(table, date_field="lastModified")
    if max_date:
        print(f"ℹ️ Current max 'lastModified' in DynamoDB: {max_date}")
    else:
        print("ℹ️ No existing 'lastModified', treating as first run")

    # --- Build existing CVE map for weakness update ---
    print("🔎 Checking which CVEs already have 'weakness' field...")
    existing_cve_map = {}
    paginator = table.meta.client.get_paginator("scan")
    for page in paginator.paginate(TableName=table.name, ProjectionExpression="id, weakness"):
        for item in page.get("Items", []):
            cve_id = item.get("id")
            if not cve_id:
                continue
            existing_cve_map[cve_id] = item.get("weakness")

    to_update_weakness = []
    skipped = 0

    # --- Process incoming records (id, weakness only) ---
    for rec in records:
        rec_cve_id = rec.get("id")
        if not rec_cve_id:
            continue

        rec_weakness = rec.get("weakness")
        if rec_cve_id in existing_cve_map:
            existing_weakness = existing_cve_map.get(rec_cve_id)
            if not existing_weakness and rec_weakness:
                to_update_weakness.append({"id": rec_cve_id, "weakness": rec_weakness})
            else:
                skipped += 1
        else:
            # Optional: if not found in table, skip it (we only want to update existing)
            skipped += 1

    print(f"🧩 Existing records missing 'weakness' to update: {len(to_update_weakness)}")
    print(f"ℹ️ Skipped/unchanged: {skipped}")

    written = 0
    batch_size = cfg.get("BATCH_WRITE_CHUNK_SIZE", 200)

    def _batch_update(items: List[Dict[str, Any]]):
        nonlocal written
        client = table.meta.client
        for i in range(0, len(items), batch_size):
            chunk = items[i:i + batch_size]
            for rec in chunk:
                try:
                    client.update_item(
                        TableName=table_name,
                        Key={"id": {"S": rec["id"]}},
                        UpdateExpression="SET weakness = :w",
                        ExpressionAttributeValues={":w": {"S": _to_ddb_safe(rec["weakness"])}}
                    )
                    written += 1
                except ClientError as e:
                    print(f"⚠️ Failed to update {rec['id']}: {e}")
            print(f"⬆️ Updated weakness for {min(i + batch_size, len(items))}/{len(items)} records")

    if to_update_weakness:
        _batch_update(to_update_weakness)

    print(f"✅ DynamoDB weakness updates complete: {written}")
    summary = {
        "total_feed_records": len(records),
        "weakness_added": len(to_update_weakness),
        "skipped": skipped
    }
    return summary
