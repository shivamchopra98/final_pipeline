import json
import concurrent.futures
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
    "PARALLEL_SCAN_SEGMENTS": 8
}


def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    return cfg


def _to_ddb_safe(v):
    """Convert Python value into a DynamoDB-storable string."""
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def _parse_date_obj(s: Optional[str]) -> Optional[datetime]:
    """Parse ISO date safely."""
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%MZ")
    except Exception:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except Exception:
            return None


def _get_max_last_modified_parallel(table, segments=8) -> Optional[datetime]:
    """Parallel scan DynamoDB to find the maximum 'lastModified' date."""
    client = table.meta.client

    def scan_segment(segment):
        paginator = client.get_paginator("scan")
        max_dt = None
        for page in paginator.paginate(
            TableName=table.name,
            ProjectionExpression="lastModified",
            TotalSegments=segments,
            Segment=segment
        ):
            for item in page.get("Items", []):
                val = item.get("lastModified")
                if not val:
                    continue
                dt = _parse_date_obj(val)
                if dt and (max_dt is None or dt > max_dt):
                    max_dt = dt
        return max_dt

    print(f"🚀 Performing parallel scan with {segments} segments for max 'lastModified'...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=segments) as executor:
        results = list(executor.map(scan_segment, range(segments)))

    max_date = max((r for r in results if r is not None), default=None)
    if max_date:
        print(f"✅ Parallel scan complete. Max 'lastModified' = {max_date}")
    else:
        print("ℹ️ No 'lastModified' found in table.")
    return max_date


def sync_nvd_records_to_dynamodb(records: List[Dict[str, Any]], json_bytes: bytes, user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Sync NVD feed data to DynamoDB (insert/update new and modified records)."""
    cfg = _resolve_cfg(user_cfg)

    ddb_kwargs = {"region_name": cfg.get("AWS_REGION")}
    if cfg.get("DDB_ENDPOINT"):
        ddb_kwargs["endpoint_url"] = cfg.get("DDB_ENDPOINT")
    ddb = boto3.resource("dynamodb", **ddb_kwargs)

    table_name = cfg["TABLE_NAME"]
    existing_tables = ddb.meta.client.list_tables().get("TableNames", [])
    if table_name not in existing_tables:
        print(f"⚡ Creating DynamoDB table '{table_name}'...")
        table = ddb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )
        table.meta.client.get_waiter("table_exists").wait(TableName=table_name)
        print("✅ Table created.")
    else:
        table = ddb.Table(table_name)

    # --- Find max 'lastModified' using parallel scan ---
    max_date = _get_max_last_modified_parallel(
        table, segments=cfg.get("PARALLEL_SCAN_SEGMENTS", 8)
    )

    # --- Filter new/updated records ---
    if max_date:
        new_records = [
            rec for rec in records
            if (dt := _parse_date_obj(rec.get("lastModified"))) and dt > max_date
        ]
        print(f"🆕 Found {len(new_records)} new/updated records since {max_date}")
    else:
        new_records = records
        print(f"🆕 First run detected — inserting all {len(new_records)} records.")

    if not new_records:
        print("✅ No new data to update.")
        return {"total_feed_records": len(records), "new_records": 0}

    # --- Batch write ---
    written = 0
    batch_size = cfg.get("BATCH_WRITE_CHUNK_SIZE", 200)

    with table.batch_writer(overwrite_by_pkeys=["id"]) as batch:
        for i, rec in enumerate(new_records, start=1):
            item = {k: _to_ddb_safe(v) for k, v in rec.items()}
            item["id"] = rec.get("cveID") or rec.get("id")
            batch.put_item(Item=item)

            if i % batch_size == 0:
                print(f"⬆️ Wrote {i} records...")

            written = i

    print(f"✅ DynamoDB load complete: {written} records written/updated.")
    summary = {"total_feed_records": len(records), "new_records": written}
    return summary
