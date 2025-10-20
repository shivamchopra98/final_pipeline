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
    "DDB_ENDPOINT": "",
}

def _resolve_cfg(user_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    cfg = DEFAULT_CONFIG.copy()
    if user_cfg:
        cfg.update(user_cfg)
    return cfg

def _to_ddb_safe(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)

def _parse_date_obj(s: Optional[str]):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

def _max_date_from_ddb_table(table, date_field="lastModified") -> Optional[datetime]:
    paginator = table.meta.client.get_paginator("scan")
    max_dt = None
    for page in paginator.paginate(TableName=table.name, ProjectionExpression=date_field):
        for itm in page.get("Items", []):
            val = itm.get(date_field)
            if not val:
                continue
            dt = _parse_date_obj(val)
            if dt and (max_dt is None or dt > max_dt):
                max_dt = dt
    return max_dt

def sync_nvd_records_to_dynamodb(records: List[Dict[str, Any]], json_bytes: bytes, user_cfg: Dict[str, Any]) -> Dict[str, Any]:
    cfg = _resolve_cfg(user_cfg)
    ddb_kwargs = {"region_name": cfg.get("AWS_REGION")}
    if cfg.get("DDB_ENDPOINT"):
        ddb_kwargs["endpoint_url"] = cfg.get("DDB_ENDPOINT")

    ddb = boto3.resource("dynamodb", **ddb_kwargs)
    table_name = cfg.get("TABLE_NAME")
    table = ddb.Table(table_name)

    print(f"🔁 Checking latest 'lastModified' in DynamoDB table '{table_name}' ...")
    max_date = _max_date_from_ddb_table(table, "lastModified")
    print(f"ℹ️ Current max 'lastModified': {max_date.isoformat() if max_date else 'None'}")

    to_write, skipped = [], 0
    for rec in records:
        rec_date = _parse_date_obj(rec.get("lastModified"))
        if not max_date or (rec_date and rec_date > max_date):
            to_write.append(rec)
        else:
            skipped += 1

    print(f"🟡 New or updated: {len(to_write)}, Skipped: {skipped}")
    written = 0
    batch_size = cfg.get("BATCH_WRITE_CHUNK_SIZE", 200)

    for i in range(0, len(to_write), batch_size):
        chunk = to_write[i:i + batch_size]
        with table.batch_writer() as batch:
            for rec in chunk:
                item = {k: _to_ddb_safe(v) for k, v in rec.items() if v is not None}
                batch.put_item(Item=item)
                written += 1
        print(f"⬆️ Batch uploaded {min(i+batch_size, len(to_write))}/{len(to_write)}")

    print(f"✅ DynamoDB sync complete. Written={written}, Skipped={skipped}")
    return {"total_feed_records": len(records), "written": written, "skipped": skipped}
