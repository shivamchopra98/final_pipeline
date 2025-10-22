# utils/dynamo_helpers.py
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import logging
import boto3
from utils.time_utils import iso_now


def parallel_scan(table, total_segments=8, filter_expr=None, log=None):
    """Parallel scan helper for DynamoDB."""
    log = log or logging.getLogger("vuln-sync")
    from concurrent.futures import ThreadPoolExecutor

    def scan_segment(seg):
        params = {"Segment": seg, "TotalSegments": total_segments}
        if filter_expr is not None:
            params["FilterExpression"] = filter_expr

        items = []
        resp = table.scan(**params)
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"], **params)
            items.extend(resp.get("Items", []))
        return items

    with ThreadPoolExecutor(max_workers=total_segments) as ex:
        results = list(ex.map(scan_segment, range(total_segments)))

    all_items = [item for sub in results for item in sub]
    log.info(f"📦 Scan complete for {table.name}: {len(all_items)} items")
    return all_items


def get_max_uploaded_date(dynamodb, table_name: str, log) -> str:
    """
    Fetch max(uploaded_date) or max(date_updated) efficiently.
    Falls back to table scan if no sort key-based index exists.

    Automatically detects column:
    - For NVD → uses 'date_updated'
    - For others → uses 'uploaded_date'
    """
    table = dynamodb.Table(table_name)
    column = "date_updated" if "nvd" in table_name else "uploaded_date"

    log.info(f"📊 Fetching max({column}) from {table_name} using scan()")

    try:
        # Use a lightweight projection to fetch only date fields
        resp = table.scan(
            FilterExpression=Attr(column).gt("1970-01-01T00:00:00Z"),
            ProjectionExpression=column
        )

        items = resp.get("Items", [])
        while "LastEvaluatedKey" in resp:
            resp = table.scan(
                FilterExpression=Attr(column).gt("1970-01-01T00:00:00Z"),
                ProjectionExpression=column,
                ExclusiveStartKey=resp["LastEvaluatedKey"]
            )
            items.extend(resp.get("Items", []))

        if not items:
            log.warning(f"⚠️ No {column} values found in {table_name}. Using current time.")
            from utils.time_utils import iso_now
            return iso_now()

        max_date = max(i[column] for i in items if column in i)
        log.info(f"✅ Max {column} for {table_name}: {max_date}")
        return max_date

    except Exception as e:
        log.error(f"❌ Failed to get max({column}) for {table_name}: {e}")
        from utils.time_utils import iso_now
        return iso_now()



def build_update_expression_and_values(attr_map: dict, timestamp: str):
    """Build a DynamoDB UpdateExpression dynamically for given attributes."""
    parts, eav, ean = [], {}, {}
    idx = 0
    for k, v in attr_map.items():
        if v is None:
            continue
        idx += 1
        ph_val = f":v{idx}"
        ph_name = f"#k{idx}"
        parts.append(f"{ph_name} = {ph_val}")
        eav[ph_val] = v
        ean[ph_name] = k
    if not parts:
        return None, None, None
    eav[":ts"] = timestamp
    update_expr = "SET " + ", ".join(parts) + ", uploaded_date = :ts"
    return update_expr, eav, ean


def get_last_sync(metadata_table, source_name):
    try:
        r = metadata_table.get_item(Key={"source_table": source_name})
        return r.get("Item", {}).get("last_sync_time", "1970-01-01T00:00:00Z")
    except ClientError:
        return "1970-01-01T00:00:00Z"


def set_last_sync(metadata_table, source_name, timestamp):
    metadata_table.put_item(Item={"source_table": source_name, "last_sync_time": timestamp})
