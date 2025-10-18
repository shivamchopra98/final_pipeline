# utils/dynamo_helpers.py
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError

import concurrent.futures
import logging
from boto3.dynamodb.conditions import Attr

def parallel_scan(table, log: logging.Logger, total_segments: int = 8, filter_expr=None):
    """
    Perform a parallel DynamoDB scan with optional filter expression.
    - `filter_expr`: optional DynamoDB filter (e.g. Attr("uploaded_date").gt("2025-10-01T00:00:00Z"))
    - Returns merged list of items.
    """
    log.info(f"⚡ Scanning {table.name} (segments={total_segments})")

    def scan_segment(segment):
        seg_items = []
        scan_kwargs = {
            "Segment": segment,
            "TotalSegments": total_segments,
        }

        # ✅ Add filter only if provided
        if filter_expr is not None:
            scan_kwargs["FilterExpression"] = filter_expr

        response = table.scan(**scan_kwargs)
        seg_items.extend(response.get("Items", []))

        while "LastEvaluatedKey" in response:
            scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
            response = table.scan(**scan_kwargs)
            seg_items.extend(response.get("Items", []))

        return seg_items

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_segments) as ex:
        results = list(ex.map(scan_segment, range(total_segments)))

    merged = [item for seg in results for item in seg]
    log.info(f"📦 Scan complete for {table.name}: {len(merged)} items")

    return merged


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
