# utils/dynamo_helpers.py
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
import logging
import boto3
from utils.time_utils import iso_now


def parallel_scan(table, total_segments=8, filter_expr=None, log=None, max_retries=3, backoff=1.5):
    """
    High-performance parallel scan for DynamoDB.
    - Uses multiple threads for scanning partitions concurrently.
    - Handles pagination, throttling, and transient network errors.
    - Returns all items from the table (or filtered subset if filter_expr provided).
    """

    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import botocore

    log = log or logging.getLogger("vuln-scan")

    # Use a low-level client for thread-safe parallelism
    dynamodb_resource = boto3.resource("dynamodb", region_name=table.meta.client.meta.region_name)
    table = dynamodb_resource.Table(table.name)

    # Create paginator once (thread-safe)
    paginator = table.meta.client.get_paginator("scan")
    def scan_segment(seg):
        """Scan a single DynamoDB partition segment."""
        params = {
            "TableName": table.name,
            "Segment": seg,
            "TotalSegments": total_segments,
        }
        if filter_expr is not None:
            params["FilterExpression"] = filter_expr

        items = []
        retries = 0

        while True:
            try:
                for page in paginator.paginate(**params):
                    items.extend(page.get("Items", []))
                break  # exit retry loop if successful

            except botocore.exceptions.ClientError as e:
                error_code = e.response["Error"]["Code"]
                if error_code in ("ProvisionedThroughputExceededException", "ThrottlingException"):
                    retries += 1
                    if retries > max_retries:
                        log.error(f"❌ Segment {seg}: exceeded max retries ({max_retries}).")
                        break
                    sleep_time = backoff ** retries
                    log.warning(f"⚠️ Segment {seg}: throttled, retry {retries}/{max_retries}, sleeping {sleep_time:.2f}s")
                    time.sleep(sleep_time)
                else:
                    log.error(f"❌ Segment {seg}: {e}")
                    break
            except Exception as e:
                log.error(f"⚠️ Unexpected error in segment {seg}: {e}")
                break

        log.debug(f"Segment {seg} done: {len(items)} items")
        return items

    start = time.time()
    all_items = []

    log.info(f"⚙️ Starting parallel scan with {total_segments} segments on table '{table.name}'")

    # Run all segments in parallel
    with ThreadPoolExecutor(max_workers=total_segments) as executor:
        futures = [executor.submit(scan_segment, seg) for seg in range(total_segments)]
        for future in as_completed(futures):
            segment_items = future.result()
            all_items.extend(segment_items)

    duration = time.time() - start
    log.info(f"✅ Scan complete for {table.name}: {len(all_items)} items in {duration:.2f}s")

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

def get_all_cve_ids(dynamodb, table_name, log=None, total_segments=8):
    """
    Scan the given DynamoDB table to collect all CVE IDs.
    Used for left joins to ensure we match existing final data.
    Handles both raw DynamoDB JSON and deserialized records.
    """
    from boto3.dynamodb.types import TypeDeserializer
    import botocore
    import time

    log = log or logging.getLogger("vuln-sync")
    table = dynamodb.Table(table_name)
    log.info(f"🧩 Scanning {table_name} to collect all CVE IDs...")

    items = []
    deserializer = TypeDeserializer()

    try:
        from utils.dynamo_helpers import parallel_scan
        all_records = parallel_scan(table, log=log, total_segments=total_segments)

        for r in all_records:
            if "cve_id" in r:
                val = r["cve_id"]
                # Handle both {"S": "CVE-..."} and plain strings
                if isinstance(val, dict):
                    val = deserializer.deserialize(val)
                if isinstance(val, str):
                    items.append(val.strip())

    except botocore.exceptions.ClientError as e:
        log.error(f"❌ Error collecting CVE IDs from {table_name}: {e}")
    except Exception as e:
        log.error(f"⚠️ Unexpected error scanning {table_name}: {e}")

    unique_cves = set(items)
    log.info(f"📦 Found {len(unique_cves)} unique CVE IDs in {table_name}.")
    return unique_cves
