import boto3
import concurrent.futures
import logging
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from transformations import (
    nvd_transform,
    cisa_transform,
    exploitdb_transform,
    metasploit_transform,
)
from utils.dynamo_utils import ensure_table

# ===============================================================
# 🧩 Logging Configuration
# ===============================================================
log_filename = f"sync_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_filename),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ===============================================================
# ⚙️ AWS Setup & Configuration
# ===============================================================
region = "us-east-1"
dynamodb = boto3.resource("dynamodb", region_name=region)
client = boto3.client("dynamodb", region_name=region)

main_table_name = "infoservices-cybersecurity-vuln-nvd-data"
final_table_name = "infoservices-cybersecurity-final-data"
metadata_table_name = "infoservices-cybersecurity-sync-metadata"

source_tables = [
    ("infoservices-cybersecurity-cisa-data", "cveID"),
    ("infoservices-cybersecurity-vuln-exploitdb-data", "CVE_id"),
    ("infoservices-cybersecurity-vuln-metasploit-data", "cve_id"),
]

# Ensure final and metadata tables
ensure_table(client, final_table_name, "cve_id")
ensure_table(client, metadata_table_name, "source_table")

final_table = dynamodb.Table(final_table_name)
metadata_table = dynamodb.Table(metadata_table_name)

# ===============================================================
# 🕓 Metadata Helpers
# ===============================================================
def get_last_sync(source_name: str) -> str:
    try:
        r = metadata_table.get_item(Key={"source_table": source_name})
        return r.get("Item", {}).get("last_sync_time", "1970-01-01T00:00:00Z")
    except ClientError:
        return "1970-01-01T00:00:00Z"


def set_last_sync(source_name: str, last_time: str):
    metadata_table.put_item(Item={"source_table": source_name, "last_sync_time": last_time})


# ===============================================================
# ⚡ Universal Parallel Scan Function
# ===============================================================
def parallel_scan(table, filter_column, last_sync, total_segments=8):
    log.info(f"⚡ Parallel scanning {table.name} (filter: {filter_column} > {last_sync}) using {total_segments} threads...")

    def scan_segment(segment):
        seg_items = []
        response = table.scan(
            Segment=segment,
            TotalSegments=total_segments,
            FilterExpression=Attr(filter_column).gt(last_sync)
        )
        seg_items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = table.scan(
                Segment=segment,
                TotalSegments=total_segments,
                ExclusiveStartKey=response["LastEvaluatedKey"],
                FilterExpression=Attr(filter_column).gt(last_sync)
            )
            seg_items.extend(response.get("Items", []))
        return seg_items

    with concurrent.futures.ThreadPoolExecutor(max_workers=total_segments) as ex:
        results = list(ex.map(scan_segment, range(total_segments)))

    merged = [item for seg in results for item in seg]
    log.info(f"📦 Parallel scan complete for {table.name}: {len(merged)} items found.")
    return merged


# ===============================================================
# 🧱 Incremental Join for Source Tables
# ===============================================================
def incremental_join(source_table_name: str, source_key: str):
    table = dynamodb.Table(source_table_name)
    last_sync = get_last_sync(source_table_name)
    log.info(f"\n🔍 Syncing source: {source_table_name} (last_sync={last_sync})")

    # parallel scan to fetch all new items
    try:
        new_items = parallel_scan(table, "uploaded_date", last_sync)
    except ClientError as e:
        log.error(f"❌ Error scanning {source_table_name}: {e}")
        return

    if not new_items:
        log.warning(f"⚠️ No new or updated records in {source_table_name}.")
        return

    count = 0
    max_date = last_sync

    # ⚡ batch write instead of one-by-one put_item
    with final_table.batch_writer(overwrite_by_pkeys=["cve_id"]) as batch:
        for rec in new_items:
            # Apply transformation
            if "cisa" in source_table_name:
                transformed = cisa_transform.clean_and_rename(rec)
            elif "exploitdb" in source_table_name:
                transformed = exploitdb_transform.clean_and_rename(rec)
            elif "metasploit" in source_table_name:
                transformed = metasploit_transform.clean_and_rename(rec)
            else:
                transformed = rec.copy()

            # Extract primary key
            cve_id = (
                transformed.get("cve_id")
                or rec.get(source_key)
                or rec.get("cveID")
                or rec.get("id")
            )
            if not cve_id and "codes" in rec and isinstance(rec["codes"], (list, tuple)) and rec["codes"]:
                cve_id = rec["codes"][0]
            if not cve_id:
                continue

            transformed["cve_id"] = cve_id

            # No need to fetch existing record — batch_writer will overwrite
            batch.put_item(Item=transformed)

            rec_date = transformed.get("uploaded_date") or rec.get("uploaded_date")
            if rec_date and rec_date > max_date:
                max_date = rec_date

            count += 1
            if count % 1000 == 0:
                log.info(f"📝 Buffered {count} records from {source_table_name}...")

    set_last_sync(source_table_name, max_date)
    log.info(f"✅ {source_table_name} synced via batch: {count} records written (last_sync={max_date})")

# ===============================================================
# 🧩 Main NVD Table Sync (Parallel Scan)
# ===============================================================
def sync_main_table():
    main_table = dynamodb.Table(main_table_name)
    last_sync = get_last_sync(main_table_name)
    log.info(f"\n🔍 Syncing main table: {main_table_name} (last_sync={last_sync})")

    try:
        new_items = parallel_scan(main_table, "date_updated", last_sync)
    except ClientError as e:
        log.error(f"❌ Error scanning main table {main_table_name}: {e}")
        return

    if not new_items:
        log.warning(f"⚠️ No new or updated records in main table {main_table_name}.")
        return

    count = 0
    max_date = last_sync

    with final_table.batch_writer() as batch:
        for rec in new_items:
            transformed = nvd_transform.clean_and_rename(rec)
            cve_id = transformed.get("cve_id") or rec.get("id") or rec.get("cveID")
            if not cve_id:
                continue
            transformed["cve_id"] = cve_id
            batch.put_item(Item=transformed)

            rec_date = transformed.get("uploaded_date") or rec.get("date_updated")
            if rec_date and rec_date > max_date:
                max_date = rec_date

            count += 1
            if count % 1000 == 0:
                log.info(f"📝 Processed {count} NVD records...")

    set_last_sync(main_table_name, max_date)
    log.info(f"✅ Main NVD table synced: {count} records (last_sync={max_date})")


# ===============================================================
# 🚀 Runner
# ===============================================================
if __name__ == "__main__":
    log.info("\n⚙️ Starting Vulnerability Sync Pipeline (Parallel Scan Mode)...\n")

    # Step 1: Main NVD table
    # sync_main_table()

    # Step 2: Other sources
    for tname, key in source_tables:
        incremental_join(tname, key)

    log.info("\n🎯 All done! All tables synced successfully.\n")
    log.info(f"📄 Logs saved to {log_filename}")
