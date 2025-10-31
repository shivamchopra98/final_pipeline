#!/usr/bin/env python3
"""
Export all columns from the Final Vulnerability Table → CSV

- Uses parallel_scan() for high-speed reading
- Dynamically extracts all fields (handles missing/extra columns)
- Writes clean CSV file
"""

import boto3
import csv
import logging
from decimal import Decimal
from utils.dynamo_helpers import parallel_scan  # ✅ your existing high-speed helper

# ============================
# CONFIGURATION
# ============================
REGION = "us-east-1"  # change if needed
TABLE_NAME = "infoservices-cybersecurity-vuln-final-data"  # your final DynamoDB table
OUTPUT_FILE = "final_table_full_export.csv"
MAX_RECORDS = 50000  # adjust (100, 500, 1000, etc.)
TOTAL_SEGMENTS = 8  # parallel scan concurrency
# ============================

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("export-final-table")


# ============================
# Helper — Convert Decimals
# ============================
def _convert_decimal(obj):
    """Recursively convert Decimal types to float or int for CSV export."""
    if isinstance(obj, list):
        return [_convert_decimal(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: _convert_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    else:
        return obj


# ============================
# Export Logic
# ============================
def export_final_table_to_csv():
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    table = dynamodb.Table(TABLE_NAME)

    log.info(f"📥 Starting full parallel scan of table '{TABLE_NAME}' ...")
    items = parallel_scan(table, total_segments=TOTAL_SEGMENTS, log=log)

    if not items:
        log.warning("⚠️ No items found in table.")
        return

    log.info(f"✅ Retrieved {len(items)} records from {TABLE_NAME}")

    # Limit records if user wants only subset
    if len(items) > MAX_RECORDS:
        log.info(f"⚙️ Limiting output to first {MAX_RECORDS} records for export.")
        items = items[:MAX_RECORDS]

    # Convert Decimals for CSV compatibility
    clean_items = [_convert_decimal(i) for i in items]

    # Dynamically collect *all possible* field names
    all_keys = set()
    for item in clean_items:
        all_keys.update(item.keys())

    # Convert to sorted list for consistent column order
    fieldnames = sorted(all_keys)
    log.info(f"🧩 Total columns detected: {len(fieldnames)}")

    # Write to CSV
    with open(OUTPUT_FILE, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(clean_items)

    log.info(f"✅ Export complete → {OUTPUT_FILE}")
    log.info(f"📊 Records written: {len(clean_items)} | Columns: {len(fieldnames)}")


# ============================
# Main Entry
# ============================
if __name__ == "__main__":
    export_final_table_to_csv()
