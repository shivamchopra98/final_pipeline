# loaders/nvd_loader.py
import logging
from boto3.dynamodb.conditions import Attr
from utils.time_utils import iso_now
from utils.dynamo_helpers import parallel_scan, get_max_uploaded_date
from config import CVE_PATTERN


def load_nvd_base(
    dynamodb,
    final_table,
    nvd_table_name,
    transform_fn,
    set_last_sync_fn,
    get_last_sync_fn,
    limit=None
):
    """
    Incrementally load NVD base data into the final table.
    - Reads last_sync from metadata table.
    - Scans only new records since last_sync (based on date_updated).
    - Updates metadata with max(date_updated) from NVD table.
    """
    log = logging.getLogger("vuln-sync")
    nvd_table = dynamodb.Table(nvd_table_name)

    # Step 1️⃣ — Get last sync
    last_sync = get_last_sync_fn(nvd_table_name)
    log.info(f"📅 Last sync time for {nvd_table_name}: {last_sync}")

    # Step 2️⃣ — Scan new/updated items (date_updated-based)
    log.info(f"⚡ Scanning {nvd_table_name} for records with date_updated > {last_sync}...")
    new_items = parallel_scan(
        nvd_table,
        log=log,
        filter_expr=Attr("date_updated").gt(last_sync)
    )

    if limit:
        new_items = new_items[:limit]
        log.info(f"🧪 Testing mode — limiting to {limit} NVD items")

    if not new_items:
        log.info("✅ No new or updated NVD records found. Skipping load.")
        return set()

    log.info(f"📦 Found {len(new_items)} new or updated NVD records.")

    # Step 3️⃣ — Write to final table
    cve_ids = set()
    written = 0

    with final_table.batch_writer() as batch:
        for rec in new_items:
            cve = rec.get("id") or rec.get("cveID") or rec.get("CVE_ID")
            if not cve or not CVE_PATTERN.match(cve):
                continue

            transformed = transform_fn(rec)
            transformed["cve_id"] = transformed.get("cve_id") or cve
            transformed.setdefault("uploaded_date", rec.get("date_updated", iso_now()))

            batch.put_item(Item=transformed)
            cve_ids.add(transformed["cve_id"])
            written += 1

            if written % 1000 == 0:
                log.info(f"📝 Written {written} NVD base rows")

    log.info(f"✅ NVD base load complete: {written} new records written.")

    # Step 4️⃣ — Compute max(date_updated)
    max_date = get_max_uploaded_date(dynamodb, nvd_table_name, log)
    set_last_sync_fn(nvd_table_name, max_date)
    log.info(f"🕓 Stored max(date_updated) = {max_date} for {nvd_table_name}")

    return cve_ids
