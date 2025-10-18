# loaders/nvd_loader.py
import logging
from boto3.dynamodb.conditions import Attr
from utils.time_utils import iso_now
from utils.dynamo_helpers import parallel_scan
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
    Incrementally load NVD base data into final table.
    - Reads last sync timestamp from metadata table.
    - Scans only records with uploaded_date > last_sync.
    - If no new items found, loads existing CVE IDs from final table.
    - Returns set of CVE IDs used for left joins.
    """
    log = logging.getLogger("vuln-sync")
    nvd_table = dynamodb.Table(nvd_table_name)

    # ===========================================================
    # 🕓 Step 1 — Fetch last sync time from metadata
    # ===========================================================
    last_sync = get_last_sync_fn(nvd_table_name)
    log.info(f"📅 Last sync time for {nvd_table_name}: {last_sync}")

    # ===========================================================
    # ⚡ Step 2 — Scan only new/updated items since last sync
    # ===========================================================
    log.info(f"⚡ Scanning {nvd_table_name} for records with uploaded_date > {last_sync}...")
    new_items = parallel_scan(
        nvd_table,
        log=log,
        filter_expr=Attr("uploaded_date").gt(last_sync)
    )

    if limit:
        new_items = new_items[:limit]
        log.info(f"🧪 Testing mode — limiting to {limit} NVD items")

    # ===========================================================
    # 🧱 Step 3 — If no new items, reuse existing CVE set
    # ===========================================================
    if not new_items:
        log.info("✅ No new or updated NVD records found. Using existing CVE list from final table.")
        existing_items = parallel_scan(final_table, log=log)
        cve_ids = {
            item["cve_id"].upper().strip()
            for item in existing_items
            if "cve_id" in item
        }
        log.info(f"📋 Loaded {len(cve_ids)} existing CVE IDs from final table for joining.")
        return cve_ids

    log.info(f"📦 Found {len(new_items)} new or updated NVD records.")

    # ===========================================================
    # 🧱 Step 4 — Write new records to final table
    # ===========================================================
    cve_ids = set()
    written = 0
    max_date = last_sync

    with final_table.batch_writer() as batch:
        for rec in new_items:
            cve = rec.get("id") or rec.get("cveID") or rec.get("CVE_ID")
            if not cve or not CVE_PATTERN.match(cve):
                continue

            transformed = transform_fn(rec)
            transformed["cve_id"] = transformed.get("cve_id") or cve
            transformed.setdefault("uploaded_date", iso_now())

            batch.put_item(Item=transformed)
            cve_ids.add(transformed["cve_id"].upper().strip())
            written += 1

            # Track latest upload time for next sync
            uploaded_date = transformed.get("uploaded_date")
            if uploaded_date > max_date:
                max_date = uploaded_date

            if written % 1000 == 0:
                log.info(f"📝 Written {written} NVD base rows")

    log.info(f"✅ NVD base load complete: {written} new records written.")
    set_last_sync_fn(nvd_table_name, max_date)

    return cve_ids
