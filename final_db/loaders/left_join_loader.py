# loaders/left_join_loader.py
import logging
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from utils.dynamo_helpers import parallel_scan, get_max_uploaded_date
from utils.cve_utils import normalize_cve


def left_join_source(
    dynamodb,
    final_table,
    source_table_name: str,
    source_join_key: str,
    transform_fn,
    nvd_cve_set: set,
    get_last_sync_fn,
    set_last_sync_fn,
    is_static: bool = False,
    log=None,
    total_segments: int = 8,
):
    """
    Left-join a source table (CISA, ExploitDB, Metasploit, APT, etc.) onto the NVD-based final table.

    Features:
    - Incremental join for dynamic sources (uploaded_date > last_sync)
    - Full scan for static sources (no uploaded_date)
    - Skips non-matching CVEs
    - Fills missing fields with None
    - Handles reserved DynamoDB keywords safely
    - Updates metadata with max(uploaded_date) only for dynamic sources
    """
    log = log or logging.getLogger("vuln-sync")
    source_table = dynamodb.Table(source_table_name)

    # Step 1️ — Get last sync time
    last_sync = get_last_sync_fn(source_table_name)
    log.info(f" Left-joining {source_table_name} (static={is_static}, last_sync={last_sync})")

    # Step 2️ — Scan items
    if is_static:
        log.info(f" ⚙️ Static dataset detected — performing full scan for {source_table_name}")
        items = parallel_scan(source_table, log=log, total_segments=1)
    else:
        log.info(f" Scanning {source_table_name} for records with uploaded_date > {last_sync}...")
        items = parallel_scan(
            source_table,
            log=log,
            filter_expr=Attr("uploaded_date").gt(last_sync),
            total_segments=total_segments
        )

    if not items:
        log.info(f" No records found for {source_table_name}.")
        return

    log.info(f" Found {len(items)} records in {source_table_name}.")

    updated = 0
    debug_print_limit = 5

    # Discover schema fields dynamically
    try:
        sample_transformed = transform_fn(items[0])
        final_columns = list(sample_transformed.keys())
    except Exception:
        final_columns = []

    def process_item(rec):
        nonlocal updated
        raw_cve = rec.get("cve_id") or rec.get(source_join_key) or rec.get("CVE") or rec.get("cveID")
        cve_id = normalize_cve(raw_cve)

        if not cve_id or cve_id not in nvd_cve_set:
            return False

        transformed = transform_fn(rec)
        if not transformed:
            return False

        transformed.pop("uploaded_date", None)

        # Fill missing columns with None
        for col in final_columns:
            transformed.setdefault(col, None)

        # Build safe update expression
        update_expr = []
        expr_attr_values = {}
        expr_attr_names = {}

        for k, v in transformed.items():
            if k == "cve_id":
                continue
            name_placeholder = f"#attr_{k}"
            value_placeholder = f":{k}"
            expr_attr_names[name_placeholder] = k
            expr_attr_values[value_placeholder] = v
            update_expr.append(f"{name_placeholder} = {value_placeholder}")

        if not update_expr:
            return False

        try:
            final_table.update_item(
                Key={"cve_id": cve_id},
                UpdateExpression="SET " + ", ".join(update_expr),
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values,
            )

            if updated < debug_print_limit:
                log.info(f" ✅ Updated CVE {cve_id} — fields: {list(transformed.keys())}")

            updated += 1
            return True

        except Exception as e:
            log.error(f" ❌ Error updating CVE {cve_id} from {source_table_name}: {e}")
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(process_item, items))

    log.info(f" ✅ Left-join complete for {source_table_name}: updated {updated} items.")

    # Step 3️ — Update metadata only for dynamic sources
    if not is_static:
        max_uploaded = get_max_uploaded_date(dynamodb, source_table_name, log)
        set_last_sync_fn(source_table_name, max_uploaded)
        log.info(f" 🕒 Stored max(uploaded_date) = {max_uploaded} for {source_table_name}")
    else:
        log.info(f" 💤 Static dataset — skipping metadata update for {source_table_name}")
