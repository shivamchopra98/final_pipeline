# loaders/left_join_loader.py
import logging
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from utils.time_utils import iso_now
from utils.dynamo_helpers import parallel_scan
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
    log=None,
    total_segments: int = 8,
):
    """
    Left-join a source table (CISA, ExploitDB, Metasploit) onto NVD-based final table.

    ✅ Improvements:
      - Safe handling of DynamoDB reserved keywords via ExpressionAttributeNames
      - Fills missing columns with None for schema consistency
      - Skips updating partition key (cve_id)
      - Only updates CVEs already existing in NVD
      - Parallel updates with thread pool
      - Updates metadata.last_sync_time after completion
    """
    log = log or logging.getLogger("vuln-sync")
    source_table = dynamodb.Table(source_table_name)

    # ==============================================================
    # 🕓 Step 1: Get last sync timestamp from metadata table
    # ==============================================================
    last_sync = get_last_sync_fn(source_table_name)
    log.info(f"🔗 Left-joining {source_table_name} (last_sync={last_sync})")

    # ==============================================================
    # ⚡ Step 2: Incremental scan for new/updated items
    # ==============================================================
    log.info(f"⚡ Scanning {source_table_name} for records with uploaded_date > {last_sync}...")
    items = parallel_scan(
        source_table,
        log=log,
        filter_expr=Attr("uploaded_date").gt(last_sync),
        total_segments=total_segments
    )

    if not items:
        log.info(f"✅ No new or updated records found for {source_table_name}.")
        return

    log.info(f"📦 Found {len(items)} new/updated records in {source_table_name}.")

    # ==============================================================
    # 🧱 Step 3: Process each item & left join on cve_id
    # ==============================================================
    updated = 0
    debug_print_limit = 5  # print only first 5 updates for visibility

    # Infer schema from one sample record
    try:
        sample_transformed = transform_fn(items[0])
        final_columns = list(sample_transformed.keys())
    except Exception:
        final_columns = []

    def process_item(rec):
        nonlocal updated
        raw_cve = rec.get("cve_id") or rec.get(source_join_key) or rec.get("CVE") or rec.get("cveID")
        cve_id = normalize_cve(raw_cve)

        # Skip if no valid CVE or not in base NVD set
        if not cve_id or cve_id not in nvd_cve_set:
            return False

        transformed = transform_fn(rec)
        if not transformed:
            return False

        transformed.pop("uploaded_date", None)

        # Ensure all expected fields are present
        for col in final_columns:
            transformed.setdefault(col, None)

        # Build safe DynamoDB update expression
        update_expr = []
        expr_attr_values = {}
        expr_attr_names = {}

        for k, v in transformed.items():
            if k == "cve_id":
                continue  # never update primary key

            # handle DynamoDB reserved keywords safely
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
                log.info(f"🧩 Updated CVE {cve_id} — fields: {list(transformed.keys())}")

            updated += 1
            return True

        except Exception as e:
            log.error(f"❌ Error updating CVE {cve_id} from {source_table_name}: {e}")
            return False

    # ==============================================================
    # ⚙️ Step 4: Run in parallel threads
    # ==============================================================
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(process_item, items))

    log.info(f"✅ Left-join complete for {source_table_name}: updated {updated} items.")

    # ==============================================================
    # 🕒 Step 5: Update last_sync time in metadata
    # ==============================================================
    set_last_sync_fn(source_table_name, iso_now())
    log.info(f"🕓 Updated metadata last_sync for {source_table_name}.")
