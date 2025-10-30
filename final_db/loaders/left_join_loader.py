# loaders/left_join_loader_cveindex.py
import logging
import time
import concurrent.futures
from boto3.dynamodb.conditions import Attr
from utils.dynamo_helpers import parallel_scan
from utils.cve_utils import normalize_cve


def left_join_source_from_cveindex(
    dynamodb,
    final_table,
    cveindex_table_name: str,
    source_table_name: str,
    source_join_key: str,
    transform_fn,
    get_last_sync_fn,
    set_last_sync_fn,
    is_static: bool = False,
    log=None,
    total_segments: int = 8,
):
    """
    Left-join a source (APTfinal, AttackerKB, etc.) onto final table
    using CVE IDs from the CVE Index table instead of scanning the final table.
    ⚡ Much faster for static datasets.

    Args:
        dynamodb: boto3 resource
        final_table: DynamoDB.Table for final data
        cveindex_table_name: Table name of the CVE index
        source_table_name: Source table name
        source_join_key: Field in source table that maps to CVE
        transform_fn: Transformation function for source record
        get_last_sync_fn: Metadata getter
        set_last_sync_fn: Metadata setter
        is_static: True if the source is static (no uploaded_date)
        log: Logger
        total_segments: Parallel scan segments
    """
    log = log or logging.getLogger("left-join-cveindex")

    log.info(f"🔄 Starting left join for {source_table_name} (static={is_static}) using CVE index")

    source_table = dynamodb.Table(source_table_name)
    cveindex_table = dynamodb.Table(cveindex_table_name)

    # ==========================================================
    # Step 1 — Load CVE set from CVE index
    # ==========================================================
    log.info(f"📥 Scanning CVE index table '{cveindex_table_name}' to collect CVEs ...")
    cve_items = parallel_scan(cveindex_table, log=log, total_segments=total_segments)
    cve_set = {normalize_cve(i.get("cve_id")) for i in cve_items if i.get("cve_id")}
    log.info(f"✅ Loaded {len(cve_set)} CVEs from index table.")

    # ==========================================================
    # Step 2 — Scan source table (static/dynamic)
    # ==========================================================
    last_sync = get_last_sync_fn(source_table_name)
    if is_static:
        log.info(f"⚙️ Static dataset detected — performing full scan for {source_table_name}")
        items = parallel_scan(source_table, log=log, total_segments=total_segments)
    else:
        log.info(f"🔍 Incremental scan: uploaded_date > {last_sync}")
        items = parallel_scan(
            source_table,
            log=log,
            filter_expr=Attr("uploaded_date").gt(last_sync),
            total_segments=total_segments
        )

    if not items:
        log.warning(f"⚠️ No records found in {source_table_name}")
        return

    log.info(f"📦 Found {len(items)} records in {source_table_name}")

    # ==========================================================
    # Step 3 — Parallel join for matching CVEs
    # ==========================================================
    updated, skipped = 0, 0
    start = time.time()

    def process(rec):
        nonlocal updated, skipped
        raw_cve = rec.get("cve_id") or rec.get(source_join_key) or rec.get("CVE") or rec.get("cveID") or rec.get("CVE_ID")
        cve_id = normalize_cve(raw_cve)
        if not cve_id or cve_id not in cve_set:
            skipped += 1
            return False

        transformed = transform_fn(rec)
        if not transformed:
            skipped += 1
            return False

        transformed.pop("uploaded_date", None)
        expr_attr_values, expr_attr_names = {}, {}
        update_expr = []

        for k, v in transformed.items():
            if k == "cve_id":
                continue
            name_placeholder = f"#attr_{k}"
            val_placeholder = f":val_{k}"
            expr_attr_names[name_placeholder] = k
            expr_attr_values[val_placeholder] = v
            update_expr.append(f"{name_placeholder} = {val_placeholder}")

        if not update_expr:
            skipped += 1
            return False

        try:
            final_table.update_item(
                Key={"cve_id": cve_id},
                UpdateExpression="SET " + ", ".join(update_expr),
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values,
            )
            updated += 1
            return True
        except Exception as e:
            log.error(f"❌ Failed to update CVE {cve_id}: {e}")
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(process, items))

    log.info(
        f"✅ Left join complete for {source_table_name}: updated {updated}, skipped {skipped}, duration={time.time()-start:.2f}s"
    )

    # ==========================================================
    # Step 4 — Metadata update for dynamic sources
    # ==========================================================
    if not is_static:
        max_uploaded = max((rec.get("uploaded_date", "") for rec in items), default=None)
        if max_uploaded:
            set_last_sync_fn(source_table_name, max_uploaded)
            log.info(f"🕒 Stored max(uploaded_date) = {max_uploaded} for {source_table_name}")
