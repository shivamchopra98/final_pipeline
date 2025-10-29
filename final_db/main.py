# main.py
import boto3
from botocore.config import Config
from config import REGION, NVD_TABLE, FINAL_TABLE, METADATA_TABLE, SOURCE_SPECS
from transformations import nvd_transform
from utils.logging_utils import setup_logging
from utils.dynamo_helpers import get_last_sync, set_last_sync, get_all_cve_ids
from loaders.nvd_loader import load_nvd_base
from loaders.left_join_loader import left_join_source


def run_pipeline(test_limit: int | None = None):
    log = setup_logging()
    log.info(" 🚀 Starting Vulnerability Sync (LEFT JOIN MODE)")

    # ==========================================================
    # DynamoDB setup
    # ==========================================================
    config = Config(
        region_name=REGION,
        max_pool_connections=50,
        retries={"max_attempts": 5, "mode": "adaptive"},
    )

    dynamodb = boto3.resource("dynamodb", config=config)
    final_table = dynamodb.Table(FINAL_TABLE)
    metadata_table = dynamodb.Table(METADATA_TABLE)

    # ==========================================================
    # Phase A — Load NVD base dataset into final table
    # ==========================================================
    log.info("📥 Loading NVD base data into final table...")
    nvd_cves = load_nvd_base(
        dynamodb,
        final_table,
        NVD_TABLE,
        nvd_transform.clean_and_rename,
        lambda t, ts: set_last_sync(metadata_table, t, ts),
        lambda t: get_last_sync(metadata_table, t),
        limit=test_limit,
    )
    log.info(f"✅ NVD base load complete. Loaded {len(nvd_cves)} CVE IDs from NVD table.")

    # ==========================================================
    # Phase B — Fetch all existing CVE IDs from final table
    # ==========================================================
    log.info("🔍 Fetching all CVE IDs from final table for left joins...")
    final_cve_set = get_all_cve_ids(dynamodb, FINAL_TABLE, log)
    log.info(f"✅ Loaded {len(final_cve_set)} CVE IDs from final table.")

    # ==========================================================
    # Phase C — Left join all other data sources
    # ==========================================================
    for table_name, join_key, transform, is_static in SOURCE_SPECS:
        log.info(f"🔄 Starting left join for {table_name} (static={is_static})")
        left_join_source(
            dynamodb,
            final_table,
            table_name,
            join_key,
            transform,
            final_cve_set,  # ✅ Use final table CVE set instead of NVD-only
            lambda t: get_last_sync(metadata_table, t),
            lambda t, ts: set_last_sync(metadata_table, t, ts),
            is_static=is_static,
            log=log,
        )

    log.info("🏁 ✅ All sources left-joined successfully.")


if __name__ == "__main__":
    run_pipeline()
