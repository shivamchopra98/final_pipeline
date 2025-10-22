# main.py
import boto3
from botocore.config import Config
from config import REGION, NVD_TABLE, FINAL_TABLE, METADATA_TABLE, SOURCE_SPECS
from transformations import nvd_transform
from utils.logging_utils import setup_logging
from utils.dynamo_helpers import get_last_sync, set_last_sync
from loaders.nvd_loader import load_nvd_base
from loaders.left_join_loader import left_join_source


def run_pipeline(test_limit: int | None = None):
    log = setup_logging()
    log.info("🚀 Starting Vulnerability Sync (LEFT JOIN MODE)")

    # ==========================================================
    # ⚙️ AWS DynamoDB Setup with connection pooling and retries
    # ==========================================================
    config = Config(
        region_name=REGION,
        max_pool_connections=50,  # ✅ increase connection pool for concurrent operations
        retries={
            "max_attempts": 5,
            "mode": "adaptive"  # ✅ smart retry mode (backoff)
        }
    )

    dynamodb = boto3.resource("dynamodb", config=config)
    final_table = dynamodb.Table(FINAL_TABLE)
    metadata_table = dynamodb.Table(METADATA_TABLE)

    # ==========================================================
    # 🧱 Phase A — Load NVD as base table
    # ==========================================================
    nvd_cves = load_nvd_base(
        dynamodb,
        final_table,
        NVD_TABLE,
        nvd_transform.clean_and_rename,
        lambda t, ts: set_last_sync(metadata_table, t, ts),
        lambda t: get_last_sync(metadata_table, t),
        limit=test_limit
    )

    # ==========================================================
    # 🔗 Phase B — Left join all other sources sequentially
    # ==========================================================
    for table_name, join_key, transform in SOURCE_SPECS:
        left_join_source(
            dynamodb,
            final_table,
            table_name,
            join_key,
            transform,
            nvd_cves,
            lambda t: get_last_sync(metadata_table, t),
            lambda t, ts: set_last_sync(metadata_table, t, ts),
            log=log
        )

    log.info("🎯 All sources left-joined successfully.")


if __name__ == "__main__":
    # You can limit NVD records during testing like: run_pipeline(test_limit=10)
    run_pipeline()
