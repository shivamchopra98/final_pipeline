#!/usr/bin/env python3
"""
Auto Merge: NVD Table → Final Table (safe merge mode)

- Auto-detects NVD table primary key (e.g., 'id', 'cve_id', etc.)
- Uses update_item() to merge fields (non-destructive)
- Supports single, limited, or full-table merge
- Skips empty/null fields and retries failed updates
"""

import boto3
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config
from utils.cve_utils import normalize_cve
from utils.dynamo_helpers import parallel_scan

# ---------- CONFIG ----------
REGION = "us-east-1"
NVD_TABLE = "infoservices-cybersecurity-vuln-nvd-data"
FINAL_TABLE = "infoservices-cybersecurity-vuln-final-data"
MAX_WORKERS = 16
SCAN_SEGMENTS = 8

# ---------- LOGGING ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nvd-auto-merge")

# ---------- SETUP ----------
def setup_dynamodb():
    cfg = Config(region_name=REGION, max_pool_connections=80, retries={"max_attempts": 5, "mode": "adaptive"})
    return boto3.resource("dynamodb", config=cfg), boto3.client("dynamodb", config=cfg)


def get_table_key_name(dynamodb_client, table_name):
    """Detects the primary key name of a DynamoDB table."""
    resp = dynamodb_client.describe_table(TableName=table_name)
    key_name = resp["Table"]["KeySchema"][0]["AttributeName"]
    log.info(f"🧩 Detected key for {table_name}: '{key_name}'")
    return key_name


# ---------- MERGE FUNCTION ----------
def merge_items_to_final(dynamodb, items, final_table, nvd_key_name):
    """Merges NVD items into Final table safely using update_item()."""
    updated = 0
    skipped = 0
    start_time = time.time()

    def process_item(item):
        nonlocal updated, skipped
        try:
            # Normalize CVE
            cve = item.get(nvd_key_name) or item.get("id") or item.get("cve_id") or item.get("CVE")
            cve = normalize_cve(cve)
            if not cve:
                skipped += 1
                return False

            # Clean invalid/empty values
            clean = {k: v for k, v in item.items() if v not in [None, "", "null", "None"]}
            if not clean:
                skipped += 1
                return False

            # Build update expression
            update_expr = []
            expr_attr_names = {}
            expr_attr_values = {}

            for k, v in clean.items():
                if k.lower() in ["id", "cve_id", "name"]:
                    continue
                name_placeholder = f"#attr_{k}"
                value_placeholder = f":val_{k}"
                expr_attr_names[name_placeholder] = k
                expr_attr_values[value_placeholder] = v
                update_expr.append(f"{name_placeholder} = {value_placeholder}")

            if not update_expr:
                skipped += 1
                return False

            final_table.update_item(
                Key={"cve_id": cve},
                UpdateExpression="SET " + ", ".join(update_expr),
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values,
            )

            updated += 1
            if updated % 500 == 0:
                log.info(f"✅ Merged {updated} CVEs so far...")
            return True

        except Exception as e:
            log.error(f"❌ Error updating {item.get(nvd_key_name)}: {e}")
            skipped += 1
            return False

    # Parallel merge execution
    log.info(f"⚙️ Starting parallel merge of {len(items)} records...")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        list(ex.map(process_item, items))

    log.info(
        f"🎯 Merge complete: updated={updated}, skipped={skipped}, duration={time.time() - start_time:.2f}s"
    )


# ---------- MAIN MERGE FLOW ----------
def reupload_nvd_to_final_auto(dynamodb, dynamodb_client, target_cves=None, limit=None, full_scan=False):
    nvd_table = dynamodb.Table(NVD_TABLE)
    final_table = dynamodb.Table(FINAL_TABLE)
    nvd_key_name = get_table_key_name(dynamodb_client, NVD_TABLE)

    items = []

    if full_scan:
        # 🔹 Option 1 — Full table merge
        log.info(f"📥 Performing full scan of NVD table '{NVD_TABLE}' ...")
        items = parallel_scan(nvd_table, log=log, total_segments=SCAN_SEGMENTS)
    elif target_cves:
        # 🔹 Option 2 — Only for specific CVEs
        target_cves = [normalize_cve(c) for c in target_cves if c]
        if limit:
            target_cves = target_cves[:limit]
        log.info(f"🎯 Merging {len(target_cves)} selected CVEs from NVD → Final")

        for cve in target_cves:
            try:
                resp = nvd_table.get_item(Key={nvd_key_name: cve})
                if "Item" in resp:
                    items.append(resp["Item"])
                else:
                    log.warning(f"⚠️ CVE {cve} not found in NVD table.")
            except Exception as e:
                log.error(f"❌ Failed to fetch {cve}: {e}")
    else:
        log.warning("⚠️ No CVEs provided and full_scan=False. Nothing to do.")
        return

    if not items:
        log.warning("⚠️ No valid items found to merge.")
        return

    merge_items_to_final(dynamodb, items, final_table, nvd_key_name)


# ---------- MAIN ----------
if __name__ == "__main__":
    dynamodb, dynamodb_client = setup_dynamodb()

    # 🔹 Option A — Single CVE or small list
    target_cves = [
        "CVE-2017-0199",
        # "CVE-2020-0601",
        # "CVE-2021-26855",
    ]

    # 🔹 Option B — Set full_scan=True to merge entire NVD → Final table
    reupload_nvd_to_final_auto(
        dynamodb,
        dynamodb_client,
        target_cves=target_cves,  # or None
        limit=None,               # limit number of CVEs to test
        full_scan=True           # set True for full merge
    )
