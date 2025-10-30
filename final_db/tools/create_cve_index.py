import boto3
import logging
import concurrent.futures
from botocore.config import Config
from boto3.dynamodb.conditions import Attr
from utils.dynamo_helpers import parallel_scan
from utils.time_utils import iso_now

# AWS Setup
REGION = "us-east-1"
FINAL_TABLE = "infoservices-cybersecurity-vuln-final-data"
CVE_INDEX_TABLE = "infoservices-cybersecurity-vuln-cveindex"

def setup_dynamodb():
    config = Config(
        region_name=REGION,
        max_pool_connections=50,
        retries={"max_attempts": 5, "mode": "adaptive"},
    )
    return boto3.resource("dynamodb", config=config)

def create_cve_index_table(dynamodb):
    """
    Create CVE index table if it doesn't exist.
    """
    existing_tables = [t.name for t in dynamodb.tables.all()]
    if CVE_INDEX_TABLE in existing_tables:
        print(f"✅ Table '{CVE_INDEX_TABLE}' already exists.")
        return dynamodb.Table(CVE_INDEX_TABLE)

    print(f"⚙️ Creating table '{CVE_INDEX_TABLE}'...")
    table = dynamodb.create_table(
        TableName=CVE_INDEX_TABLE,
        KeySchema=[{"AttributeName": "cve_id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "cve_id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",  # On-Demand mode
    )
    table.wait_until_exists()
    print(f"✅ Table '{CVE_INDEX_TABLE}' created successfully.")
    return table

def sync_cve_ids(dynamodb, log=None):
    """
    Scan the final table and update the CVE Index table.
    """
    log = log or logging.getLogger("cve-index")
    final_table = dynamodb.Table(FINAL_TABLE)
    index_table = dynamodb.Table(CVE_INDEX_TABLE)

    log.info(f"🧩 Scanning {FINAL_TABLE} to collect all CVE IDs...")
    items = parallel_scan(final_table, log=log, total_segments=4)

    log.info(f"📦 Found {len(items)} total records in final table.")
    existing_ids = set()

    # Collect existing CVE IDs from index table
    log.info(f"📋 Loading existing CVE IDs from {CVE_INDEX_TABLE} for deduplication...")
    index_items = parallel_scan(index_table, log=log, total_segments=2)
    existing_ids = {r["cve_id"] for r in index_items if "cve_id" in r}
    log.info(f"✅ Loaded {len(existing_ids)} existing CVE IDs in index table.")

    new_cves = [r["cve_id"] for r in items if "cve_id" in r and r["cve_id"] not in existing_ids]
    log.info(f"🆕 Found {len(new_cves)} new CVE IDs to insert into index table.")

    if not new_cves:
        log.info("✅ No new CVEs to update.")
        return

    def put_item(cve):
        try:
            index_table.put_item(
                Item={
                    "cve_id": cve,
                    "uploaded_date": iso_now()
                }
            )
            return True
        except Exception as e:
            log.error(f"❌ Failed to insert {cve}: {e}")
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        list(executor.map(put_item, new_cves))

    log.info(f"✅ CVE Index table updated with {len(new_cves)} new records.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    log = logging.getLogger("cve-index")

    dynamodb = setup_dynamodb()
    create_cve_index_table(dynamodb)
    sync_cve_ids(dynamodb, log)
