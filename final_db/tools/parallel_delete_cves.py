import boto3
import logging
from utils.cve_utils import normalize_cve
from utils.dynamo_helpers import parallel_scan  # ✅ your existing utility

# AWS region and table names
region = "us-east-1"

final_table_name = "infoservices-cybersecurity-vuln-final-data"
atk_table_name = "infoservices-cybersecurity-vuln-static-AttackerKB"
exp_table_name = "infoservices-cybersecurity-vuln-static-exploit-output"

# DynamoDB setup
dynamodb = boto3.resource("dynamodb", region_name=region)
final_table = dynamodb.Table(final_table_name)
atk_table = dynamodb.Table(atk_table_name)
exp_table = dynamodb.Table(exp_table_name)

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("parallel-delete")

def get_all_cves_parallel(table, key_fields, total_segments=8):
    """
    Parallel scan for fetching all CVE IDs from a source DynamoDB table.
    """
    cves = set()
    log.info(f"⚙️ Starting parallel scan for {table.name} (segments={total_segments})")

    items = parallel_scan(
        table,
        total_segments=total_segments,
        log=log
    )

    log.info(f"📦 Scan complete for {table.name}: {len(items)} items fetched")

    for item in items:
        cve = None
        for f in key_fields:
            if f in item and item[f]:
                cve = item[f]
                break
        if cve:
            cves.add(normalize_cve(cve))

    log.info(f"✅ Found {len(cves)} normalized CVEs in {table.name}")
    return cves


# ===============================
# Step 1 — Collect CVEs from sources
# ===============================
log.info("🔍 Collecting CVEs from Attackerkb...")
atk_cves = get_all_cves_parallel(atk_table, ["Name", "CVE", "cve_id"])
log.info(f"✅ Found {len(atk_cves)} Attackerkb CVEs")

log.info("🔍 Collecting CVEs from Exploit-Output...")
exp_cves = get_all_cves_parallel(exp_table, ["CVE_ID", "CVE", "cve_id"])
log.info(f"✅ Found {len(exp_cves)} Exploit-Output CVEs")

total_cves = atk_cves.union(exp_cves)
log.info(f"🧩 Total {len(total_cves)} CVEs to delete from final table")

# ===============================
# Step 2 — Delete CVEs from final table
# ===============================
count = 0
batch_size = 1000  # You can increase if you have many CVEs
cve_list = list(total_cves)

log.info(f"🗑️ Starting batch delete of {len(cve_list)} CVEs...")

for i in range(0, len(cve_list), batch_size):
    chunk = cve_list[i:i + batch_size]
    with final_table.batch_writer() as batch:
        for cve in chunk:
            if not cve:
                continue
            batch.delete_item(Key={"cve_id": cve})
            count += 1
    log.info(f"✅ Deleted {min(i + batch_size, len(cve_list))}/{len(cve_list)} CVEs")

log.info(f"🧹 Finished deleting {count} CVEs from final table.")
