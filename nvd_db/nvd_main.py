# main.py
import os
from dotenv import load_dotenv
from extract import extract_nvd_items
from transform import transform_nvd_items
from load import (
    load_existing_baseline_from_s3,
    upload_baseline_to_s3,
    load_existing_records_from_dynamodb,
    sync_nvd_records_to_dynamodb,
    diff_records,
)

load_dotenv()

S3_BUCKET = os.getenv("S3_BUCKET")
S3_PREFIX = os.getenv("S3_PREFIX")
TABLE_NAME = os.getenv("TABLE_NAME", "infoservices-cybersecurity-vuln-nvd-data")
S3_KEY = f"{S3_PREFIX.rstrip('/')}/nvd-baseline.json"

# Always use latest daily feed
NVD_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"

if not S3_BUCKET or not S3_PREFIX:
    raise RuntimeError("❌ S3_BUCKET or S3_PREFIX not set in .env or environment")


def main():
    print("🚀 Starting incremental NVD ETL pipeline")

    # Step 1: Load existing baseline from S3
    old_records = load_existing_baseline_from_s3(S3_BUCKET, S3_KEY)

    # Step 1b: If S3 baseline missing, fallback to DynamoDB
    if old_records is None:
        print("⚠️ S3 baseline missing. Loading from DynamoDB...")
        old_records = load_existing_records_from_dynamodb(TABLE_NAME)

    # Step 2: Extract & Transform latest NVD feed
    print("⬇️ Extracting and transforming new NVD feed...")
    nvd_items_gen = extract_nvd_items(NVD_URL)
    new_records, _ = transform_nvd_items(list(nvd_items_gen))
    print(f"📊 Total new feed CVEs: {len(new_records)}")

    # Step 3: Compute new/updated records
    changes = diff_records(old_records, new_records)

    if not changes:
        print("✅ No new or updated CVEs detected. Pipeline complete.")
        return

    # Step 4: Update DynamoDB
    sync_nvd_records_to_dynamodb(changes, TABLE_NAME)

    # Step 5: Merge and upload updated baseline to S3
    merged = {**old_records, **{r["id"]: r for r in new_records}}
    upload_baseline_to_s3(list(merged.values()), S3_BUCKET, S3_KEY)

    print("🎉 Incremental ETL pipeline completed successfully.")


if __name__ == "__main__":
    main()
