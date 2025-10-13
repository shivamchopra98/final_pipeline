# epss_main.py
import os
from dotenv import load_dotenv
from extract import extract_epss_data_incremental
from transform import transform_epss_api_responses
from load import sync_epss_records_to_dynamodb_and_s3

load_dotenv()

RAW_NVD_XZ = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"
EPSS_API_BASE = os.getenv("EPSS_API_BASE", "https://api.first.org/data/v1/epss?cve=")

EPSS_CONFIG = {
    "TABLE_NAME": os.getenv("EPSS_TABLE", "infoservices-cybersecurity-epss-data"),
    "S3_PREFIX": os.getenv("S3_PREFIX", "vuln-raw-source/epss/"),
    "BASELINE_FILENAME": os.getenv("BASELINE_FILENAME", "epss_baseline.json"),
    "S3_BUCKET": os.getenv("S3_BUCKET"),
    "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
    "BATCH_WRITE_CHUNK_SIZE": int(os.getenv("BATCH_WRITE_CHUNK_SIZE", "1000")),
    "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "500")),
    "PARALLEL_THREADS": int(os.getenv("PARALLEL_THREADS", "20")),
}

def main():
    s3_bucket = EPSS_CONFIG["S3_BUCKET"]
    s3_prefix = EPSS_CONFIG["S3_PREFIX"]
    baseline_key = f"{s3_prefix}{EPSS_CONFIG['BASELINE_FILENAME']}"

    print("▶️ Starting incremental EPSS ETL (in-memory, no file download)...")
    api_results = extract_epss_data_incremental(
        RAW_NVD_XZ, EPSS_API_BASE, s3_bucket, baseline_key, EPSS_CONFIG["AWS_REGION"], batch_size=100
    )

    if not api_results:
        print("✅ No new CVEs to process; everything is up to date.")
        return

    records, json_bytes = transform_epss_api_responses(api_results)
    summary = sync_epss_records_to_dynamodb_and_s3(records, json_bytes, EPSS_CONFIG)
    print("✅ Incremental ETL complete. Summary:", summary)
    return summary

if __name__ == "__main__":
    main()
