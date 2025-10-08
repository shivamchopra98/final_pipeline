# cisa_main.py
import os
from dotenv import load_dotenv
from extract import extract_cisa_json
from transform import transform_cisa_json
from load import sync_cisa_records_to_dynamodb_and_s3

load_dotenv()

def build_config_from_env():
    cfg = {
        "S3_BUCKET": os.getenv("S3_BUCKET"),
        "S3_PREFIX": os.getenv("S3_PREFIX", "vuln-raw-source/cisa/"),
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        "TABLE_NAME": "infoservices-cybersecurity-cisa-data",  # fixed table name
        "BASELINE_FILENAME": os.getenv("BASELINE_FILENAME", "cisa_baseline.json"),
        "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "200")),
    }
    if not cfg["S3_BUCKET"]:
        raise RuntimeError("S3_BUCKET must be set in environment or .env")
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] += "/"
    return cfg


def main():
    print("🚀 Starting CISA ETL (in-memory)")

    cfg = build_config_from_env()

    # Default feed URL (can be overridden in .env)
    CISA_FEED_URL = os.getenv(
        "CISA_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    raw_json = extract_cisa_json(CISA_FEED_URL)
    records = transform_cisa_json(raw_json)
    result = sync_cisa_records_to_dynamodb_and_s3(records, cfg)
    print("✅ ETL finished. Summary:", result)


if __name__ == "__main__":
    main()
