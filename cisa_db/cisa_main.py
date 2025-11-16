# fast_api.py
import json
import os
from dotenv import load_dotenv
from extract import extract_cisa_json
from transform import transform_cisa_json
from load import sync_cisa_records_to_dynamodb

load_dotenv()

def build_config_from_env():
    cfg = {
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        "TABLE_NAME": "infoservices-cybersecurity-cisa-data",
        "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "200")),
    }
    return cfg


def main():
    print("🚀 Starting incremental CISA KEV ETL pipeline")

    cfg = build_config_from_env()

    # Default CISA KEV feed
    CISA_FEED_URL = os.getenv(
        "CISA_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    # 1️⃣ Extract
    raw_json = extract_cisa_json(CISA_FEED_URL)

    # 2️⃣ Transform
    records = transform_cisa_json(raw_json)

    # 3️⃣ Load (only DynamoDB, skip S3)
    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    result = sync_cisa_records_to_dynamodb(records, json_bytes, cfg)

    print("✅ ETL finished. Summary:", result)


if __name__ == "__main__":
    main()
