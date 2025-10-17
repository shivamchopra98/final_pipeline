import os
from dotenv import load_dotenv

load_dotenv()

from extract import extract_nvd_json
from transform import transform_nvd_json_to_records_and_json_bytes
from load import sync_nvd_records_to_dynamodb

def build_config_from_env():
    return {
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        "TABLE_NAME": os.getenv("NVD_TABLE", "infoservices-cybersecurity-vuln-nvd-data"),
        "BATCH_WRITE_CHUNK_SIZE": int(os.getenv("BATCH_WRITE_CHUNK_SIZE", "200")),
        "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "200")),
        "DDB_ENDPOINT": os.getenv("DDB_ENDPOINT", "")
    }

def main():
    print("🚀 Starting NVD ETL pipeline")
    cfg = build_config_from_env()

    raw_json = extract_nvd_json()
    records, json_bytes = transform_nvd_json_to_records_and_json_bytes(raw_json)
    print(f"📦 Prepared {len(records)} records for DynamoDB")
    print(records[0] if records else "No records to show")
    import time
    time.sleep(100)  # Just to separate logs visually

    summary = sync_nvd_records_to_dynamodb(records, json_bytes, cfg)
    print("✅ ETL finished. Summary:", summary)
    return summary

if __name__ == "__main__":
    main()
