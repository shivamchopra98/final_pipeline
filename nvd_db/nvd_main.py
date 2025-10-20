import os
from dotenv import load_dotenv
from extract import extract_nvd_json
from transform import transform_nvd_json_to_records_and_json_bytes
from load import sync_nvd_records_to_dynamodb

load_dotenv()

def build_config_from_env():
    return {
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        "TABLE_NAME": os.getenv("NVD_TABLE", "infoservices-cybersecurity-vuln-nvd-data"),
        "BATCH_WRITE_CHUNK_SIZE": int(os.getenv("BATCH_WRITE_CHUNK_SIZE", "200")),
        "DDB_ENDPOINT": os.getenv("DDB_ENDPOINT", "")
    }

def main():
    print("🚀 Starting NVD Incremental ETL Pipeline")
    cfg = build_config_from_env()

    json_text = extract_nvd_json()
    records, json_bytes = transform_nvd_json_to_records_and_json_bytes(json_text)
    summary = sync_nvd_records_to_dynamodb(records, json_bytes, cfg)

    print("✅ ETL finished. Summary:", summary)

if __name__ == "__main__":
    main()
