# misp_main.py
import os
from dotenv import load_dotenv

load_dotenv()

from extract import extract_misp_text
from transform import transform_json_text_to_records_and_json_bytes
from load import sync_misp_records_to_dynamodb_and_s3

def build_config_from_env():
    cfg = {
        "S3_BUCKET": os.getenv("S3_BUCKET"),
        "S3_PREFIX": os.getenv("S3_PREFIX", "vuln-raw-source/misp/"),
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        # "DDB_ENDPOINT": os.getenv("DDB_ENDPOINT", ""),  # not required for AWS
        "TABLE_NAME": "infoservices-cybersecurity-vuln-misp-data",
        "BASELINE_FILENAME": os.getenv("BASELINE_FILENAME", "misp_baseline.json"),
        "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "100")),
    }
    if not cfg["S3_BUCKET"]:
        raise RuntimeError("S3_BUCKET must be set in environment or .env")
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] = cfg["S3_PREFIX"] + "/"
    return cfg

def main():
    print("🚀 Starting MISP ETL (in-memory)")

    cfg = build_config_from_env()
    raw_text = extract_misp_text()
    records, json_bytes = transform_json_text_to_records_and_json_bytes(raw_text)
    result = sync_misp_records_to_dynamodb_and_s3(records, json_bytes, cfg)
    print("✅ ETL finished. Summary:", result)
    return result

if __name__ == "__main__":
    main()
