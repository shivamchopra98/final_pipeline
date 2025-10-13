# metasploit_main.py
import os
from dotenv import load_dotenv

load_dotenv()

from extract import download_raw_json_to_text
from transform import transform_json_text_to_records_and_json_bytes
from load_metasploit import sync_records_to_dynamodb_and_store_baseline

RAW_JSON_URL = os.getenv(
    "METASPLOIT_RAW_URL",
    "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
)

def build_config_from_env():
    cfg = {
        "TABLE_NAME": os.getenv("METASPLOIT_TABLE", "infoservices-cybersecurity-vuln-metasploit-data"),
        # IMPORTANT: default DDB_ENDPOINT to empty string so production AWS is used unless overridden
        "DDB_ENDPOINT": os.getenv("DDB_ENDPOINT", ""),
        "AWS_REGION": os.getenv("AWS_REGION", "us-east-1"),
        "S3_BUCKET": os.getenv("S3_BUCKET"),
        "S3_PREFIX": os.getenv("S3_PREFIX", "vuln-raw-source/metasploit/"),
        "BASELINE_FILENAME": os.getenv("BASELINE_FILENAME", "metasploit_baseline.json"),
        "CANONICAL_FILENAME": os.getenv("CANONICAL_FILENAME", "metasploit.json"),
        "AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
        "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY"),
        "BATCH_PROGRESS_INTERVAL": int(os.getenv("BATCH_PROGRESS_INTERVAL", "100")),
        "BATCH_WRITE_CHUNK_SIZE": int(os.getenv("BATCH_WRITE_CHUNK_SIZE", "500")),
    }
    if not cfg["S3_BUCKET"]:
        raise RuntimeError("S3_BUCKET must be set in environment or .env")
    if cfg["S3_PREFIX"] and not cfg["S3_PREFIX"].endswith("/"):
        cfg["S3_PREFIX"] = cfg["S3_PREFIX"] + "/"
    return cfg

def main():
    print("▶️ Starting Metasploit ETL (in-memory, JSON-based)")
    cfg = build_config_from_env()

    raw_url = os.getenv("METASPLOIT_RAW_URL", RAW_JSON_URL)
    raw_text = download_raw_json_to_text(raw_url)
    records, json_bytes = transform_json_text_to_records_and_json_bytes(raw_text)
    summary = sync_records_to_dynamodb_and_store_baseline(records, json_bytes, cfg)
    print("✅ ETL finished. Summary:", summary)
    return summary

if __name__ == "__main__":
    main()
