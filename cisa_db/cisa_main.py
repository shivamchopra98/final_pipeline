import os
import boto3
from extract import download_raw_json
from transform import transform_json
from load import sync_today_with_dynamodb
from dotenv import load_dotenv

load_dotenv()  # load .env variables

RAW_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CISA_CONFIG = {
    "TABLE_NAME": "cisa_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "BASELINE_FILENAME": "cisa_extract.json",
    "BATCH_PROGRESS_SIZE": 25
}

S3_BUCKET = os.getenv("S3_BUCKET")
S3_PREFIX = os.getenv("S3_PREFIX")

def upload_to_s3(local_path):
    s3 = boto3.client("s3")
    key = os.path.join(S3_PREFIX, os.path.basename(local_path)).replace("\\", "/")
    print(f"⬆️ Uploading to s3://{S3_BUCKET}/{key}")
    s3.upload_file(local_path, S3_BUCKET, key)
    print(f"✅ Upload complete\n✅ File stored at: s3://{S3_BUCKET}/{key}")
    return f"s3://{S3_BUCKET}/{key}"

def main():
    daily_dir = "./daily_extract"
    os.makedirs(daily_dir, exist_ok=True)

    # 1) Extract
    try:
        local_path = download_raw_json(RAW_JSON_URL, daily_dir)
        print(f"✅ File stored locally at: {local_path}")
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return

    # 2) Transform (local)
    try:
        transformed_path = transform_json(local_path)
    except Exception as e:
        print(f"❌ Transformation failed: {e}")
        return

    # 3) Upload transformed JSON to S3
    try:
        s3_uri = upload_to_s3(transformed_path)
    except Exception as e:
        print(f"❌ S3 upload failed: {e}")
        return

    # 4) Load / Sync to DynamoDB
    try:
        res = sync_today_with_dynamodb(transformed_path, config=CISA_CONFIG)
        print("✅ Sync result:", res)
    except Exception as e:
        print(f"❌ Load/sync failed: {e}")
        return

if __name__ == "__main__":
    main()
