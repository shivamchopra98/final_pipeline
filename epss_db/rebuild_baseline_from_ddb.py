import json
import boto3
import pandas as pd

# -----------------------------
# Config
# -----------------------------
csv_file = r"C:\Users\ShivamChopra\Projects\vuln\epss_db\daily_extract\epss_DB.csv"
s3_bucket = "infoservices-cybersecurity-team"
s3_key = "vuln-raw-source/epss/epss_baseline.json"

s3 = boto3.client("s3", region_name="us-east-1")

# -----------------------------
# Read CSV
# -----------------------------
df = pd.read_csv(csv_file)

# -----------------------------
# Clean Data
# -----------------------------
partition_key = "cve"  # DynamoDB partition key
df = df.dropna(subset=[partition_key])  # Remove rows with missing key
df = df.drop_duplicates(subset=[partition_key])

# -----------------------------
# Convert dates to ISO format
# -----------------------------
for col in ["date", "updated_date"]:
    if col in df.columns:
        df[col] = pd.to_datetime(df[col], dayfirst=True, errors="coerce").dt.strftime("%Y-%m-%d")

# -----------------------------
# Convert DataFrame to JSON array
# -----------------------------
data_list = df.to_dict(orient="records")
json_array = json.dumps(data_list, ensure_ascii=False, indent=2)  # Pretty-print

# -----------------------------
# Upload to S3
# -----------------------------
s3.put_object(Bucket=s3_bucket, Key=s3_key, Body=json_array.encode("utf-8"))

print(f"✅ Uploaded JSON array file to s3://{s3_bucket}/{s3_key}")
print(f"➡️ Ready for DynamoDB import using '{partition_key}' as the partition key")
