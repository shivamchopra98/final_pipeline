# rebuild_baseline_from_ddb.py
import json
import boto3

table_name = "infoservices-cybersecurity-epss-data"
s3_bucket = "infoservices-cybersecurity-team"
s3_key = "vuln-raw-source/epss/epss_baseline.json"

dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
table = dynamodb.Table(table_name)
s3 = boto3.client("s3", region_name="us-east-1")

print(f"📥 Scanning entire DynamoDB table: {table_name}")
items = []
scan_kwargs = {}
while True:
    response = table.scan(**scan_kwargs)
    items.extend(response.get("Items", []))
    print(f"  → Collected {len(items)} items so far...")
    if "LastEvaluatedKey" not in response:
        break
    scan_kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

print(f"✅ Total records exported: {len(items)}")

# Convert to JSON and upload to S3
baseline_bytes = json.dumps(items, ensure_ascii=False, indent=2).encode("utf-8")
s3.put_object(Bucket=s3_bucket, Key=s3_key, Body=baseline_bytes)

print(f"⬆️ Uploaded new baseline to s3://{s3_bucket}/{s3_key}")
print("✅ Baseline rebuilt successfully!")
