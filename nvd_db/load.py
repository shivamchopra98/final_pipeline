# load.py
import boto3
import json
from decimal import Decimal

def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


# ----------------------
# S3 helpers
# ----------------------
def load_existing_baseline_from_s3(bucket, key):
    """Load baseline from S3. Returns dict keyed by CVE id, or None if missing."""
    s3 = boto3.client("s3")
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
        data = json.loads(obj["Body"].read())
        print(f"📦 Loaded existing baseline from s3://{bucket}/{key} ({len(data)} records)")
        return {r["id"]: r for r in data}
    except s3.exceptions.NoSuchKey:
        print("⚠️ No existing baseline found in S3.")
        return None

def upload_baseline_to_s3(records, bucket, key):
    """Upload merged baseline to S3."""
    s3 = boto3.client("s3")
    json_bytes = json.dumps(records, ensure_ascii=False, indent=2, default=_decimal_default).encode("utf-8")
    s3.put_object(Bucket=bucket, Key=key, Body=json_bytes)
    print(f"✅ Baseline updated in s3://{bucket}/{key} ({len(records)} total CVEs)")


# ----------------------
# DynamoDB helpers
# ----------------------
def load_existing_records_from_dynamodb(table_name):
    """Load all records from DynamoDB into a dict keyed by CVE id."""
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    try:
        records = {}
        response = table.scan()
        scanned = 0
        for item in response.get("Items", []):
            records[item["id"]] = item
            scanned += 1
            if scanned % 5000 == 0:
                print(f"📦 Scanned {scanned} items from DynamoDB...")

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            for item in response.get("Items", []):
                records[item["id"]] = item
                scanned += 1
                if scanned % 5000 == 0:
                    print(f"📦 Scanned {scanned} items from DynamoDB...")

        print(f"📦 Loaded {len(records)} existing records from DynamoDB table '{table_name}'")
        return records
    except dynamodb.meta.client.exceptions.ResourceNotFoundException:
        print(f"⚠️ DynamoDB table '{table_name}' does not exist.")
        return {}


def sync_nvd_records_to_dynamodb(records, table_name, chunk_size=5000):
    """Write new or updated records to DynamoDB in chunks with progress logging."""
    if not records:
        print("⚠️ No records to sync to DynamoDB.")
        return

    dynamodb = boto3.resource("dynamodb")
    existing_tables = [t.name for t in dynamodb.tables.all()]

    if table_name not in existing_tables:
        print(f"⚠️ Table {table_name} not found. Creating...")
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table.wait_until_exists()
        print(f"✅ Table {table_name} created.")
    else:
        table = dynamodb.Table(table_name)

    total = len(records)
    for i in range(0, total, chunk_size):
        batch_records = records[i:i+chunk_size]
        with table.batch_writer() as batch:
            for rec in batch_records:
                batch.put_item(Item=rec)
        print(f"✅ Written {min(i + chunk_size, total)} / {total} new/updated CVEs to DynamoDB")
    

# ----------------------
# Diff helper
# ----------------------
def diff_records(old_records_dict, new_records_list):
    """
    Compare old vs new records using lastModified.
    Returns only new or updated records.
    """
    new_or_updated = []
    for rec in new_records_list:
        old = old_records_dict.get(rec["id"])
        if not old:
            new_or_updated.append(rec)
        elif rec.get("lastModified") != old.get("lastModified"):
            new_or_updated.append(rec)
    print(f"🔍 Found {len(new_or_updated)} new or updated CVEs")
    return new_or_updated
