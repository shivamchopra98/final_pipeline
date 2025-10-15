# utils/dynamo_utils.py
import boto3
from botocore.exceptions import ClientError

def ensure_table(client, table_name, key_attr):
    """
    Ensure a DynamoDB table exists; create it if missing (PAY_PER_REQUEST).
    """
    try:
        client.describe_table(TableName=table_name)
        print(f"✅ Table '{table_name}' already exists.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            print(f"⚙️ Creating table '{table_name}'...")
            client.create_table(
                TableName=table_name,
                KeySchema=[{"AttributeName": key_attr, "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": key_attr, "AttributeType": "S"}],
                BillingMode="PAY_PER_REQUEST",
            )
            boto3.resource("dynamodb").Table(table_name).meta.client.get_waiter("table_exists").wait(
                TableName=table_name
            )
            print(f"🚀 Table '{table_name}' created successfully!")
        else:
            raise

def scan_all(table):
    """
    Read all items from a DynamoDB table with pagination.
    """
    items = []
    response = table.scan()
    items.extend(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items
