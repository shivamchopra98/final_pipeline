import os
import json
import boto3
from botocore.exceptions import ClientError

DEFAULT_CONFIG = {
    "TABLE_NAME": "cisa_data",
    "DDB_ENDPOINT": "http://localhost:8000",
    "AWS_REGION": "us-east-1",
    "PROJECT_ROOT": r"C:\Users\ShivamChopra\Projects\vuln\cisa_db",
    "DAILY_DIR": None,
    "BASELINE_FILENAME": "cisa_extract.json",
    "BATCH_PROGRESS_SIZE": 25
}

def _resolve_config(user_config):
    cfg = DEFAULT_CONFIG.copy()
    if user_config:
        cfg.update(user_config)
    if not cfg["DAILY_DIR"]:
        cfg["DAILY_DIR"] = os.path.join(cfg["PROJECT_ROOT"], "daily_extract")
    cfg["BASELINE_FILE"] = os.path.join(cfg["DAILY_DIR"], cfg["BASELINE_FILENAME"])
    os.makedirs(cfg["DAILY_DIR"], exist_ok=True)
    return cfg

def get_dynamodb_table(cfg):
    ddb = boto3.resource(
        "dynamodb",
        region_name=cfg["AWS_REGION"],
        aws_access_key_id="dummy",
        aws_secret_access_key="dummy",
        endpoint_url=cfg["DDB_ENDPOINT"]
    )
    table = ddb.Table(cfg["TABLE_NAME"])
    return table

def load_json_to_map(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {str(r["cveID"]).strip(): r for r in data if "cveID" in r}

def items_equal(rec_a, rec_b):
    if rec_b is None:
        return False
    for k, v in rec_a.items():
        if k == "uploaded_date":
            continue
        if rec_a.get(k) != rec_b.get(k):
            return False
    return True

def sync_today_with_dynamodb(current_json_path: str, config: dict = None):
    cfg = _resolve_config(config)
    table = get_dynamodb_table(cfg)

    # Load current JSON
    current_map = load_json_to_map(current_json_path)
    total_current = len(current_map)
    print(f"ℹ️ Loaded current transformed records: {total_current}")

    # Load baseline if exists
    baseline_file = cfg["BASELINE_FILE"]
    baseline_map = {}
    if os.path.exists(baseline_file):
        baseline_map = load_json_to_map(baseline_file)
        print(f"ℹ️ Baseline exists with {len(baseline_map)} records")
    else:
        print("ℹ️ No baseline found (first run)")

    # Compute changed/new records
    changed_ids = [cid for cid, rec in current_map.items()
                   if cid not in baseline_map or not items_equal(rec, baseline_map[cid])]

    # Prepare writes
    to_write = []
    for cid in changed_ids:
        rec = current_map[cid]
        try:
            resp = table.get_item(Key={"cveID": cid})
            ddb_item = resp.get("Item")
        except ClientError:
            ddb_item = None
        if ddb_item is None or not items_equal(rec, ddb_item):
            to_write.append(rec)

    # Batch write
    uploaded = 0
    if to_write:
        print(f"⬆️ Writing {len(to_write)} items to DynamoDB...")
        with table.batch_writer(overwrite_by_pkeys=["cveID"]) as batch:
            for rec in to_write:
                safe_item = {k: (v if v != "" else None) for k, v in rec.items()}
                batch.put_item(Item=safe_item)
                uploaded += 1
        print(f"⬆️ Uploaded {uploaded}/{len(to_write)} items")
    else:
        print("ℹ️ Nothing to write to DynamoDB.")

    # Overwrite baseline
    os.replace(current_json_path, baseline_file)
    print(f"✅ Baseline updated: {baseline_file}")

    return {
        "total_current": total_current,
        "changed_ids": len(changed_ids),
        "uploaded": uploaded,
        "baseline_file": baseline_file,
        "table": cfg["TABLE_NAME"]
    }
