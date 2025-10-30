#!/usr/bin/env python3
"""
load_missing_from_cveindex.py

- Read CVE list from the CVE index table.
- Find CVEs missing in final table.
- Batch-get missing NVD records (parallelized) and insert them into final table.
- Left-join the configured source tables (CISA, ExploitDB, Metasploit) only for
  target CVEs, using update_item() to avoid overwrites.
"""

import logging
import time
import math
import random
from typing import Set, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import boto3
from botocore.config import Config
from boto3.dynamodb.conditions import Attr

from utils.dynamo_helpers import parallel_scan
from utils.cve_utils import normalize_cve
from utils.time_utils import iso_now

# ---------- CONFIG ----------
REGION = "us-east-1"

CVE_INDEX_TABLE = "infoservices-cybersecurity-vuln-cveindex"
NVD_TABLE = "infoservices-cybersecurity-vuln-nvd-data"
FINAL_TABLE = "infoservices-cybersecurity-vuln-final-data"

from transformations import nvd_transform, cisa_transform, exploitdb_transform, metasploit_transform

SOURCE_SPECS = [
    ("infoservices-cybersecurity-cisa-data", "cveID", cisa_transform.clean_and_rename),
    ("infoservices-cybersecurity-vuln-exploitdb-data", "CVE_id", exploitdb_transform.clean_and_rename),
    ("infoservices-cybersecurity-vuln-metasploit-data", "cve_id", metasploit_transform.clean_and_rename),
]

# Tuning
SCAN_SEGMENTS = 8                # parallel_scan segments
MAX_WORKERS = 16                 # for parallel batch_get and updates
BATCH_GET_MAX = 100              # AWS limit
PUT_CHUNK = 500                  # items per batch_writer chunk when writing final table
BATCHGET_RETRY_SLEEP = 0.2       # base sleep for retrying unprocessed keys
PUT_PARALLEL_WORKERS = 8         # number of threads for parallel put chunks
# -----------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("load-missing-cves")

def setup_dynamodb():
    cfg = Config(region_name=REGION, max_pool_connections=80, retries={"max_attempts": 5, "mode": "adaptive"})
    return boto3.resource("dynamodb", config=cfg), boto3.client("dynamodb", config=cfg)

# ---------- Utilities ----------
def dynamo_lowlevel_to_simple(item: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a low-level DynamoDB item (from client) to a simple Python dict."""
    out = {}
    for k, v in item.items():
        # v is like {"S": "value"} or {"N": "1"} or {"NULL": True} or {"BOOL": True} or {"M": {...}} etc.
        dtype, val = next(iter(v.items()))
        if dtype == "S":
            out[k] = val
        elif dtype == "N":
            # keep as string or convert to int/float heuristically
            if "." in val:
                try:
                    out[k] = float(val)
                except Exception:
                    out[k] = val
            else:
                try:
                    out[k] = int(val)
                except Exception:
                    out[k] = val
        elif dtype == "BOOL":
            out[k] = bool(val)
        elif dtype == "NULL":
            out[k] = None
        elif dtype == "M":
            # convert nested map recursively
            out[k] = {kk: dynamo_lowlevel_to_simple({kk: vv})[kk] for kk, vv in val.items()}
        elif dtype == "L":
            # convert list elements
            converted = []
            for elem in val:
                # each elem is a single-key dict
                converted.append(dynamo_lowlevel_to_simple(elem).get(next(iter(elem.keys()))))
            out[k] = converted
        else:
            out[k] = val
    return out

def describe_table_key_schema(dynamodb_client, table_name: str):
    """Return list of attribute names used as KeySchema. Example: ['cve_id'] or ['cve_id','version']"""
    resp = dynamodb_client.describe_table(TableName=table_name)
    ks = resp["Table"].get("KeySchema", [])
    key_attrs = [entry["AttributeName"] for entry in ks]
    return key_attrs

# ---------- Core functions ----------
def get_cve_index_set(dynamodb) -> Set[str]:
    """Read all CVE ids from the CVE index table using parallel_scan (fast)."""
    table = dynamodb.Table(CVE_INDEX_TABLE)
    log.info(f"Scanning CVE index table '{CVE_INDEX_TABLE}' with segments={SCAN_SEGMENTS} ...")
    items = parallel_scan(table, log=log, total_segments=SCAN_SEGMENTS)
    cves = set()
    for it in items:
        raw = it.get("cve_id") or it.get("CVE") or it.get("CVE_ID") or it.get("Name")
        if raw:
            norm = normalize_cve(raw)
            if norm:
                cves.add(norm)
    log.info(f"Found {len(cves)} CVEs in index table")
    return cves

def get_existing_final_cves(dynamodb) -> Set[str]:
    """Scan final table to collect existing cve_id set."""
    table = dynamodb.Table(FINAL_TABLE)
    segs = max(2, SCAN_SEGMENTS // 2)
    log.info(f"Scanning final table '{FINAL_TABLE}' to collect existing CVEs (segments={segs}) ...")
    items = parallel_scan(table, log=log, total_segments=segs)
    cves = {it["cve_id"] for it in items if "cve_id" in it}
    log.info(f"Found {len(cves)} existing CVEs in final table")
    return cves

def parallel_batch_get_nvd(dynamodb_client, keys: List[str], max_workers: int = MAX_WORKERS) -> List[Dict[str, Any]]:
    """
    Parallel batch_get for NVD table, respecting table key schema.
    Returns list of simple python dicts (converted).
    """
    if not keys:
        return []

    key_attrs = describe_table_key_schema(dynamodb_client, NVD_TABLE)
    if len(key_attrs) != 1:
        # Complex key schema — fallback to per-item get_item (slower)
        log.warning(f"NVD table has composite key {key_attrs}. Falling back to individual get_item calls (slower).")
        return _sequential_get_items(dynamodb_client, keys, key_attrs)

    pk = key_attrs[0]
    log.info(f"Detected NVD table partition key: '{pk}' (using it to batch-get).")

    # chunk keys into batches of at most BATCH_GET_MAX
    chunks = [keys[i:i+BATCH_GET_MAX] for i in range(0, len(keys), BATCH_GET_MAX)]
    results = []

    def fetch_chunk(chunk):
        # Build RequestItems structure
        request_keys = [{pk: {"S": c}} for c in chunk]
        request_items = {NVD_TABLE: {"Keys": request_keys}}
        attempt = 0
        max_attempts = 5
        backoff = 0.1
        collected = []
        while attempt < max_attempts:
            attempt += 1
            try:
                resp = dynamodb_client.batch_get_item(RequestItems=request_items)
            except Exception as e:
                log.error(f"BatchGet error attempt {attempt} for {len(chunk)} keys: {e}")
                time.sleep(backoff + random.random() * 0.1)
                backoff *= 2
                continue

            # convert returned items
            returned = resp.get("Responses", {}).get(NVD_TABLE, [])
            for r in returned:
                simple = dynamo_lowlevel_to_simple(r)
                collected.append(simple)

            # Check unprocessed keys
            unprocessed = resp.get("UnprocessedKeys", {}).get(NVD_TABLE, {}).get("Keys", [])
            if not unprocessed:
                break

            # Build next request_items from unprocessed keys
            request_items = {NVD_TABLE: {"Keys": unprocessed}}
            sleep_time = BATCHGET_RETRY_SLEEP * attempt
            log.info(f"BatchGet returned {len(unprocessed)} unprocessed keys, retrying after {sleep_time:.2f}s")
            time.sleep(sleep_time)
        return collected

    log.info(f"Parallel batch-get: total keys={len(keys)}, batches={len(chunks)}, workers={max_workers}")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(fetch_chunk, ch) for ch in chunks]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.extend(res)
            except Exception as e:
                log.error(f"A batch_get worker failed: {e}")

    log.info(f"Batch-get complete: retrieved {len(results)} items from NVD table")
    return results

def _sequential_get_items(dynamodb_client, keys: List[str], key_attrs: List[str]) -> List[Dict[str, Any]]:
    """Fallback when table uses composite key: perform individual get_item (slower)."""
    # We'll use resource Table to simplify conversion
    resource = boto3.resource("dynamodb", region_name=REGION)
    table = resource.Table(NVD_TABLE)
    out = []
    for k in keys:
        key = {key_attrs[0]: k}
        try:
            resp = table.get_item(Key=key)
            if "Item" in resp:
                out.append(resp["Item"])
        except Exception as e:
            log.error(f"Error get_item for {k}: {e}")
    log.info(f"Sequential get_items fetched {len(out)} items")
    return out

def parallel_put_items_into_final(dynamodb, items: List[Dict[str, Any]], chunk_size: int = PUT_CHUNK, workers: int = PUT_PARALLEL_WORKERS):
    """Put items into final table using parallel batch_writer chunks."""
    if not items:
        log.info("No NVD items to put into final table.")
        return

    table = dynamodb.Table(FINAL_TABLE)
    chunks = [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]
    log.info(f"Putting {len(items)} items into final table in {len(chunks)} chunks using {workers} workers")

    def put_chunk(chunk):
        local_count = 0
        try:
            with table.batch_writer() as batch:
                for it in chunk:
                    # ensure cve_id is present and normalized
                    cve = it.get("cve_id") or it.get("CVE") or it.get("id")
                    if not cve:
                        continue
                    # if the item uses low-level format (unlikely here), ensure it's plain dict
                    batch.put_item(Item=it)
                    local_count += 1
        except Exception as e:
            log.error(f"Batch put failed for chunk size {len(chunk)}: {e}")
        return local_count

    total = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(put_chunk, ch) for ch in chunks]
        for fut in as_completed(futures):
            try:
                res = fut.result()
                total += res
            except Exception as e:
                log.error(f"Put chunk worker failed: {e}")

    log.info(f"Inserted total {total} NVD items into final table")

def parallel_update_from_source(dynamodb, source_table_name: str, source_join_key: str, transform_fn, target_cve_set: Set[str]):
    """
    Parallel-scan source_table and update final table only for source records whose normalized CVE is in target_cve_set.
    Uses update_item (partial updates) to avoid overwriting existing final items.
    """
    src_table = dynamodb.Table(source_table_name)
    final = dynamodb.Table(FINAL_TABLE)
    log.info(f"🔄 Starting parallel left-join for {source_table_name} -> only CVEs in provided set (scan segments={SCAN_SEGMENTS})")

    items = parallel_scan(src_table, log=log, total_segments=SCAN_SEGMENTS)
    log.info(f"📦 Found {len(items)} records in source {source_table_name}")

    updated_count = 0
    debug_print_limit = 5

    def process(rec):
        nonlocal updated_count
        raw_cve = rec.get("cve_id") or rec.get(source_join_key) or rec.get("CVE") or rec.get("cveID") or rec.get("CVE_ID")
        cve = normalize_cve(raw_cve)
        if not cve:
            return False
        if cve not in target_cve_set:
            return False

        transformed = transform_fn(rec)
        if not transformed:
            return False

        # don't allow uploaded_date from source to overwrite final timestamp
        transformed.pop("uploaded_date", None)

        # build update expression (skip cve_id)
        update_expr = []
        expr_attr_values = {}
        expr_attr_names = {}
        for k, v in transformed.items():
            if k == "cve_id":
                continue
            name_ph = f"#attr_{k}"
            val_ph = f":val_{k}"
            expr_attr_names[name_ph] = k
            expr_attr_values[val_ph] = v
            update_expr.append(f"{name_ph} = {val_ph}")

        if not update_expr:
            return False

        try:
            final.update_item(
                Key={"cve_id": cve},
                UpdateExpression="SET " + ", ".join(update_expr),
                ExpressionAttributeNames=expr_attr_names,
                ExpressionAttributeValues=expr_attr_values
            )
            updated_count += 1
            if updated_count <= debug_print_limit:
                log.info(f"Updated {cve} from {source_table_name} fields: {list(transformed.keys())}")
            return True
        except Exception as e:
            log.error(f"Failed to update {cve} from {source_table_name}: {e}")
            return False

    # run in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        list(ex.map(process, items))

    log.info(f"Completed left-join for {source_table_name}: updated ~{updated_count} items")
    return updated_count

# ---------- Main flow ----------
def main():
    dynamodb, dynamodb_client = setup_dynamodb()

    log.info("Step 1 — get CVEs from CVE index table")
    cve_index_set = get_cve_index_set(dynamodb)
    if not cve_index_set:
        log.info("No CVEs found in CVE index table. Exiting.")
        return

    log.info("Step 2 — get existing CVEs from final table")
    existing_final = get_existing_final_cves(dynamodb)

    missing_cves = sorted(list(cve_index_set - existing_final))
    log.info(f"Found {len(missing_cves)} CVEs missing in final table (will load from NVD)")

    if missing_cves:
        # Fetch in manageable windows to avoid giant memory spikes and to allow incremental puts
        window = 20000
        total_fetched = 0
        for i in range(0, len(missing_cves), window):
            window_keys = missing_cves[i:i+window]
            log.info(f"Fetching window {i}..{i+len(window_keys)} (size {len(window_keys)}) via parallel batch-get")
            nvd_items = parallel_batch_get_nvd(dynamodb_client, window_keys, max_workers=MAX_WORKERS)
            total_fetched += len(nvd_items)
            if nvd_items:
                # ensure 'cve_id' is normalized and present in each returned item
                for it in nvd_items:
                    if "cve_id" not in it:
                        # attempt common alternatives
                        if "CVE" in it:
                            it["cve_id"] = normalize_cve(it["CVE"])
                        elif "id" in it:
                            it["cve_id"] = normalize_cve(it["id"])
                # write in parallel chunks
                parallel_put_items_into_final(dynamodb, nvd_items)
            else:
                log.warning("No NVD items returned for this window; check NVD table keys/formats.")
        log.info(f"Fetched and inserted total {total_fetched} NVD items for missing CVEs")
    else:
        log.info("No missing CVEs to load from NVD.")

    # Refresh final CVE set
    log.info("Refreshing final CVE set after NVD insert...")
    final_cves_after = get_existing_final_cves(dynamodb)
    target_set = set(cve_index_set).intersection(final_cves_after)
    log.info(f"Target CVE set for left-joins size: {len(target_set)}")

    # Left-join each source (sequential over sources; each source uses parallel_scan internally)
    for table_name, join_key, transform_fn in SOURCE_SPECS:
        start = time.time()
        parallel_update_from_source(dynamodb, table_name, join_key, transform_fn, target_set)
        log.info(f"Source {table_name} left-join completed in {time.time() - start:.2f}s")

    log.info("All requested sources left-joined successfully for target CVEs.")

if __name__ == "__main__":
    main()
