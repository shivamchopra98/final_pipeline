# extract_epss.py
import lzma
import json
import requests
import itertools
import time
import boto3
from typing import List, Set, Dict, Any
from botocore.config import Config
from botocore.exceptions import ClientError

def download_nvd_xz_and_extract_cves(xz_url: str, timeout: int = 60) -> List[str]:
    print(f"⬇️ Downloading {xz_url} (in-memory)...")
    resp = requests.get(xz_url, timeout=timeout)
    resp.raise_for_status()
    print("🔧 Decompressing .xz (in-memory)...")
    raw = lzma.decompress(resp.content)
    print("🔎 Parsing JSON...")
    parsed = json.loads(raw.decode("utf-8"))
    cve_items = parsed.get("CVE_Items") or parsed.get("cve_items") or []

    cves = []
    for item in cve_items:
        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID") if isinstance(item.get("cve"), dict) else item.get("id")
        if cve_id:
            cves.append(str(cve_id).strip().upper())
    print(f"ℹ️ Extracted {len(cves)} CVEs from NVD file")
    return cves

def _s3_get_existing_cves(bucket: str, key: str, region: str) -> Set[str]:
    s3 = boto3.client("s3", region_name=region, config=Config(retries={"max_attempts": 3}))
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        baseline = json.loads(resp["Body"].read().decode("utf-8"))
        existing = {item["cve"].upper() for item in baseline if "cve" in item}
        print(f"ℹ️ Loaded {len(existing)} existing CVEs from baseline S3")
        return existing
    except ClientError as e:
        if e.response["Error"]["Code"] in ("NoSuchKey", "404", "NotFound"):
            print("ℹ️ No existing baseline found in S3 (fresh start)")
            return set()
        raise

def call_epss_api_for_batch(api_base: str, cve_batch: List[str], session: requests.Session, timeout: int = 30):
    q = ",".join(cve_batch)
    url = f"{api_base}{q}"
    for attempt in range(1, 5):
        try:
            resp = session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.HTTPError as e:
            status = getattr(e.response, "status_code", None)
            if status in (429, 502, 503, 504):
                wait = attempt * 2
                print(f"⚠️ API {status}, backoff {wait}s (attempt {attempt})")
                time.sleep(wait)
                continue
            raise
        except Exception as e:
            if attempt < 4:
                wait = attempt * 2
                print(f"⚠️ API call error, retrying in {wait}s: {e}")
                time.sleep(wait)
                continue
            raise
    return None

def extract_epss_data_incremental(xz_url: str, epss_api_base: str, s3_bucket: str, s3_key: str, aws_region: str, batch_size: int = 50):
    """Extract CVEs not yet in S3 baseline and query EPSS only for them."""
    all_cves = download_nvd_xz_and_extract_cves(xz_url)
    existing_cves = _s3_get_existing_cves(s3_bucket, s3_key, aws_region)
    remaining = [c for c in all_cves if c not in existing_cves]
    print(f"🧮 Remaining CVEs to fetch: {len(remaining)} (out of {len(all_cves)})")

    session = requests.Session()
    results = []

    def chunks(iterable, n):
        it = iter(iterable)
        while True:
            chunk = list(itertools.islice(it, n))
            if not chunk:
                break
            yield chunk

    for batch in chunks(remaining, batch_size):
        print(f"➡️ Querying EPSS API for {len(batch)} CVEs (sample: {batch[:3]})")
        resp = call_epss_api_for_batch(epss_api_base, batch, session)
        if not resp:
            continue
        data = resp.get("data") if isinstance(resp, dict) else resp
        if not data:
            continue
        results.extend(data)

    print(f"✅ Incremental EPSS extraction complete: {len(results)} records fetched")
    return results
