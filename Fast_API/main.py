import os
import io
import re
import json
import time
import asyncio
import boto3
import pandas as pd
from dotenv import load_dotenv
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
from botocore.exceptions import ClientError
from boto3.dynamodb.types import TypeDeserializer
from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import scanner detector logic
from scanner_detector import detect_scanner, build_unified_output

# ============================================================
#  ENVIRONMENT & APP SETUP
# ============================================================
load_dotenv()

app = FastAPI(title="Cybersecurity Accelerator API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
#  DYNAMODB CONNECTION
# ============================================================
dynamodb = boto3.resource(
    "dynamodb",
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    region_name=os.getenv("AWS_DEFAULT_REGION"),
)

TABLE_NAME = os.getenv("DYNAMODB_TABLE")
table = dynamodb.Table(TABLE_NAME)
client = table.meta.client
_deserializer = TypeDeserializer()

# ============================================================
#  SAFE DESERIALIZATION
# ============================================================
def safe_deserialize(obj):
    """Recursively convert DynamoDB attribute maps to native Python types."""
    if isinstance(obj, dict):
        if set(obj.keys()) & {"S", "N", "BOOL", "L", "M", "NULL"}:
            try:
                return _deserializer.deserialize(obj)
            except Exception:
                return str(obj)
        return {k: safe_deserialize(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [safe_deserialize(v) for v in obj]
    else:
        return obj


def deserialize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Safely deserialize all DynamoDB attributes."""
    try:
        return {k: safe_deserialize(v) for k, v in item.items()}
    except Exception as e:
        print(f"⚠️ Error deserializing item: {e}")
        return {}


# ============================================================
#  UTILITIES
# ============================================================
def read_file_safely(contents: bytes, filename: str) -> pd.DataFrame:
    """Read CSV, Excel, JSON, or XML safely."""
    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(io.BytesIO(contents), encoding="latin-1")
        elif filename.endswith(".xlsx"):
            df = pd.read_excel(io.BytesIO(contents))
        elif filename.endswith(".json"):
            df = pd.read_json(io.BytesIO(contents))
        elif filename.endswith(".xml"):
            df = pd.read_xml(io.BytesIO(contents))
        else:
            raise ValueError("Unsupported file format.")
        print(f"✅ Loaded CSV using encoding=latin-1: {df.shape[0]} rows, {df.shape[1]} cols")
        return df
    except Exception as e:
        raise ValueError(f"Error reading file: {str(e)}")


def chunks(lst, n):
    """Split a list into chunks of size n."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def fetch_batch(batch, key_name):
    """Fetch a batch of records from DynamoDB with retries."""
    req = {table.name: {"Keys": [{key_name: k} for k in batch]}}
    out = []
    try:
        resp = client.batch_get_item(RequestItems=req)
        for i in resp.get("Responses", {}).get(table.name, []):
            out.append(deserialize_item(i))
    except ClientError as e:
        print("❌ DynamoDB batch fetch error:", e)
    return out


def parallel_batch_get(keys: List[str], key_name="cve_id", max_workers=12):
    """Parallel DynamoDB batch-get with ThreadPoolExecutor."""
    results = []
    all_batches = list(chunks(keys, 100))
    if not all_batches:
        return []
    print(f"⚡ parallel_batch_get: {len(all_batches)} batches, workers={max_workers}")
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(fetch_batch, b, key_name) for b in all_batches]
        for i, f in enumerate(futures, 1):
            try:
                results.extend(f.result())
            except Exception as e:
                print("Error in worker:", e)
            if i % 5 == 0 or i == len(futures):
                print(f"📦 Completed {i}/{len(futures)} batches ({len(results)} items so far)")
    return results


def sanitize_for_json(df: pd.DataFrame):
    """Ensure DataFrame can be safely converted to JSON."""
    df = df.copy().replace([float("inf"), float("-inf")], None)
    df = df.where(pd.notnull(df), None)
    return json.loads(df.to_json(orient="records"))


# ============================================================
#  ROUTES
# ============================================================
@app.get("/")
def home():
    """Simple health check route."""
    return {"status": "✅ Backend is running successfully!"}


@app.post("/generate-unified-output/")
async def generate_unified_output(input_file: UploadFile = File(...)):
    """Process uploaded scanner file → detect → normalize → enrich via DynamoDB."""
    try:
        contents = await input_file.read()
        df = read_file_safely(contents, input_file.filename)

        # Detect scanner
        scanner = detect_scanner(df)
        print(f"📁 Detected scanner: {scanner}")

        # Normalize scanner data
        unified = build_unified_output(df, scanner)
        print(f"🔎 Unified table has {unified.shape[0]} rows and {unified.shape[1]} columns")

        # ============================================================
        #  STEP 1: Extract CVEs from all possible columns
        # ============================================================
        cve_cols = [c for c in df.columns if any(k in c.lower() for k in ["cve", "vulnerab", "description", "plugin"])]
        print(f"ℹ️ Candidate CVE-related columns to inspect: {cve_cols}")

        cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
        found_cves = set()

        for col in cve_cols:
            df[col] = df[col].astype(str)
            for text in df[col]:
                found_cves.update(cve_pattern.findall(text))

        if not found_cves:
            print("⚠️ No valid CVE patterns found in the input file — skipping enrichment.")
            json_data = sanitize_for_json(unified)
            return JSONResponse(content={"scanner": scanner, "count": len(json_data), "data": json_data})

        cves = sorted(list({c.upper().strip() for c in found_cves}))
        print(f"🔍 Found {len(cves)} unique CVEs extracted from file")

        # ============================================================
        #  STEP 2: Fetch enrichment data from DynamoDB
        # ============================================================
        start = time.time()
        loop = asyncio.get_event_loop()
        raw = await loop.run_in_executor(None, partial(parallel_batch_get, cves))
        elapsed = round(time.time() - start, 2)
        print(f"✅ Parallel fetch complete. items={len(raw)} elapsed={elapsed}s")

        if not raw:
            print("⚠️ No enrichment data returned from DynamoDB")
            json_data = sanitize_for_json(unified)
            return JSONResponse(content={"scanner": scanner, "count": len(json_data), "data": json_data})

        enrich_df = pd.DataFrame(raw)
        if "cve_id" not in enrich_df.columns:
            print("⚠️ No cve_id found in DynamoDB results — skipping merge")
            json_data = sanitize_for_json(unified)
            return JSONResponse(content={"scanner": scanner, "count": len(json_data), "data": json_data})

        # ============================================================
        #  STEP 3: Merge enrichment data
        # ============================================================
        enrich_df["cve_id"] = enrich_df["cve_id"].astype(str).str.upper().str.strip()

        # Expand CVEs if found in the unified DataFrame
        unified["CVE_Extracted"] = unified.astype(str).apply(
            lambda row: ",".join(cve_pattern.findall(" ".join(row.values))), axis=1
        )

        expanded = unified.assign(CVE_Clean=unified["CVE_Extracted"].str.split(",")).explode("CVE_Clean")
        expanded["CVE_Clean"] = expanded["CVE_Clean"].str.strip().str.upper()

        merged = expanded.merge(
            enrich_df,
            left_on="CVE_Clean",
            right_on="cve_id",
            how="inner",
            suffixes=("", "_enriched"),
        )

        unmatched = expanded[~expanded["CVE_Clean"].isin(enrich_df["cve_id"])]
        print(f"⚠️ Unmatched CVEs: {len(unmatched)} (showing 5) → {unmatched['CVE_Clean'].dropna().unique()[:5]}")
        print(f"✅ Merge complete — {len(merged)} enriched findings (out of {len(unified)})")

        # ============================================================
        #  STEP 4: Clean output and return response
        # ============================================================
        json_data = sanitize_for_json(merged)
        csv_str = merged.to_csv(index=False)

        summary = {
            "total_input_rows": len(unified),
            "unique_cves_found": len(cves),
            "enriched_rows": len(merged),
            "unmatched_cves": len(unmatched),
        }

        return JSONResponse(
            content={
                "scanner": scanner,
                "summary": summary,
                "count": len(json_data),
                "data": json_data,
                "csv": csv_str,
            }
        )

    except Exception as e:
        print("❌ Backend Error:", e)
        return JSONResponse(status_code=500, content={"error": str(e)})
