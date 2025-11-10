import sys
import os
import io
import json
import time
import pandas as pd
from decimal import Decimal
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ============================================================
# PATH SETUP
# ============================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."))
sys.path.extend([
    BASE_DIR,
    os.path.join(ROOT_DIR, "vuln_output"),
    ROOT_DIR,
])

# ============================================================
# IMPORT UTILITIES
# ============================================================
from utils.vrr_utils import generate_vrr_score
from utils.id_utils import generate_host_finding_id
from utils.transform_utils import prepare_output_dataframe
from utils.dynamodb_utils import (
    batch_get_by_cves,
    extract_cwes_from_item,
    extract_threats_from_item
)

# ============================================================
# ENVIRONMENT & APP SETUP
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
# HELPER FUNCTIONS
# ============================================================
def split_cve_cell(cell: str):
    if not cell or pd.isna(cell):
        return []
    parts = [p.strip() for p in str(cell).replace(";", ",").split(",")]
    return [p for p in parts if p]

def make_json_safe(obj):
    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, set):
        return [make_json_safe(v) for v in obj]
    elif isinstance(obj, Decimal):
        return float(obj)
    elif obj is None or pd.isna(obj):
        return None
    return obj

def fix_invalid_json(value):
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, ensure_ascii=False)
        except Exception:
            return json.dumps({"raw_text": value}, ensure_ascii=False)
    elif isinstance(value, (dict, list)):
        try:
            return json.dumps(make_json_safe(value), ensure_ascii=False)
        except Exception:
            return json.dumps({"error": "json_encode_failed"}, ensure_ascii=False)
    if pd.isna(value):
        return json.dumps({})
    return json.dumps({"value": str(value)}, ensure_ascii=False)

def sanitize_field(val):
    if isinstance(val, str):
        return val.replace("\n", " ").replace("\r", " ")
    return val

# ============================================================
# ROOT ROUTE
# ============================================================
@app.get("/")
def home():
    """Health check route."""
    return {"status": "✅ Backend is running successfully!"}

# ============================================================
# 🔹 Route: Vulnerability Scan + DynamoDB Enrichment
# ============================================================
@app.post("/scan-vulnerabilities/")
async def scan_vulnerabilities(input_file: UploadFile = File(...)):
    try:
        start_time = time.time()
        contents = await input_file.read()
        input_df = pd.read_csv(io.BytesIO(contents), encoding="latin1")
        print(f"✅ Uploaded: {input_file.filename} | Rows={len(input_df)}")

        # Prepare output dataframe
        base_out = prepare_output_dataframe(input_df, generate_vrr_score, generate_host_finding_id)

        # Extract CVEs
        all_cves = []
        row_cve_lists = []
        for _, row in input_df.iterrows():
            cves = split_cve_cell(row.get("CVE", ""))
            row_cve_lists.append(cves)
            all_cves.extend(cves)

        if not all_cves:
            return JSONResponse({"message": "No CVEs found in uploaded file."})

        table_name = os.getenv("DYNAMODB_TABLE", "infoservices-cybersecurity-vuln-final-data")
        cve_to_item = batch_get_by_cves(table_name, all_cves, max_workers=6)

        # Extract Weaknesses and Threats
        global_cwe_set, global_threats = set(), set()
        for item in cve_to_item.values():
            global_cwe_set.update(extract_cwes_from_item(item))
            threats = extract_threats_from_item(item)
            if isinstance(threats, dict):
                global_threats.update(threats.keys())

        vulnerabilities_col, weaknesses_col, threat_col = [], [], []
        for cves in row_cve_lists:
            matched_full_records, matched_vulns, matched_cwes = [], [], set()
            for cve in cves:
                item = cve_to_item.get(cve)
                if item:
                    matched_full_records.append(item)
                    matched_vulns.append(str(item.get("cve_id", cve)))
                    matched_cwes.update(extract_cwes_from_item(item))

            merged_threat = {}
            for rec in matched_full_records:
                nested_threats = extract_threats_from_item(rec)
                if isinstance(nested_threats, dict):
                    for k, v in nested_threats.items():
                        merged_threat.setdefault(k, {}).update(v)

            vulnerabilities_col.append(list(dict.fromkeys(matched_vulns)))
            weaknesses_col.append(sorted(list(matched_cwes)))
            threat_col.append(merged_threat)

        base_out["Vulnerabilities"] = vulnerabilities_col
        base_out["Weaknesses"] = weaknesses_col
        base_out["Threat"] = threat_col

        for col in ["Vulnerabilities", "Weaknesses", "Threat"]:
            base_out[col] = base_out[col].apply(fix_invalid_json).apply(sanitize_field)

        filtered_out = base_out[
            base_out["Vulnerabilities"].apply(lambda x: bool(x) and str(x).strip() not in ["", "[]", "nan"])
        ]

        elapsed = round(time.time() - start_time, 2)
        print(f"✅ Completed in {elapsed}s | {len(filtered_out)} enriched records")

        json_data = json.loads(filtered_out.to_json(orient="records"))
        return JSONResponse(
            content={
                "status": "success",
                "message": f"Processed {len(filtered_out)} records in {elapsed}s",
                "data": json_data,
                "cwes": sorted(list(global_cwe_set)),
                "threats": sorted(list(global_threats)),
            }
        )

    except Exception as e:
        print(f"❌ Error: {e}")
        return JSONResponse(content={"status": "error", "message": str(e)}, status_code=500)

# ============================================================
# MAIN ENTRY POINT
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("fast_api:app", host="0.0.0.0", port=8000, reload=True)
