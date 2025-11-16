"""
FastAPI application for Vulnerability Scan API
Uses generate_output_main.process_file() from vuln_output folder
"""

import sys
import os
import io
import json
import time
import pandas as pd

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from typing import Dict, Any


# ============================================================
# FIX PYTHON PATH (IMPORTANT)
# ============================================================
# Path of this file = Info_vuln/api/fast_api.py
# We need to reach: Info_vuln/, Info_vuln/vuln_output/, Info_vuln/vuln_output/utils/

CURRENT_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
sys.path.append(ROOT_DIR)

VULN_DIR = os.path.join(ROOT_DIR, "vuln_output")
sys.path.append(VULN_DIR)

UTILS_DIR = os.path.join(VULN_DIR, "utils")
sys.path.append(UTILS_DIR)

print("=== PYTHONPATH ===")
print("ROOT_DIR:", ROOT_DIR)
print("VULN_DIR:", VULN_DIR)
print("UTILS_DIR:", UTILS_DIR)
print("===================")

# Import the main processing function
from vuln_output.generate_output_main import process_file


# ============================================================
# FASTAPI SETUP
# ============================================================
app = FastAPI(
    title="Vulnerability Processing API",
    description="Upload scanner CSV → Enriched vulnerability output",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["*"],  # Set specific hosts in production
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# HEALTH CHECK
# ============================================================
@app.get("/health", response_model=Dict[str, str])
async def health():
    return {"status": "healthy", "service": "vulnerability-api"}


# ============================================================
# VULNERABILITY SCAN ENDPOINT
# ============================================================
@app.post("/scan-vulnerabilities", response_model=Dict[str, Any])
async def scan_vulnerabilities(input_file: UploadFile = File(...)):
    """
    Upload a CSV → process via generate_output_main.process_file()
    → return enriched vulnerability data (Same as CLI output)
    """
    try:
        start_time = time.time()
        print(f"Received file: {input_file.filename}")

        # Save uploaded file to temporary path
        contents = await input_file.read()
        temp_path = "/tmp/vuln_input.csv"
        with open(temp_path, "wb") as f:
            f.write(contents)

        # Run the unified processing logic from generate_output_main
        table = os.getenv("DYNAMODB_TABLE", "infoservices-cybersecurity-vuln-final-data")
        final_df = process_file(temp_path, table, workers=6)

        # Convert DataFrame → JSON
        final_json = json.loads(final_df.to_json(orient="records"))

        elapsed = round(time.time() - start_time, 2)
        print(f"Processed in {elapsed}s → Total Rows = {len(final_json)}")

        return {
            "success": True,
            "message": f"Processed {len(final_json)} rows in {elapsed}s",
            "records": len(final_json),
            "data": final_json,
        }

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# RUN LOCALLY (DEV)
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.fast_api:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000)),
        reload=True
    )
