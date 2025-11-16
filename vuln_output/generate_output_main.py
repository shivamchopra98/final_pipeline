# generate_output_main.py
import json
import argparse
import pandas as pd
import csv
import logging
from decimal import Decimal
from typing import List, Dict, Any

# utils
from utils.vrr_utils import calculate_vrr_score
from utils.id_utils import generate_host_finding_id
from utils.transform_utils import prepare_output_dataframe
from utils.dynamodb_utils import batch_get_by_cves, extract_cwes_from_item
from utils.threat_utils import extract_cves_from_row, build_threat_json as format_threat_json


# -----------------------------------------------------------
# LOGGING CONFIGURATION
# -----------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


# -----------------------------------------------------------
# JSON Helpers
# -----------------------------------------------------------
def make_json_safe(o):
    if isinstance(o, dict):
        return {k: make_json_safe(v) for k, v in o.items()}
    if isinstance(o, list):
        return [make_json_safe(v) for v in o]
    if isinstance(o, set):
        return [make_json_safe(v) for v in o]
    if isinstance(o, Decimal):
        return float(o)
    return o


# -----------------------------------------------------------
# SAVE OUTPUT — USED BY CLI & FASTAPI
# -----------------------------------------------------------
def save_output(df: pd.DataFrame, output_path: str):
    """
    Saves the DataFrame to CSV (and Excel when possible).
    Works for CLI and FastAPI calls.
    """
    try:
        df.to_csv(
            output_path,
            index=False,
            encoding="utf-8-sig",
            quoting=csv.QUOTE_ALL,
            lineterminator="\n"
        )
        logger.info(f"CSV saved → {output_path}")
    except Exception as e:
        logger.error(f"Failed to save CSV: {e}")
        raise

    # Excel output (optional)
    try:
        excel_path = output_path.replace(".csv", ".xlsx")
        df.to_excel(excel_path, index=False, engine="openpyxl")
        logger.info(f"Excel saved → {excel_path}")
    except Exception:
        logger.warning("Excel not saved (openpyxl unavailable or failed).")


# -----------------------------------------------------------
# MAIN PROCESSING — FastAPI-compatible
# -----------------------------------------------------------
def process_file(input_path: str, table: str, workers: int = 6) -> pd.DataFrame:
    """
    Reads scanner CSV, enriches with DynamoDB, returns final DataFrame.
    FASTAPI uses this function directly.
    """
    logger.info(f"Reading input file: {input_path}")
    df_raw = pd.read_csv(input_path, encoding="latin1")
    logger.info(f"Loaded {len(df_raw)} rows")

    # -----------------------------------------------------------
    # CVE Extraction
    # -----------------------------------------------------------
    logger.info("Extracting CVEs from input rows...")
    row_cve_lists = []
    all_cves = set()

    for _, row in df_raw.iterrows():
        cves = extract_cves_from_row(row)
        row_cve_lists.append(cves)
        all_cves.update(cves)

    logger.info(f"Total unique CVEs found: {len(all_cves)}")

    # -----------------------------------------------------------
    # Prepare unified output frame
    # -----------------------------------------------------------
    base = prepare_output_dataframe(df_raw, calculate_vrr_score, generate_host_finding_id)

    # -----------------------------------------------------------
    # DynamoDB Fetch
    # -----------------------------------------------------------
    if all_cves:
        logger.info(f"Fetching {len(all_cves)} CVE records from DynamoDB table '{table}' using {workers} workers...")
        cve_items = batch_get_by_cves(table, sorted(list(all_cves)), max_workers=workers)
    else:
        logger.warning("No CVEs found — Threat field will contain minimal information.")
        cve_items = {}

    # -----------------------------------------------------------
    # Row-by-row enrichment
    # -----------------------------------------------------------
    vulnerabilities = []
    weaknesses = []
    threats = []
    vrr_scores = []  # <--- NEW

    for cves in row_cve_lists:
        matched_records = [cve_items.get(c) for c in cves if c in cve_items]

        vul_list = []
        cwe_set = set()

        for rec in matched_records:
            if not rec:
                continue

            cid = rec.get("cve_id") or rec.get("CVE")
            if cid:
                vul_list.append(cid)

            raw_cwes = extract_cwes_from_item(rec)
            for cw in raw_cwes:
                if isinstance(cw, str) and cw.upper().startswith("CWE-"):
                    cwe_set.add(cw.strip())

        vulnerabilities.append(sorted(set(vul_list)))
        weaknesses.append(sorted(cwe_set))
        threats.append(format_threat_json(matched_records, cves))

        # NEW — VRR Score from FIRST matched DynamoDB record
        if matched_records:
            vrr = calculate_vrr_score(matched_records[0])
        else:
            vrr = 0

        vrr_scores.append(vrr)

    base["VRR Score"] = vrr_scores

    # -----------------------------------------------------------
    # Add columns to DF
    # -----------------------------------------------------------
    base["Vulnerabilities"] = vulnerabilities
    base["Weaknesses"] = weaknesses
    base["Threat"] = threats

    # Convert dict/list → JSON string
    for col in ["Vulnerabilities", "Weaknesses", "Threat"]:
        base[col] = base[col].apply(lambda v: json.dumps(make_json_safe(v), ensure_ascii=False))

    # -----------------------------------------------------------
    # Final Output Schema
    # -----------------------------------------------------------
    final_cols = [
        "Host Findings ID",
        "VRR Score",
        "Scanner Name",
        "Scanner plugin ID",
        "Vulnerability name",
        "Scanner Reported Severity",
        "Scanner Severity",
        "Description",
        "Status",
        "Port",
        "Protocol",
        "Plugin Output",
        "Possible Solutions",
        "Possible patches",
        "IPAddress",
        "Vulnerabilities",
        "Weaknesses",
        "Threat"
    ]

    final_df = base[final_cols].copy()
    logger.info("DataFrame prepared successfully.")

    return final_df


# -----------------------------------------------------------
# CLI ENTRYPOINT
# -----------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", "-i", required=True)
    p.add_argument("--output", "-o", required=True)
    p.add_argument("--table", "-t", required=True)
    p.add_argument("--workers", "-w", type=int, default=6)
    return p.parse_args()


def main():
    args = parse_args()
    df = process_file(args.input, args.table, args.workers)
    save_output(df, args.output)
    logger.info("✔ Completed successfully.")


if __name__ == "__main__":
    main()
