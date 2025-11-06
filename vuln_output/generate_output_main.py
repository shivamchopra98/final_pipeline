import os
import json
import argparse
import pandas as pd
import csv
from decimal import Decimal

from utils.vrr_utils import generate_vrr_score
from utils.id_utils import generate_host_finding_id
from utils.transform_utils import prepare_output_dataframe
from utils.dynamodb_utils import (
    batch_get_by_cves,
    extract_cwes_from_item,
    extract_threats_from_item,
)

# ---------- ARGUMENT PARSER ----------
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--input", "-i", default="vuln_input_a.csv", help="Input Nessus CSV")
    p.add_argument("--output", "-o", default="vulnerability_output.csv", help="Output CSV")
    p.add_argument("--table", "-t", default="infoservices-cybersecurity-vuln-final-data", help="DynamoDB table name")
    p.add_argument("--workers", "-w", type=int, default=4, help="Number of parallel workers for DynamoDB batches")
    p.add_argument("--test-create-input", action="store_true", help="Create test input with 100 CVEs (for local testing)")
    return p.parse_args()


# ---------- UTILITIES ----------
def split_cve_cell(cell: str):
    """Split a CSV cell that may contain multiple CVEs (comma/semicolon separated)"""
    if not cell or pd.isna(cell):
        return []
    parts = [p.strip() for p in str(cell).replace(";", ",").split(",")]
    return [p for p in parts if p]


def make_json_safe(obj):
    """Recursively make sure all data types are JSON serializable."""
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
    """Ensure each Threat/Vulnerabilities/Weaknesses value is valid JSON."""
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return json.dumps(parsed, ensure_ascii=False)
        except Exception:
            return json.dumps({"raw_text": value}, ensure_ascii=False)
    elif isinstance(value, (dict, list)):
        try:
            return json.dumps(make_json_safe(value), ensure_ascii=False)
        except Exception as e:
            print(f"⚠️ JSON encode error: {e}")
            return json.dumps({"error": "json_encode_failed"}, ensure_ascii=False)
    if pd.isna(value):
        return json.dumps({})
    return json.dumps({"value": str(value)}, ensure_ascii=False)


def sanitize_field(val):
    """Remove newlines for Excel/CSV safety."""
    if isinstance(val, str):
        return val.replace("\n", " ").replace("\r", " ")
    return val


# ---------- MAIN ----------
def main():
    args = parse_args()
    INPUT_FILE = args.input
    OUTPUT_FILE = args.output
    TABLE = args.table
    WORKERS = args.workers

    if args.test_create_input:
        rows = []
        for i in range(1, 101):
            rows.append(
                {
                    "Plugin ID": "9999",
                    "CVE": f"CVE-TEST-{i:04d}",
                    "CVSS": "",
                    "Risk": "None",
                    "Host": "10.10.1.20",
                    "Protocol": "tcp",
                    "Port": "80",
                    "Name": "TEST-VULN",
                    "Synopsis": "test",
                    "Description": "test",
                    "Solution": "",
                    "See Also": "",
                    "Plugin Output": "",
                }
            )
        pd.DataFrame(rows).to_csv(INPUT_FILE, index=False)
        print(f"Test input created: {INPUT_FILE} (100 test CVEs)")

    print(f"🔍 Reading input from: {os.path.abspath(INPUT_FILE)}")
    with open(INPUT_FILE, "r", encoding="latin1") as f:
        df = pd.read_csv(f)

    base_out = prepare_output_dataframe(df, generate_vrr_score, generate_host_finding_id)

    # ---------- Collect CVEs ----------
    all_cves = []
    row_cve_lists = []
    for _, r in df.iterrows():
        cves = split_cve_cell(r.get("CVE", ""))
        row_cve_lists.append(cves)
        all_cves.extend(cves)

    print(f"⚡ Fetching {len(set(all_cves))} unique CVEs from DynamoDB table '{TABLE}' using up to {WORKERS} workers...")
    cve_to_item = batch_get_by_cves(TABLE, all_cves, max_workers=WORKERS)

    # ---------- Global sets ----------
    global_cwe_set = set()
    global_threats = set()
    for item in cve_to_item.values():
        for c in extract_cwes_from_item(item):
            global_cwe_set.add(c)
        for t in extract_threats_from_item(item):
            if isinstance(t, str):
                global_threats.add(t)

    # ---------- Per-row enrichments ----------
    vulnerabilities_col, weaknesses_col, threat_col = [], [], []

    for cves in row_cve_lists:
        matched_full_records = []
        matched_vulns = []
        matched_cwes = set()

        for cve in cves:
            item = cve_to_item.get(cve)
            if item:
                matched_full_records.append(item)
                if "cve_id" in item:
                    matched_vulns.append(str(item["cve_id"]))
                elif "CVE" in item:
                    matched_vulns.append(str(item["CVE"]))
                else:
                    matched_vulns.append(cve)
                for cw in extract_cwes_from_item(item):
                    matched_cwes.add(cw)

        # ✅ Build nested Threat JSON (instead of full_record)
        if matched_full_records:
            merged_threat = {}
            for rec in matched_full_records:
                nested_threats = extract_threats_from_item(rec)
                for group_name, group_data in nested_threats.items():
                    if group_name not in merged_threat:
                        merged_threat[group_name] = {}
                    merged_threat[group_name].update(group_data)
            threat_col.append(merged_threat)
        else:
            threat_col.append({})

        vulnerabilities_col.append(list(dict.fromkeys(matched_vulns)))
        weaknesses_col.append(sorted(list(matched_cwes)))

    # ---------- Attach results ----------
    base_out["Vulnerabilities"] = vulnerabilities_col
    base_out["Weaknesses"] = weaknesses_col
    base_out["Threat"] = threat_col

    # ---------- Clean & Fix JSON ----------
    for col in ["Vulnerabilities", "Weaknesses", "Threat"]:
        base_out[col] = base_out[col].apply(fix_invalid_json)
        base_out[col] = base_out[col].apply(sanitize_field)

    # ---------- Filter & Limit ----------
    filtered_out = base_out[
        base_out["Vulnerabilities"].apply(lambda x: bool(x) and str(x).strip() not in ["", "[]", "nan"])
    ]

    # ---------- Write to CSV ----------
    filtered_out.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig",
        quoting=csv.QUOTE_ALL,
        lineterminator="\n",
    )
    print(f"✅ CSV file generated: {OUTPUT_FILE}")

    # ---------- Write to Excel ----------
    try:
        excel_output = OUTPUT_FILE.replace(".csv", ".xlsx")
        filtered_out.to_excel(excel_output, index=False, engine="openpyxl")
        print(f"✅ Excel file generated: {excel_output}")
    except ImportError:
        print("⚠️ openpyxl not installed. Run 'pip install openpyxl' to enable Excel export.")

    print(f"✅ Output file generated successfully with {len(filtered_out)} matched CVE records.")
    print(f"Global unique CWEs found across matches: {sorted(list(global_cwe_set))}")
    print(f"Global unique Threats found across matches: {sorted(list(global_threats))}")


if __name__ == "__main__":
    main()
