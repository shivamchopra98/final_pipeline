# transformations/nvd_transform.py
"""
NVD transformation (strict final schema with logging):
- Retains only final schema columns required by the unified table
- Renames and standardizes fields
- Flattens CVSS metrics into dedicated columns
- Adds detailed logs for visibility and debugging
"""

import logging
from typing import Any, Dict, Optional

# ===========================================================
# 🧾 Logging Setup
# ===========================================================
log = logging.getLogger(__name__)

# ===========================================================
# 🎯 Final Schema Columns
# ===========================================================
NVD_FINAL_COLUMNS = [
    "cve_id",
    "nvd_references",
    "weakness",
    "nvd_descriptions",
    "metrics_cvssmetricv31",
    "metrics_cvssmetricv30",
    "metrics_cvssmetricv2",
    "metrics_cvssmetricv40",
]

# ===========================================================
# 🧩 Utility Helpers
# ===========================================================
def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value from the record."""
    for n in names:
        if n in record:
            return record[n]
    return None


def extract_cvss(metric_section: Any) -> Optional[Dict[str, Any]]:
    """
    Convert a DynamoDB-style CVSS metric structure into a flattened dictionary.
    Expected format: {"L": [{"M": {...}}]}
    """
    if not metric_section or not isinstance(metric_section, dict):
        return None

    try:
        if "L" in metric_section and isinstance(metric_section["L"], list) and metric_section["L"]:
            first = metric_section["L"][0]
            if isinstance(first, dict) and "M" in first:
                metric = first["M"]
                cvss_map = {}

                # Extract nested cvssData block
                cvss_data = metric.get("cvssData", {}).get("M", {})
                for k, v in cvss_data.items():
                    if isinstance(v, dict):
                        cvss_map[k] = list(v.values())[0]  # {"S": "HIGH"} → "HIGH"
                    else:
                        cvss_map[k] = v

                # Extract numeric scores
                expl = metric.get("exploitabilityScore")
                imp = metric.get("impactScore")
                if isinstance(expl, dict) and "N" in expl:
                    cvss_map["exploitabilityScore"] = float(expl["N"])
                if isinstance(imp, dict) and "N" in imp:
                    cvss_map["impactScore"] = float(imp["N"])

                return cvss_map or None

    except Exception as e:
        log.warning(f"⚠️ nvd_transform.extract_cvss error: {e}")

    return None


# ===========================================================
# 🧱 Main Transformation Logic
# ===========================================================
def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cleans and renames NVD record fields.
    Keeps only final schema columns and discards any extra data.
    """
    out: Dict[str, Any] = {}

    # --- Primary key ---
    cve_val = _get_field(record, ["id", "cveID", "CVE_ID"])
    if cve_val:
        out["cve_id"] = cve_val
    else:
        log.debug("⚠️ Missing CVE ID in NVD record")

    # --- Define rename map (strict mapping only) ---
    rename_map = {
        "id": "cve_id",
        "references": "nvd_references",
        "weakness": "weakness",
        "descriptions": "nvd_descriptions",

    }

    # --- Apply renames ---
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val
            log.debug(f"🪶 Renamed field '{old}' → '{new}'")

    # --- Flatten metrics ---
    metrics = _get_field(record, ["metrics", "Metrics"])
    metric_versions = {
        "cvssMetricV31": "metrics_cvssmetricv31",
        "cvssMetricV30": "metrics_cvssmetricv30",
        "cvssMetricV2": "metrics_cvssmetricv2",
        "cvssMetricV40": "metrics_cvssmetricv40",
    }

    for src, dest in metric_versions.items():
        parsed = None
        if isinstance(metrics, dict) and src in metrics:
            parsed = extract_cvss(metrics.get(src))
        out[dest] = parsed

    # --- Keep only final schema fields ---
    strict_output = {k: out.get(k) for k in NVD_FINAL_COLUMNS if k in out or k == "cve_id"}

    # --- Log summary ---
    if "cve_id" in strict_output:
        log.debug(f"✅ Transformed NVD record for CVE {strict_output['cve_id']}")
    else:
        log.debug("⚠️ Skipped NVD record (missing CVE ID)")

    return strict_output
