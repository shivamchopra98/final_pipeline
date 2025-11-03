"""
EPSS transformation (minimal schema)
"""

import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# ✅ Final strict columns
EPSS_FINAL_COLUMNS = [
    "cve",
    "epss_value",
    "epss_percentile",
]


def _get_field(record: Dict[str, Any], names):
    """Helper to safely fetch a field from multiple key variants."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize EPSS record to the simplified schema:
    {
        "CVE": "CVE-2015-2100",
        "EPSS": 0.02664,
        "Percentile": 0.85246
    }
    -> {"cve": "CVE-2015-2100", "epss_value": 0.02664, "epss_percentile": 0.85246}
    """

    out: Dict[str, Any] = {}

    # --- CVE ---
    cve = _get_field(record, ["cve", "CVE", "cve_id"])
    out["cve"] = str(cve).strip() if cve else None

    # --- EPSS value ---
    epss_val = _get_field(record, ["epss", "EPSS", "score", "epss_value"])
    try:
        out["epss_value"] = float(epss_val)
    except (TypeError, ValueError):
        out["epss_value"] = None

    # --- EPSS percentile ---
    perc_val = _get_field(record, ["percentile", "Percentile", "epss_percentile"])
    try:
        out["epss_percentile"] = float(perc_val)
    except (TypeError, ValueError):
        out["epss_percentile"] = None

    # --- Ensure all keys exist ---
    for col in EPSS_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out


def transform_epss_records(records: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Transform a list of EPSS records dynamically into the minimal schema."""
    results = []
    for rec in records:
        try:
            cleaned = clean_and_rename(rec)
            results.append(cleaned)
        except Exception as e:
            log.error(f"❌ Failed to transform EPSS record: {rec} | Error: {e}")
    return results
