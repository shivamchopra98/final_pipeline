"""
EPSS transformation (strict schema with CVE inclusion)
"""

import logging
from typing import Dict, Any
from utils.time_utils import iso_now
from decimal import Decimal

log = logging.getLogger(__name__)

EPSS_FINAL_COLUMNS = [
    "cve_id",
    "epss_value",
    "epss_percentile",
    "uploaded_date",
]


def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    # --- CVE ---
    cve = _get_field(record, ["cve", "CVE", "cve_id"])
    out["cve_id"] = str(cve).strip() if cve else None

    # --- EPSS score ---
    epss_val = _get_field(record, ["epss", "EPSS", "score", "epss_value"])
    try:
        epss_val = float(epss_val)
    except Exception:
        epss_val = None
    out["epss_value"] = Decimal(str(epss_val)) if epss_val is not None else None

    # --- Percentile ---
    perc_val = _get_field(record, ["percentile", "Percentile", "epss_percentile"])
    try:
        perc_val = float(perc_val)
    except Exception:
        perc_val = None
    out["epss_percentile"] = Decimal(str(perc_val)) if perc_val is not None else None

    # Add uploaded date
    out["uploaded_date"] = iso_now()

    # Ensure all keys exist
    for col in EPSS_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
