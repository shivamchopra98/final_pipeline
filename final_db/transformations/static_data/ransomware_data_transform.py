"""
Ransomware transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `ransomware_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting (e.g., CVE-2020-1234)

log = logging.getLogger(__name__)

# Final schema columns for Ransomware dataset
RANSOMWARE_FINAL_COLUMNS = [
    "cve_id",
    "ransomware_name",
    "ransomware_data_source",  # provenance marker (always "ransomware")
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Ransomware dataset records.
    - Normalizes CVE ID using normalize_cve()
    - Prefixes all mapped fields to avoid collisions
    - Fills missing fields with None (→ DynamoDB NULL)
    """
    out: Dict[str, Any] = {}

    # ✅ Normalize CVE ID
    cve = _get_field(record, ["CVE", "cve", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Map → prefixed schema
    rename_map = {
        "Ransomware": "ransomware_data_name",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["ransomware_data_source"] = "ransomware"

    # ✅ Fill missing fields with None (DynamoDB stores as NULL)
    for col in RANSOMWARE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
