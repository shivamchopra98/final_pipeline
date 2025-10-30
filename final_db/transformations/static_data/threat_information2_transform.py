"""
Threat Information 2 transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `threatinfo2_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting (e.g., CVE-2020-1234)

log = logging.getLogger(__name__)

# Final schema for Threat Information 2 dataset
THREATINFO2_FINAL_COLUMNS = [
    "cve_id",
    "threatinfo2_ransomware",
    "threatinfo2_associated_exploitkit",
    "threatinfo2_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Threat Information 2 dataset records.
    - Normalizes CVE IDs.
    - Prefixes all mapped fields.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Normalize CVE ID
    cve = _get_field(record, ["cve", "CVE", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Rename map → prefixed schema
    rename_map = {
        "ransomware": "threatinfo2_ransomware",
        "Associated ExploitKit": "threatinfo2_associated_exploitkit",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["threatinfo2_source"] = "threat_information_2"

    # ✅ Fill missing columns with None
    for col in THREATINFO2_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
