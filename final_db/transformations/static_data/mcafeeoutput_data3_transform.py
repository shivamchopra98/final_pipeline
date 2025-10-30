"""
McAfee Output Data 3 transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `mcafee3_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting like CVE-2020-1234

log = logging.getLogger(__name__)

# Final schema for McAfee static dataset (Data3)
MCAFEE3_FINAL_COLUMNS = [
    "cve_id",
    "mcafee3_exploit_kits",
    "mcafee3_ransomware",
    "mcafee3_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename McAfee Output Data 3 records.
    - Normalizes CVE IDs from 'CVE' column.
    - Prefixes all mapped fields with `mcafee3_`.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Normalize CVE ID
    cve = _get_field(record, ["CVE", "cve", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Rename map → prefixed schema
    rename_map = {
        "Exploit kits": "mcafee3_exploit_kits",
        "Ransomware": "mcafee3_ransomware",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["mcafee3_source"] = "mcafee_output_data3"

    # ✅ Fill missing columns with None
    for col in MCAFEE3_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
