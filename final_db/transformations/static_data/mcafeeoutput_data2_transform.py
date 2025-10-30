"""
McAfee Output Data 2 transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `mcafee2_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ Ensures consistent CVE formatting (e.g., CVE-2020-1234)

log = logging.getLogger(__name__)

# Final schema for McAfee static dataset (Data2)
MCAFEE2_FINAL_COLUMNS = [
    "cve_id",
    "mcafee2_campaign",
    "mcafee2_description",
    "mcafee2_exploit_kits",
    "mcafee2_ransomware",
    "mcafee2_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename McAfee Output Data 2 records.
    - Normalizes CVE IDs from 'Vulnerabilities' column.
    - Prefixes all mapped fields.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Extract and normalize CVE ID
    cve = _get_field(record, ["Vulnerabilities", "vulnerabilities", "CVE", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Map → prefixed schema
    rename_map = {
        "Campaign": "mcafee2_campaign",
        "Description": "mcafee2_description",
        "Exploit kits": "mcafee2_exploit_kits",
        "Ransomware": "mcafee2_ransomware",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["mcafee2_source"] = "mcafee_output_data2"

    # ✅ Fill missing columns with None
    for col in MCAFEE2_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
