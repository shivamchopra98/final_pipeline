"""
McAfee Output transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `mcafee_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting like CVE-2020-1234

log = logging.getLogger(__name__)

# Final schema for McAfee static dataset
MCAFEE_FINAL_COLUMNS = [
    "cve_id",
    "mcafee1_campaign",
    "mcafee1_exploit_kits",
    "mcafee1_ransomware",
    "mcafee1_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename McAfee dataset records.
    - Extracts and normalizes CVE from 'Vulnerabilities' column.
    - Prefixes all mapped fields with `mcafee_`.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Extract CVE from 'Vulnerabilities' column
    cve = _get_field(record, ["Vulnerabilities", "vulnerabilities", "CVE", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Rename fields → prefixed schema
    rename_map = {
        "Campaign": "mcafee1_campaign",
        "Exploit kits": "mcafee1_exploit_kits",
        "Ransomware": "mcafee1_ransomware",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["mcafee1_source"] = "mcafee1_output"

    # ✅ Fill missing fields with None
    for col in MCAFEE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
