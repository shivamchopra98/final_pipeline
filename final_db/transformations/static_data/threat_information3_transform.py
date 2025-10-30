"""
Threat Information 3 transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `threatinfo3_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting like CVE-2020-1234

log = logging.getLogger(__name__)

# Final schema for Threat Information 3 dataset
THREATINFO3_FINAL_COLUMNS = [
    "cve_id",
    "threatinfo3_ransomware",
    "threatinfo3_associated_exploit_kits",
    "threatinfo3_campaign",
    "threatinfo3_description",
    "threatinfo3_exploit_kits",
    "threatinfo3_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Threat Information 3 dataset records.
    - Normalizes CVE IDs.
    - Prefixes all mapped fields.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Normalize CVE ID
    cve = _get_field(record, ["Vulnerabilities", "CVE", "cve", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Map → prefixed schema
    rename_map = {
        "Ransomware": "threatinfo3_ransomware",
        "Associated Exploit kits": "threatinfo3_associated_exploit_kits",
        "Campaign": "threatinfo3_campaign",
        "Description": "threatinfo3_description",
        "Exploit kits": "threatinfo3_exploit_kits",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["threatinfo3_source"] = "threat_information_3"

    # ✅ Fill missing columns with None
    for col in THREATINFO3_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
