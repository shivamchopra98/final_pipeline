"""
APT Group transformation (static dataset)
"""

import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# Final strict schema for APT group
APTGROUP_FINAL_COLUMNS = [
    "cve_id",
    "aptgroup_name",
]

def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record:
            return record[n]
    return None

def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename APT Group dataset records to match strict schema.
    """
    out: Dict[str, Any] = {}

    # Always include CVE ID
    cve = _get_field(record, ["CVE", "CVE_ID", "cve_id", "cve_exploited"])
    out["cve_id"] = cve

    rename_map = {
        "apt_group": "aptgroup_name",    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # Fill missing columns with None (DynamoDB stores as NULL)
    for col in APTGROUP_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
