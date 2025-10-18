"""
CISA transformation (strict schema with CVE inclusion)
"""

import logging
from typing import Dict, Any
from utils.time_utils import iso_now

log = logging.getLogger(__name__)

CISA_FINAL_COLUMNS = [
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "short_description",
    "required_action",
    "cisa_dueDate",
    "known_ransomware_use",
    "notes",
    "cwes",
    "uploaded_date",
]


def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    # Always include CVE
    cve = _get_field(record, ["cveID", "cve_id", "CVE"])
    out["cve_id"] = cve

    rename_map = {
        "vendorProject": "vendor_project",
        "product": "product",
        "vulnerabilityName": "vulnerability_name",
        "shortDescription": "short_description",
        "requiredAction": "required_action",
        "dueDate": "cisa_dueDate",
        "knownRansomwareCampaignUse": "known_ransomware_use",
        "notes": "notes",
        "cwes": "cwes",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    out["uploaded_date"] = iso_now()

    # fill missing fields with None
    for col in CISA_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
