"""
Metasploit transformation (strict schema with CVE inclusion)
"""

import logging
from typing import Dict, Any, Optional
from utils.time_utils import iso_now

log = logging.getLogger(__name__)

METASPLOIT_FINAL_COLUMNS = [
    "cve_id",
    "metasploit_module_name",
    "metasploit_ref_name",
    "metasploit_fullname",
    "metasploit_aliases",
    "rank",
    "metasploit_type",
    "metasploit_author",
    "metasploit_description",
    "metasploit_references",
    "metasploit_platform",
    "autofilter_services",
    "rport",
    "metasploit_path",
    "uploaded_date",
]


def _get_field(record: Dict[str, Any], names) -> Optional[Any]:
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    # Include CVE
    cve = _get_field(record, ["CVE", "cve_id", "cveID"])
    out["cve_id"] = cve

    mapping = {
        "name": "metasploit_module_name",
        "ref_name": "metasploit_ref_name",
        "fullname": "metasploit_fullname",
        "aliases": "metasploit_aliases",
        "rank": "metasploit_rank",
        "type": "metasploit_type",
        "author": "metasploit_author",
        "description": "metasploit_description",
        "references": "metasploit_references",
        "platform": "metasploit_platform",
        "autofilter_services": "autofilter_services",
        "rport": "rport",
        "path": "metasploit_path",
    }

    for old, new in mapping.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    out["uploaded_date"] = iso_now()

    for col in METASPLOIT_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
