"""
Intruder (static) transformation

Input CSV headers (example):
"S.No","Plugin ID","Base Score","CPE","CVE ID","CVSS2 Vector","Depandency","exclude key",
"Exploit Available","Exploit easy","family","File Name","Port","Published Date","Reference",
"Required key","Service","Type","Updated Date","uploaded_date","Version","Vuln Title"

All mapped fields are prefixed with `intruder_`.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve

log = logging.getLogger(__name__)

INTRUDER_FINAL_COLUMNS = [
    "cve_id",                    # normalized CVE
    "intruder_plugin_id",
    "intruder_base_score",
    "intruder_cpe",
    "intruder_cvss2_vector",
    "intruder_dependency",
    "intruder_exclude_key",
    "intruder_exploit_available",
    "intruder_exploit_easy",
    "intruder_family",
    "intruder_file_name",
    "intruder_port",
    "intruder_published_date",
    "intruder_reference",
    "intruder_required_key",
    "intruder_service",
    "intruder_type",
    "intruder_updated_date",
    "intruder_version",
    "intruder_vuln_title",
    "intruder_source",
]


def _get_field(record: Dict[str, Any], names):
    """Return the first present key from names (exact match), or None."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform one Intruder record (dict from CSV/Dynamo) into canonical shape.
    - Normalizes CVE into cve_id
    - Prefixes all mapped columns with intruder_
    - Fills missing values with None
    """
    out: Dict[str, Any] = {}

    # CVE — accept several candidate field names
    raw_cve = _get_field(record, ["CVE ID", "CVE", "CVE_ID", "cve_id", "cve"])
    out["cve_id"] = normalize_cve(raw_cve) if raw_cve else None

    rename_map = {
        "Plugin ID": "intruder_plugin_id",
        "Base Score": "intruder_base_score",
        "CPE": "intruder_cpe",
        "CVSS2 Vector": "intruder_cvss2_vector",
        "Depandency": "intruder_dependency",
        "Dependency": "intruder_dependency",  # tolerate alternate spelling
        "exclude key": "intruder_exclude_key",
        "Exploit Available": "intruder_exploit_available",
        "Exploit easy": "intruder_exploit_easy",
        "family": "intruder_family",
        "File Name": "intruder_file_name",
        "Port": "intruder_port",
        "Published Date": "intruder_published_date",
        "Reference": "intruder_reference",
        "Required key": "intruder_required_key",
        "Service": "intruder_service",
        "Type": "intruder_type",
        "Updated Date": "intruder_updated_date",
        "Version": "intruder_version",
        "Vuln Title": "intruder_vuln_title",
    }

    for src_name, dst_name in rename_map.items():
        val = _get_field(record, [src_name])
        if val is not None:
            out[dst_name] = val

    # provenance marker
    out["intruder_source"] = "intruder"

    # ensure all final columns exist (set missing to None)
    for col in INTRUDER_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
