"""
Top10 Ransomware transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `top10ransomware_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ Ensures consistent CVE formatting (e.g., CVE-2020-1234)

log = logging.getLogger(__name__)

# Final schema for Top10 Ransomware dataset
TOP10RANSOMWARE_FINAL_COLUMNS = [
    "cve_id",
    "top10ransomware_associated_ransomware",
    "top10ransomware_associated_threat_groups",
    "top10ransomware_attack_date",
    "top10ransomware_attack_methods",
    "top10ransomware_cvssv2_score",
    "top10ransomware_cvssv2_vector",
    "top10ransomware_cvssv3_score",
    "top10ransomware_cvssv3_vector",
    "top10ransomware_cwe",
    "top10ransomware_description",
    "top10ransomware_encryption",
    "top10ransomware_exploit_kit",
    "top10ransomware_file_extension",
    "top10ransomware_industry_targeted",
    "top10ransomware_iocs",
    "top10ransomware_originated_year",
    "top10ransomware_other_names",
    "top10ransomware_product",
    "top10ransomware_ransom_demand",
    "top10ransomware_ransomware",
    "top10ransomware_recent_attack",
    "top10ransomware_recommendation",
    "top10ransomware_references",
    "top10ransomware_targeted_countries",
    "top10ransomware_vendor",
    "top10ransomware_vulnerabilities",
    "top10ransomware_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Top10 Ransomware dataset records.
    - Normalizes CVE IDs.
    - Prefixes all mapped fields to prevent name collisions.
    - Fills missing values with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # ✅ Normalize CVE
    cve = _get_field(record, ["CVE", "cve", "cve_id"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # ✅ Rename map → prefixed schema
    rename_map = {
        "Associated Ransomware": "top10ransomware_associated_ransomware",
        "Associated threat groups": "top10ransomware_associated_threat_groups",
        "Attack date": "top10ransomware_attack_date",
        "Attack methods": "top10ransomware_attack_methods",
        "CVSSV2 Score": "top10ransomware_cvssv2_score",
        "CVSSV2 Vector": "top10ransomware_cvssv2_vector",
        "CVSSV3 score": "top10ransomware_cvssv3_score",
        "CVSSV3 vector": "top10ransomware_cvssv3_vector",
        "CWE": "top10ransomware_cwe",
        "Description": "top10ransomware_description",
        "Encryption": "top10ransomware_encryption",
        "Exploit kit": "top10ransomware_exploit_kit",
        "File extension": "top10ransomware_file_extension",
        "Industry Targeted": "top10ransomware_industry_targeted",
        "IOCs": "top10ransomware_iocs",
        "Originated year": "top10ransomware_originated_year",
        "Other Names": "top10ransomware_other_names",
        "Product": "top10ransomware_product",
        "Ransome Demand": "top10ransomware_ransom_demand",
        "Ransomware": "top10ransomware_ransomware",
        "Recent Attack": "top10ransomware_recent_attack",
        "Recommendation": "top10ransomware_recommendation",
        "References": "top10ransomware_references",
        "Targeted Countries": "top10ransomware_targeted_countries",
        "Vendor": "top10ransomware_vendor",
        "Vulnerabilities": "top10ransomware_vulnerabilities",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # ✅ Add provenance marker
    out["top10ransomware_source"] = "top10_ransomware"

    # ✅ Fill missing fields
    for col in TOP10RANSOMWARE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
