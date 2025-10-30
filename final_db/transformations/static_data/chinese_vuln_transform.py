"""
Chinese Vulnerabilities transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `chinese1_` to avoid name collisions.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ for consistent CVE format (CVE-YYYY-NNNN)

log = logging.getLogger(__name__)

# Final strict schema for the Chinese Vulnerabilities dataset
CHINESE_FINAL_COLUMNS = [
    "cve_id",
    "chinese_vuln_apt_attack_method",
    "chinese_vuln_apt_groups",
    "chinese_vuln_apt_software_used",
    "chinese_vuln_cvssv2_score",
    "chinese_vuln_cvssv2_vector",
    "chinese_vuln_cvssv3_score",
    "chinese_vuln_cvssv3_vector",
    "chinese_vuln_cwe_id",
    "chinese_vuln_exploit_kit",
    "chinese_vuln_exploit_links",
    "chinese_vuln_exploit_type",
    "chinese_vuln_exploit_available",
    "chinese_vuln_malware",
    "chinese_vuln_metasploit",
    "chinese_vuln_nexpose_id",
    "chinese_vuln_product",
    "chinese_vuln_qualys_plugin_id",
    "chinese_vuln_ransomware",
    "chinese_vuln_script",
    "chinese_vuln_target_industries",
    "chinese_vuln_target_countries",
    "chinese_vuln_tenable_plugin_id",
    "chinese_vuln_vendor",
    "chinese_vuln_version",
    "chinese_vuln_source"
]


def _get_field(record: Dict[str, Any], names):
    """Return first present key from names (case-sensitive as stored in CSV → DynamoDB)."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename the Chinese Vulnerabilities dataset record.
    - Always include normalized CVE
    - Prefix mapped columns with chinese_vuln_
    - Fill missing fields with None (→ DynamoDB NULL)
    """
    out: Dict[str, Any] = {}

    # Always include normalized CVE
    cve = _get_field(record, ["CVE", "cve_id", "Name"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    rename_map = {
        "APT Attack method": "chinese_vuln_apt_attack_method",
        "APT Groups": "chinese_vuln_apt_groups",
        "APT software used": "chinese_vuln_apt_software_used",
        "CVSSV2 Score": "chinese_vuln_cvssv2_score",
        "CVSSV2 Vector": "chinese_vuln_cvssv2_vector",
        "CVSSV3 Score": "chinese_vuln_cvssv3_score",
        "CVSSV3 Vector": "chinese_vuln_cvssv3_vector",
        "CWE id": "chinese_vuln_cwe_id",
        "Exploit Kit": "chinese_vuln_exploit_kit",
        "Exploit Links": "chinese_vuln_exploit_links",
        "Exploit Type": "chinese_vuln_exploit_type",
        "Exploit(Y/N)": "chinese_vuln_exploit_available",
        "Malware": "chinese_vuln_malware",
        "Metasploit": "chinese_vuln_metasploit",
        "Nexpose id": "chinese_vuln_nexpose_id",
        "Product": "chinese_vuln_product",
        "Qualys Plugin-ID": "chinese_vuln_qualys_plugin_id",
        "Ransomware": "chinese_vuln_ransomware",
        "Script": "chinese_vuln_script",
        "Target industries": "chinese_vuln_target_industries",
        "TargetCountries": "chinese_vuln_target_countries",
        "Tenable Plugin-ID": "chinese_vuln_tenable_plugin_id",
        "Vendor": "chinese_vuln_vendor",
        "version": "chinese_vuln_version",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # Add source marker
    out["chinese_vuln_source"] = "chinese-vulnerabilities"

    # Fill missing columns with None (DynamoDB NULL)
    for col in CHINESE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
