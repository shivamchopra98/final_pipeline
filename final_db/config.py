# config.py
import re

# AWS Region
REGION = "us-east-1"

# DynamoDB Tables
NVD_TABLE = "infoservices-cybersecurity-vuln-nvd-data"
FINAL_TABLE = "infoservices-cybersecurity-vuln-final-data"
METADATA_TABLE = "infoservices-cybersecurity-vuln-sync-metadata"

# Regex for validating CVE IDs (e.g., CVE-2022-30190)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# ==========================================================
# Source Tables → Transformation Mapping
# ==========================================================
from transformations import (
    cisa_transform,
    exploitdb_transform,
    metasploit_transform,
)

from transformations.static_data import (
    apt_transform,
    aptgroup_transform,
    attackerkb_transform,
    chinese_vuln_transform,
    exploit_output_transform,  # ✅ add this
)


# Each entry: (table_name, join_key, transform_fn, is_static)
SOURCE_SPECS = [
    # ("infoservices-cybersecurity-cisa-data", "cveID", cisa_transform.clean_and_rename, False),
    # ("infoservices-cybersecurity-vuln-exploitdb-data", "CVE_id", exploitdb_transform.clean_and_rename, False),
    # ("infoservices-cybersecurity-vuln-metasploit-data", "cve_id", metasploit_transform.clean_and_rename, False),
    ("infoservices-cybersecurity-vuln-static-APTfinal", "CVE_Exploited", apt_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-aptgroup", "CVE_Exploited", aptgroup_transform.clean_and_rename, True),# ✅ static source
    # ("infoservices-cybersecurity-vuln-static-AttackerKB", "Name", attackerkb_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-chinese-Vulnerabilities", "CVE", chinese_vuln_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-exploit-output", "CVE_ID", exploit_output_transform.clean_and_rename, True),

]
