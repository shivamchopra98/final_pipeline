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

# Source tables with mapping to transformation functions
from transformations import (
    cisa_transform,
    exploitdb_transform,
    metasploit_transform,
)

SOURCE_SPECS = [
    ("infoservices-cybersecurity-cisa-data", "cveID", cisa_transform.clean_and_rename),
    ("infoservices-cybersecurity-vuln-exploitdb-data", "CVE_id", exploitdb_transform.clean_and_rename),
    ("infoservices-cybersecurity-vuln-metasploit-data", "cve_id", metasploit_transform.clean_and_rename),
]
