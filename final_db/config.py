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
    epss_transform
)

from transformations.static_data import (
    apt_transform,
    aptgroup_transform,
    attackerkb_transform,
    chinese_vuln_transform,
    exploit_output_transform,
    exploitkit_transform,
    ibm_merged_transform,
    intruder_transform,
    packet_output_transform,
    packetalone_transform,
ransomware_data_transform,
top10_ransomware_transform,
threat_information1_transform,
threat_information2_transform,
threat_information3_transform,
threat_information4_transform,
threat_information5_transform,
mcafeeoutput_data1_transform,
mcafeeoutput_data2_transform,
mcafeeoutput_data3_transform,
packetstorm_exploits_transform
)


# Each entry: (table_name, join_key, transform_fn, is_static)
SOURCE_SPECS = [
#     ("infoservices-cybersecurity-cisa-data", "cveID", cisa_transform.clean_and_rename, False),
#     ("infoservices-cybersecurity-vuln-exploitdb-data", "CVE_id", exploitdb_transform.clean_and_rename, False),
#     ("infoservices-cybersecurity-vuln-metasploit-data", "cve_id", metasploit_transform.clean_and_rename, False),
("infoservices-cybersecurity-epss-data", "cve", epss_transform.clean_and_rename, True),

    # ("infoservices-cybersecurity-vuln-static-APTfinal", "CVE_Exploited", apt_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-aptgroup", "CVE_Exploited", aptgroup_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-AttackerKB", "Name", attackerkb_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-chinese-Vulnerabilities", "CVE", chinese_vuln_transform.clean_and_rename,
    #  True),
    # (
    # "infoservices-cybersecurity-vuln-static-exploit-output", "CVE_ID", exploit_output_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-exploits-kits", "cve", exploitkit_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-ibm-merged-data", "CVE", ibm_merged_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-intruder-data", "CVE ID", intruder_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-packet-output", "cve_id", packet_output_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-packetalone-output", "cve_id", packetalone_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-ransomware", "CVE", ransomware_data_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-threat-information1", "CVE", threat_information1_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-threat-information2", "cve", threat_information2_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-threat-information3", "Vulnerabilities", threat_information3_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-threat-information4", "CVE",threat_information4_transform.clean_and_rename, True),
    # ("infoservices-cybersecurity-vuln-static-threat-information5", "CVE", threat_information5_transform.clean_and_rename, True),
# ("infoservices-cybersecurity-vuln-static-mcafeeoutput-data1", "Vulnerabilities", mcafeeoutput_data1_transform.clean_and_rename, True),
# ("infoservices-cybersecurity-vuln-static-mcafeeoutput-data2", "Vulnerabilities", mcafeeoutput_data2_transform.clean_and_rename, True),
# ("infoservices-cybersecurity-vuln-static-mcafeeoutput-data3", "Vulnerabilities", mcafeeoutput_data3_transform.clean_and_rename, True),
# ("infoservices-cybersecurity-vuln-static-Packetstorm-Exploits", "CVE", packetstorm_exploits_transform.clean_and_rename, True),


]


