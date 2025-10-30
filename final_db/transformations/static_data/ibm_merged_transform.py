import logging
import copy
from typing import Dict, Any, List
from utils.cve_utils import extract_cves, normalize_cve

log = logging.getLogger(__name__)

IBM_FINAL_COLUMNS = [
    "cve_id",
    "ibm_affected_products",
    "ibm_attack_complexity",
    "ibm_attack_vector",
    "ibm_authentication",
    "ibm_availability_impact",
    "ibm_collection_links",
    "ibm_collections",
    "ibm_confidentiality_impact",
    "ibm_consequences",
    "ibm_cvss1_base_score",
    "ibm_cvss1_temporal_score",
    "ibm_cvss2_base_score",
    "ibm_cvss2_temporal_score",
    "ibm_cvss3_base_score",
    "ibm_cvss3_temporal_score",
    "ibm_dependent_products",
    "ibm_details",
    "ibm_exploitability",
    "ibm_ibm_network_protection",
    "ibm_integrity_impact",
    "ibm_privileges_required",
    "ibm_ref_link",
    "ibm_references",
    "ibm_remediation_level",
    "ibm_remedy",
    "ibm_report_confidence",
    "ibm_scope",
    "ibm_sourcesheet",
    "ibm_user_interaction",
    "ibm_vuln_name",
    "ibm_vuln_id_link",
    "ibm_source",
]


def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Transform IBM merged record(s) into the canonical schema.
    - Handles multiple CVEs in a single field (explodes into multiple rows)
    - Normalizes CVEs using extract_cves()
    - Prefixes mapped fields
    - Fills missing values with None
    - Does not propagate uploaded_date
    """
    out_list: List[Dict[str, Any]] = []

    # ✅ extract all possible CVEs
    raw_cve = _get_field(
        record,
        ["CVE", "CVE_ID", "cve", "cve_id", "vuln_ID_link", "vuln_id_link", "Vuln_ID_Link"],
    )
    cve_list = extract_cves(raw_cve)

    # fallback if no valid CVE found
    if not cve_list:
        cve_list = [None]

    rename_map = {
        "Affected_Products": "ibm_affected_products",
        "Attack_Complexity": "ibm_attack_complexity",
        "Attack_Vector": "ibm_attack_vector",
        "Authentication": "ibm_authentication",
        "Availability_Impact": "ibm_availability_impact",
        "Collection_Links": "ibm_collection_links",
        "Collections": "ibm_collections",
        "Confidentiality_Impact": "ibm_confidentiality_impact",
        "Consequences": "ibm_consequences",
        "Cvss_1_Base_score": "ibm_cvss1_base_score",
        "Cvss_1_Temporal_Score": "ibm_cvss1_temporal_score",
        "Cvss_2_Base_score": "ibm_cvss2_base_score",
        "Cvss_2_Temporal_Score": "ibm_cvss2_temporal_score",
        "Cvss_3_Base_score": "ibm_cvss3_base_score",
        "Cvss_3_Temporal_Score": "ibm_cvss3_temporal_score",
        "Dependent_Products": "ibm_dependent_products",
        "Details": "ibm_details",
        "Exploitability": "ibm_exploitability",
        "IBM_Network_Ptotection": "ibm_ibm_network_protection",
        "IBM_Network_Protection": "ibm_ibm_network_protection",
        "Integrity_Impact": "ibm_integrity_impact",
        "Privileges_Required": "ibm_privileges_required",
        "Ref_Link": "ibm_ref_link",
        "References": "ibm_references",
        "Remediation_Level": "ibm_remediation_level",
        "Remedy": "ibm_remedy",
        "Report_Confidence": "ibm_report_confidence",
        "Scope": "ibm_scope",
        "SourceSheet": "ibm_sourcesheet",
        "User_Interaction": "ibm_user_interaction",
        "Vul_Name": "ibm_vuln_name",
        "vuln_ID_link": "ibm_vuln_id_link",
    }

    # ✅ map static fields once
    base = {}
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            base[new] = val
        else:
            base[new] = None

    base["ibm_source"] = "ibm_merged"

    # ✅ explode by CVE
    for cve in cve_list:
        new_rec = dict(base)
        new_rec["cve_id"] = normalize_cve(cve) if cve else None
        for col in IBM_FINAL_COLUMNS:
            new_rec.setdefault(col, None)
        out_list.append(new_rec)

    return out_list
