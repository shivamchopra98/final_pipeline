"""
IBM merged vulnerabilities transformation (static dataset)

All mapped fields are prefixed with `ibm_` to avoid collisions in the final table.
This is a static dataset: uploaded_date is NOT propagated.
Missing values are set to None (DynamoDB NULL).
"""

import logging
from typing import Dict, Any

from utils.cve_utils import normalize_cve  # make sure this exists in your repo

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
    "ibm_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return first present key from names (case-sensitive as stored in CSV → Dynamo item)."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform one IBM merged record into the canonical schema for the final table.
    - Always include normalized cve_id (tries 'CVE', 'CVE_ID', 'vuln_ID_link' as fallback)
    - Prefixes mapped columns with ibm_
    - Defaults missing values to None (→ DynamoDB NULL)
    - Does NOT propagate uploaded_date (static dataset)
    """
    out: Dict[str, Any] = {}

    # CVE may be present under different headers; prefer explicit CVE field,
    # then try vuln_ID_link or 'CVE' alternatives.
    raw_cve = _get_field(record, ["CVE", "CVE_ID", "cve", "cve_id", "vuln_ID_link", "vuln_id_link", "Vuln_ID_Link"])
    out["cve_id"] = normalize_cve(raw_cve) if raw_cve else None

    rename_map = {
        "Affected_Products": "ibm_affected_products",
        "Attack_Complexity": "ibm_attack_complexity",
        "Attack_Vector": "ibm_attack_vector",
        "Attack Vector": "ibm_attack_vector",
        "Authentication": "ibm_authentication",
        "Availability_Impact": "ibm_availability_impact",
        "Availability Impact": "ibm_availability_impact",
        "Collection_Links": "ibm_collection_links",
        "Collections": "ibm_collections",
        "Confidentiality_Impact": "ibm_confidentiality_impact",
        "Confidentiality Impact": "ibm_confidentiality_impact",
        "Consequences": "ibm_consequences",
        "Cvss_1_Base_score": "ibm_cvss1_base_score",
        "Cvss_1_Temporal_Score": "ibm_cvss1_temporal_score",
        "Cvss_2_Base_score": "ibm_cvss2_base_score",
        "Cvss_2_Temporal_Score": "ibm_cvss2_temporal_score",
        "Cvss_3_Base_score": "ibm_cvss3_base_score",
        "Cvss_3_Temporal_Score": "ibm_cvss3_temporal_score",
        "Dependent_Products": "ibm_dependent_products",
        "Dependent Products": "ibm_dependent_products",
        "Details": "ibm_details",
        "Exploitability": "ibm_exploitability",
        "IBM_Network_Ptotection": "ibm_ibm_network_protection",
        "IBM_Network_Protection": "ibm_ibm_network_protection",
        "Integrity_Impact": "ibm_integrity_impact",
        "Privileges_Required": "ibm_privileges_required",
        "Privileges Required": "ibm_privileges_required",
        "Ref_Link": "ibm_ref_link",
        "Ref Link": "ibm_ref_link",
        "References": "ibm_references",
        "Remediation_Level": "ibm_remediation_level",
        "Remedy": "ibm_remedy",
        "Report_Confidence": "ibm_report_confidence",
        "Scope": "ibm_scope",
        "SourceSheet": "ibm_sourcesheet",
        "Source Sheet": "ibm_sourcesheet",
        "User_Interaction": "ibm_user_interaction",
        "User Interaction": "ibm_user_interaction",
        "Vul_Name": "ibm_vuln_name",
        "Vuln Name": "ibm_vuln_name",
        "vuln_ID_link": "ibm_vuln_id_link",
        "vuln_ID_Link": "ibm_vuln_id_link",
        "vuln_id_link": "ibm_vuln_id_link",
        "vuln_ID": "ibm_vuln_id_link",
    }

    # Map fields (skip uploaded_date intentionally — static dataset)
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # Add provenance marker
    out["ibm_source"] = "ibm_merged"

    # Fill missing columns with None (DynamoDB NULL)
    for col in IBM_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
