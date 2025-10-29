"""
APT transformation (static dataset — no uploaded_date)
Prefixed all mapped columns with 'apt_' to avoid field conflicts in final table.
"""

import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# Final schema (no uploaded_date)
APT_FINAL_COLUMNS = [
    "cve_id",
    "apt_group",
    "apt_name",
    "apt_associated_groups",
    "apt_associated_malware",
    "apt_attacker_motivation",
    "apt_countries_targeted",
    "apt_cwe",
    "apt_description",
    "apt_industry_targeted",
    "apt_malwares_used",
    "apt_mitre_tactics",
    "apt_mitregroup_id",
    "apt_mitresoftware_id",
    "apt_mitretechnique_id",
    "apt_mitretechnique_name",
    "apt_exploit_type",
    "apt_exploit_kit_used",
    "apt_exploit_links",
    "apt_nexpose",
    "apt_qualys",
    "apt_tenable",
    "apt_ransomware_used",
    "apt_software_used",
    "apt_weapon_of_choice",
    "apt_operating_since",
    "apt_origin_country",
    "apt_protocol_used",
    "apt_analysis_urls",
    "apt_reference_links",
    "apt_year",
    "apt_sponsor",
    "apt_email",
    "apt_acunetix",

]


def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename APT dataset records to match strict schema with apt_ prefix.
    """
    out: Dict[str, Any] = {}

    # Always include CVE
    cve = _get_field(record, ["CVE", "CVE_Exploited", "cve_id", "cveID"])
    out["cve_id"] = cve

    # Prefixed rename map
    rename_map = {
        "APT_Group": "apt_group",
        "APT_Name": "apt_name",
        "Accociated_Groups": "apt_associated_groups",
        "Associated_malware": "apt_associated_malware",
        "Attacker_Motivation": "apt_attacker_motivation",
        "Countries_Targeted": "apt_countries_targeted",
        "CWE": "apt_cwe",
        "Description": "apt_description",
        "Industry_targeted": "apt_industry_targeted",
        "Malwares_Used": "apt_malwares_used",
        "Mitre_Tactics": "apt_mitre_tactics",
        "MitreGroup-ID": "apt_mitregroup_id",
        "MitreSoftware-ID": "apt_mitresoftware_id",
        "MitreTechnique-ID": "apt_mitretechnique_id",
        "MitreTechnique-ID_Name": "apt_mitretechnique_name",
        "Exploit_(RCE/PE/DOS/WEBAPP)": "apt_exploit_type",
        "Exploit_Kit_Used": "apt_exploit_kit_used",
        "Exploit_Links": "apt_exploit_links",
        "Nexpose": "apt_nexpose",
        "Qualys": "apt_qualys",
        "Tenable": "apt_tenable",
        "Ransomware_Used": "apt_ransomware_used",
        "Software_Used": "apt_software_used",
        "Weapon_of_Choice/Attack_Methods": "apt_weapon_of_choice",
        "Operating_Since": "apt_operating_since",
        "Origin _Country": "apt_origin_country",
        "Protocol_Used_(C&C,_Exfiltration)": "apt_protocol_used",
        "Analysis_URLs": "apt_analysis_urls",
        "Reference_Links": "apt_reference_links",
        "Year": "apt_year",
        "Sponsor": "apt_sponsor",
        "Email": "apt_email",
        "Acunetix": "apt_acunetix",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # Fill missing columns with None
    for col in APT_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
