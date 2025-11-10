# scanner_detector.py
from typing import Dict
import pandas as pd

SCANNER_COLUMN_MAP = {
    "Nessus": {
        "Scanner plugin ID": "Plugin ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Risk",
        "Scanner Severity": "CVSS",
        "Description": "Synopsis / Description",
        "Status": "Open",  # or "Status" if your input has one
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Plugin Output",
        "Possible Solutions": "Solution",
        "Possible patches": "See Also",
        "IPAddress": "Host"
    },
    "HCL AppScan": {
        "Scanner plugin ID": "Issue ID",
        "Vulnerability name": "Issue Type / Title",
        "Scanner Reported Severity": "Severity (raw text)",
        "Scanner Severity": "CVSS Score (if available)",
        "Description": "Description",
        "Status": "Issue Status (Open/Fixed)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Evidence / HTTP request-response",
        "Possible Solutions": "Fix Recommendation",
        "Possible patches": "CVE / Patch Reference (if available)",
        "IPAddress": "Hostname / IP"
    },
    "Acunetix / Invicti": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Vulnerability Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Base",
        "Description": "Description",
        "Status": "Status / Confirmed",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Proof / Payload / Evidence",
        "Possible Solutions": "Recommendation",
        "Possible patches": "CVE → Patch Reference",
        "IPAddress": "Target / Host"
    },
    "OWASP ZAP": {
        "Scanner plugin ID": "Alert ID",
        "Vulnerability name": "Alert Name",
        "Scanner Reported Severity": "Risk",
        "Scanner Severity": "CVSS (if mapped)",
        "Description": "Description",
        "Status": "Status (Confirmed / False Positive)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Evidence",
        "Possible Solutions": "Solution",
        "Possible patches": "N/A",
        "IPAddress": "Host / URL"
    },
    "Netsparker / Invicti": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Vulnerability Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Score",
        "Description": "Description",
        "Status": "Status",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Proof / Payload",
        "Possible Solutions": "Recommendation",
        "Possible patches": "Fix Version / Patch Link",
        "IPAddress": "Target / Host"
    },
    "w3af": {
        "Scanner plugin ID": "Vulnerability ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "N/A",
        "Description": "Description",
        "Status": "Active / Verified",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "HTTP Request/Response",
        "Possible Solutions": "Fix Guidance",
        "Possible patches": "N/A",
        "IPAddress": "Host / URL"
    },
    "OpenVAS / Greenbone (GVM)": {
        "Scanner plugin ID": "NVT OID / Vulnerability ID",
        "Vulnerability name": "Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Score",
        "Description": "Summary / Description",
        "Status": "Threat / QoD / Result",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Detection Output / Details",
        "Possible Solutions": "Solution",
        "Possible patches": "Patch / CVE Ref",
        "IPAddress": "Host"
    },
    "Qualys VMDR": {
        "Scanner plugin ID": "QID",
        "Vulnerability name": "Title",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS Base",
        "Description": "Diagnosis",
        "Status": "Vuln Status (Active, Fixed, Reopened)",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Results",
        "Possible Solutions": "Solution",
        "Possible patches": "Patchable / Fix Version",
        "IPAddress": "Host"
    },
    "Masscan / RustScan": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "N/A",
        "Scanner Reported Severity": "Severity (1-5)",
        "Scanner Severity": "N/A",
        "Description": "Scan Output / Banner",
        "Status": "N/A",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Scan Output / Banner",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Nmap": {
        "Scanner plugin ID": "Script ID / Script Name",
        "Vulnerability name": "Script Title / Service Name",
        "Scanner Reported Severity": "Script risk output",
        "Scanner Severity": "CVSS (if script reports)",
        "Description": "Script Output Summary",
        "Status": "Host Up / Down",
        "Port": "Port",
        "Protocol": "TCP/UDP",
        "Plugin Output": "Script Output",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Angry IP Scanner": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "N/A",
        "Scanner Reported Severity": "N/A",
        "Scanner Severity": "N/A",
        "Description": "N/A",
        "Status": "Alive / Dead",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "N/A",
        "Possible Solutions": "N/A",
        "Possible patches": "N/A",
        "IPAddress": "Host"
    },
    "Nuclei": {
        "Scanner plugin ID": "Template ID",
        "Vulnerability name": "Template Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "CVSS (if tagged in template)",
        "Description": "Description",
        "Status": "Matched / Not matched",
        "Port": "Port",
        "Protocol": "Protocol",
        "Plugin Output": "Matched Data / Extracted Results",
        "Possible Solutions": "N/A",
        "Possible patches": "Fix Version / Patch Tag (if any)",
        "IPAddress": "Target / Host"
    },
    "EyeWitness": {
        "Scanner plugin ID": "N/A",
        "Vulnerability name": "Screenshot / Page Title",
        "Scanner Reported Severity": "N/A",
        "Scanner Severity": "N/A",
        "Description": "Screenshot Context / Page Title",
        "Status": "Captured / Skipped",
        "Port": "Port (if applicable)",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Screenshot / HTML Title",
        "Possible Solutions": "N/A",
        "Possible patches": "Reference (Exploit / Patch link)",
        "IPAddress": "Target / Domain"
    },
    "Sn1per / Recon-ng": {
        "Scanner plugin ID": "Finding ID / Module ID",
        "Vulnerability name": "Finding Title",
        "Scanner Reported Severity": "Severity / Confidence",
        "Scanner Severity": "N/A",
        "Description": "Reference / Patch URL",
        "Status": "Found / Not Found",
        "Port": "Port",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Command Output / Evidence",
        "Possible Solutions": "Recommendation / Next Steps",
        "Possible patches": "Reference / Patch URL",
        "IPAddress": "Target"
    },
    "Burp Suite": {
        "Scanner plugin ID": "Issue Type",
        "Vulnerability name": "Issue Name",
        "Scanner Reported Severity": "Severity",
        "Scanner Severity": "N/A",
        "Description": "Issue Detail",
        "Status": "Issue Status (Certain / Tentative)",
        "Port": "N/A",
        "Protocol": "HTTP/HTTPS",
        "Plugin Output": "Evidence",
        "Possible Solutions": "Remediation Background",
        "Possible patches": "Reference / Patch URL",
        "IPAddress": "Host"
    }
}

def detect_scanner(df: pd.DataFrame) -> str:
    """Detect scanner type based on best column name match."""
    cols_lower = {c.lower() for c in df.columns}
    best_match, best_score = "Unknown Scanner", 0
    for scanner, mapping in SCANNER_COLUMN_MAP.items():
        score = sum(1 for src in mapping.values() if src.lower() in cols_lower)
        if score > best_score:
            best_match, best_score = scanner, score
    return best_match


def build_unified_output(df: pd.DataFrame, scanner: str) -> pd.DataFrame:
    """Normalize scanner output to the unified schema format."""
    mapping = SCANNER_COLUMN_MAP.get(scanner, {})

    def get_col(name: str):
        """Safely get a column if it exists, else return an empty string."""
        if not name:
            return ""
        for col in df.columns:
            if col.strip().lower() == name.strip().lower():
                return df[col]
        return ""

    out = pd.DataFrame()

    # Build unified columns safely
    out["Host Findings ID"] = (
        get_col(mapping.get("IPAddress", "Host")).astype(str).fillna("") +
        get_col(mapping.get("Scanner plugin ID", "Plugin ID")).astype(str).fillna("")
    )
    out["VRR Score"] = 7.5  # placeholder
    out["Scanner Name"] = scanner
    out["Scanner plugin ID"] = get_col(mapping.get("Scanner plugin ID", ""))
    out["Vulnerability name"] = get_col(mapping.get("Vulnerability name", ""))
    out["Scanner Reported Severity"] = get_col(mapping.get("Scanner Reported Severity", ""))
    out["Scanner Severity"] = get_col(mapping.get("Scanner Severity", ""))
    out["Description"] = get_col(mapping.get("Description", ""))
    out["Status"] = get_col(mapping.get("Status", ""))
    out["Port"] = get_col(mapping.get("Port", ""))
    out["Protocol"] = get_col(mapping.get("Protocol", ""))
    out["Plugin Output"] = get_col(mapping.get("Plugin Output", ""))
    out["Possible Solutions"] = get_col(mapping.get("Possible Solutions", ""))
    out["Possible patches"] = get_col(mapping.get("Possible patches", ""))
    out["IPAddress"] = get_col(mapping.get("IPAddress", ""))
    out["Vulnerabilities"] = ""
    out["Weaknesses"] = ""
    out["Threat"] = ""

    return out