import pandas as pd
from typing import Callable, Optional

# Mapping: scanner name → unified-field → source column name
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
    """Detect scanner type by matching most column names."""
    cols_lower = {c.lower() for c in df.columns}
    best_match = None
    best_score = 0

    for scanner, mapping in SCANNER_COLUMN_MAP.items():
        # Count how many of the expected columns exist
        score = sum(1 for src_col in mapping.values() if src_col and src_col.lower() in cols_lower)
        if score > best_score:
            best_match = scanner
            best_score = score

    return best_match or "Unknown Scanner"


def prepare_output_dataframe(
    df: pd.DataFrame,
    vrr_func: Callable[[], float],
    id_func: Callable[[str, str], str]
) -> pd.DataFrame:
    """
    Build the unified output DataFrame for any scanner format.
    """
    scanner = detect_scanner(df)
    mapping = SCANNER_COLUMN_MAP.get(scanner, {})

    def pick_col(*candidates):
        for c in candidates:
            if c and c in df.columns:
                return df[c]
        # fallback to a series of empty strings
        return pd.Series([""] * len(df), index=df.index)

    out = pd.DataFrame(index=df.index)
    out["Host Findings ID"] = df.apply(
        lambda r: id_func(
            str(r.get(mapping.get("IPAddress", "Host"), "")),
            str(r.get(mapping.get("Scanner plugin ID", "Plugin ID"), ""))
        ),
        axis=1
    )
    out["VRR Score"] = [vrr_func() for _ in range(len(df))]
    out["Scanner Name"] = scanner
    out["Scanner plugin ID"] = pick_col(mapping.get("Scanner plugin ID", ""), "Plugin ID")
    out["Vulnerability name"] = pick_col(mapping.get("Vulnerability name", ""), "Name")
    out["Scanner Reported Severity"] = pick_col(mapping.get("Scanner Reported Severity", ""), "Risk")
    out["Scanner Severity"] = pick_col(mapping.get("Scanner Severity", ""), "CVSS")
    # Description may need to combine two fields if analogous to your original "Synopsis + Description"
    out["Description"] = (
        pick_col(mapping.get("Description", ""), "Description")
        .fillna("") + " " +
        pick_col("Synopsis", "Summary / Description").fillna("")
    ).str.strip()
    out["Status"] = pick_col(mapping.get("Status", ""), "Status").replace("", "Open")
    out["Port"] = pick_col(mapping.get("Port", ""), "Port")
    out["Protocol"] = pick_col(mapping.get("Protocol", ""), "Protocol")
    out["Plugin Output"] = pick_col(mapping.get("Plugin Output", ""), "Plugin Output")
    out["Possible Solutions"] = pick_col(mapping.get("Possible Solutions", ""), "Solution")
    out["Possible patches"] = pick_col(mapping.get("Possible patches", ""), "See Also")
    out["IPAddress"] = pick_col(mapping.get("IPAddress", ""), "Host")

    # Enrichment placeholders
    out["Vulnerabilities"] = ""
    out["Weaknesses"] = ""
    out["Threat"] = ""

    print(f"Detected scanner format: {scanner}")
    return out
