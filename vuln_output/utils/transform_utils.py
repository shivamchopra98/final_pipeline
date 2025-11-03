import pandas as pd

def prepare_output_dataframe(df: pd.DataFrame, vrr_func, id_func) -> pd.DataFrame:
    """
    Build the basic output DF with required columns (from input).
    Keep columns exactly as you specified, plus placeholders for enrichment.
    """
    # Ensure necessary input cols exist
    for col in ["Plugin ID", "CVE", "CVSS", "Risk", "Host", "Protocol", "Port",
                "Name", "Synopsis", "Description", "Solution", "See Also", "Plugin Output"]:
        if col not in df.columns:
            df[col] = ""

    out = pd.DataFrame()
    out["Host Findings ID"] = df.apply(lambda r: id_func(str(r.get("Host","")), str(r.get("Plugin ID",""))), axis=1)
    out["VRR Score"] = [vrr_func() for _ in range(len(df))]
    out["Scanner Name"] = "Nessus"
    out["Scanner plugin ID"] = df["Plugin ID"]
    out["Vulnerability name"] = df["Name"]
    out["Scanner Reported Severity"] = df["Risk"]
    out["Scanner Severity"] = df["CVSS"]
    out["Description"] = df["Synopsis"].fillna("") + " " + df["Description"].fillna("")
    out["Status"] = "Open"  # as requested (from input you can override if needed)
    out["Port"] = df["Port"]
    out["Protocol"] = df["Protocol"]
    out["Plugin Output"] = df["Plugin Output"]
    out["Possible Solutions"] = df["Solution"]
    out["Possible patches"] = df["See Also"]
    out["IPAddress"] = df["Host"]

    # Placeholders for enrichment
    out["Vulnerabilities"] = ""  # will fill with list of CVEs (non-null)
    out["Weaknesses"] = ""       # list of unique CWE ids
    out["Threat"] = ""           # aggregated threat info

    return out
