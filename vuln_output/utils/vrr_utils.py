# utils/vrr_utils.py

def safe_float(v):
    try:
        return float(v)
    except:
        return 0


def calculate_vrr_score(dynamo_row):
    """
    Calculate VRR score based ONLY on DynamoDB enriched CVE record.
    We print it first before sending into output.
    """

    print("\n========== VRR DEBUG ==========")
    print(dynamo_row)
    print("================================\n")

    score = 0

    # -----------------------------
    # YES/NO fields
    # -----------------------------
    yes_fields_30 = ["cisa_key"]
    yes_fields_20 = [
        "cisa_known_ransomware", "ransomware_name",
        "threatinfo5_ransomware", "top10ransomware_associated_ransomware",
        "mcafee3_ransomware"
    ]
    yes_fields_15 = [
        "threatinfo5_family", "threatinfo5_apt_group", "threatinfo5_exploit_kit",
        "top10ransomware_associated_threat_groups",
        "top10ransomware_exploit_kit",
        "mcafee3_exploit_kits"
    ]
    yes_fields_10 = ["exploit_db", "metasploit", "threatinfo5_exploit_type"]

    # 30-point flags
    for f in yes_fields_30:
        if str(dynamo_row.get(f, "")).lower() == "yes":
            score += 30

    # 20-point flags
    for f in yes_fields_20:
        if str(dynamo_row.get(f, "")).lower() == "yes":
            score += 20

    # 15-point flags
    for f in yes_fields_15:
        if str(dynamo_row.get(f, "")).lower() == "yes":
            score += 15

    # 10-point flags
    for f in yes_fields_10:
        if str(dynamo_row.get(f, "")).lower() == "yes":
            score += 10

    # -----------------------------
    # Numeric scaling
    # -----------------------------
    score += safe_float(dynamo_row.get("epss_value", 0)) * 10
    score += safe_float(dynamo_row.get("cvss3_base_score", 0)) / 2
    score += safe_float(dynamo_row.get("attackerkb_exploitability_score", 0))
    score += safe_float(dynamo_row.get("attackerkb_score", 0)) / 2
    score += safe_float(dynamo_row.get("attackerkb_impact_score", 0)) / 2
    score += safe_float(dynamo_row.get("ibm_cvss3_base_score", 0)) / 2
    score += safe_float(dynamo_row.get("packet_cv3_basescore", 0)) / 2

    # Exploit links
    if dynamo_row.get("packet_exploit_links"):
        score += 2.5

    if dynamo_row.get("packetalone_exploit_links"):
        score += 2.5

    final_score = round(score, 2)

    print(f"➡️ FINAL VRR SCORE: {final_score}\n")

    return final_score
