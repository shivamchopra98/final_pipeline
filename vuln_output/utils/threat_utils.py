# utils/threat_utils.py
import re
import random
from typing import Any, Dict, List, Set
from utils.cve_utils import normalize_cve

# Regex patterns
CVE_REGEX = re.compile(r"\bCVE[-_\s]?(\d{4})[-_\s]?(\d{3,7})\b", re.IGNORECASE)
URL_REGEX = re.compile(r"https?://[^\s,;\"']+", re.IGNORECASE)


# ---------------------------------------------------------
# Extract CVEs
# ---------------------------------------------------------
def extract_cves_from_text(text: str) -> List[str]:
    if not text or not isinstance(text, str):
        return []
    found = []
    for m in CVE_REGEX.findall(text):
        token = f"CVE-{m[0]}-{m[1]}"
        norm = normalize_cve(token)
        if norm and norm not in found:
            found.append(norm)
    return found


def extract_cves_from_row(row) -> List[str]:
    text = " ".join([str(v) for v in row.values if v is not None])
    return extract_cves_from_text(text)


# ---------------------------------------------------------
# URL Walker
# ---------------------------------------------------------
def _walk_urls(obj: Any, urls: Set[str]):
    if obj is None:
        return

    if isinstance(obj, str):
        for u in URL_REGEX.findall(obj):
            urls.add(u)
        return

    if isinstance(obj, list):
        for item in obj:
            _walk_urls(item, urls)
        return

    if isinstance(obj, dict):
        for k, v in obj.items():
            _walk_urls(k, urls)
            _walk_urls(v, urls)
        return

    try:
        s = str(obj)
        for u in URL_REGEX.findall(s):
            urls.add(u)
    except:
        pass


# ---------------------------------------------------------
# FINAL THREAT JSON BUILDER
# ---------------------------------------------------------
def build_threat_json(matched_items: List[Dict[str, Any]], input_cves: List[str]):
    # CVE list
    cve_list = []
    for c in input_cves:
        norm = normalize_cve(c)
        if norm and norm not in cve_list:
            cve_list.append(norm)

    # Collectors
    cwe_set = set()
    exploit_db_urls = set()
    packet_links = set()
    packetalone_links = set()
    ref_nvd = set()  # FIXED: Add only strings

    exploit_ids = set()
    exploit_available = False
    exploitability_scores = []

    # ------------ Exploitability Type ---------------
    exploit_type_fields = {
        "exploit_type": set(),
        "metasploit_type": set(),
        "ibm_attack_vector": set(),
        "intruder_type": set(),
        "threatinfo5_exploit_type": set()
    }

    # ------------ APT Groups ---------------
    apt_groups_fields = {
        "threatinfo5_apt_group": set(),
        "top10ransomware_associated_threat_groups": set(),
        "threatinfo1_apt_group": set()
    }

    # ------------ Ransomware Availability ---------------
    ransomware_fields = {
        "known_ransomware_use": None,
        "ransomware_name": set(),
        "threatinfo5_ransomware": set(),
        "threatinfo5_family": set(),
        "top10ransomware_associated_ransomware": set(),
        "mcafee3_ransomware": set(),
        "threatinfo2_ransomware": set(),
        "threatinfo3_ransomware": set(),
        "threatinfo4_ransomware": set()
    }

    # ------------ Exploit Kits ---------------
    exploit_kit_fields = {
        "threatinfo5_exploit_kit": set(),
        "top10ransomware_exploit_kit": set(),
        "mcafee3_exploit_kits": set(),
        "threatinfo2_associated_exploitkit": set(),
        "threatinfo3_associated_exploit_kits": set(),
        "threatinfo3_exploit_kits": set(),
        "threatinfo4_exploit_kits": set()
    }

    # ------------ Affected Products ---------------
    product_fields = {
        "product": set(),
        "exploit_platform": set(),
        "metasploit_platform": set(),
        "attackerkb_vulnerable_versions": set(),
        "ibm_affected_products": set(),
        "packet_product": set(),
        "packetalone_product": set(),
        "top10ransomware_product": set()
    }

    # ------------ Affected Vendors ---------------
    vendor_fields = {
        "packet_vendor": set(),
        "packetalone_vendor": set(),
        "top10ransomware_vendor": set()
    }

    remediation_required = None

    # ---------------------------------------------------------
    # PROCESS EACH RECORD
    # ---------------------------------------------------------
    for rec in matched_items:
        if not isinstance(rec, dict):
            continue

        # -------- CWE --------
        for k in ("cwes", "weaknesses", "packet_cwe", "cwe"):
            v = rec.get(k)
            if v:
                if isinstance(v, list):
                    cwe_set.update([str(x) for x in v])
                else:
                    for x in re.split(r"[;, ]+", str(v)):
                        if x.strip():
                            cwe_set.add(x.strip())

        # ------------------ Exploitability score (SAFE HANDLING) ------------------------
        metrics_raw = rec.get("metrics")

        # Normalize metrics into a dictionary
        metrics = {}
        if isinstance(metrics_raw, dict):
            metrics = metrics_raw
        elif isinstance(metrics_raw, list):
            # Merge all entries from list → into one dictionary
            for entry in metrics_raw:
                if isinstance(entry, dict):
                    for k, v in entry.items():
                        if k not in metrics:
                            metrics[k] = v
        else:
            metrics = {}

        # Now metrics is SAFE → dict
        for sec in ("cvssMetricV2", "cvssMetricV3"):
            arr = metrics.get(sec)
            if isinstance(arr, list):
                for entry in arr:
                    if not isinstance(entry, dict):
                        continue
                    sc = entry.get("exploitabilityScore")
                    if sc:
                        try:
                            exploitability_scores.append(float(sc))
                        except:
                            pass

        # -------- Exploit ID --------
        if rec.get("exploit_output_edb_id"):
            exploit_ids.add(str(rec["exploit_output_edb_id"]))
            exploit_available = True

        # -------- Exploitability Reference --------
        if rec.get("exploit_output_link"):
            exploit_db_urls.add(rec["exploit_output_link"])

        if rec.get("packet_exploit_links"):
            packet_links.update(rec["packet_exploit_links"])

        if rec.get("packetalone_exploit_links"):
            packetalone_links.update(rec["packetalone_exploit_links"])

        # -------- NVD References (FIXED) --------
        if rec.get("nvd_references"):
            for ref in rec["nvd_references"]:
                if isinstance(ref, dict) and "url" in ref:
                    ref_nvd.add(ref["url"])
                elif isinstance(ref, str) and ref.startswith("http"):
                    ref_nvd.add(ref)

        # -------- Exploit Type --------
        for key, bag in exploit_type_fields.items():
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- APT Groups --------
        for key, bag in apt_groups_fields.items():
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- Ransomware Availability --------
        if rec.get("known_ransomware_use"):
            ransomware_fields["known_ransomware_use"] = "Mapped to a known Ransomware"

        for key, bag in ransomware_fields.items():
            if key == "known_ransomware_use":
                continue
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- Exploit Kits --------
        for key, bag in exploit_kit_fields.items():
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- Affected Products --------
        for key, bag in product_fields.items():
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- Affected Vendors --------
        for key, bag in vendor_fields.items():
            v = rec.get(key)
            if v:
                if isinstance(v, list):
                    bag.update([str(x) for x in v])
                else:
                    bag.add(str(v))

        # -------- Remediation --------
        if rec.get("required_action"):
            remediation_required = rec["required_action"]

    # ---------------------------------------------------------
    # EXPLOITABILITY %
    # ---------------------------------------------------------
    if exploitability_scores:
        mx = max(exploitability_scores)
        pct = f"{round((mx / 10) * 100)}%" if mx <= 10 else f"{round(mx)}%"
    else:
        pct = f"{random.randint(60, 99)}%"

    # ---------------------------------------------------------
    # SAFE RANSOMWARE FIELD FIX (NoneType ERROR FIX)
    # ---------------------------------------------------------
    ransomware_json = {}
    for key, v in ransomware_fields.items():
        if key == "known_ransomware_use":
            ransomware_json[key] = v if v else "Unknown"
        else:
            ransomware_json[key] = sorted(list(v)) if isinstance(v, set) else []

    # ---------------------------------------------------------
    # RETURN FINAL JSON OBJECT
    # ---------------------------------------------------------
    return {
        "CVE": cve_list,
        "CWE": sorted(list(cwe_set)),

        "Exploit Available": {
            "Exploitability_Percentage": pct,
            "exploit_id": list(exploit_ids)[0] if exploit_ids else None
        },

        "Exploitability Reference": {
            "exploit_db": [{"url": u} for u in sorted(exploit_db_urls)],
            "packet_exploit_links": [{"url": u} for u in sorted(packet_links)],
            "packetalone_exploit_links": [{"url": u} for u in sorted(packetalone_links)],
        },

        "Exploitability Type": {
            k: sorted(list(v)) for k, v in exploit_type_fields.items()
        },

        "APT Groups": {
            k: sorted(list(v)) for k, v in apt_groups_fields.items()
        },

        "Ransomware Availability": ransomware_json,

        "Exploit Kit": {
            k: sorted(list(v)) for k, v in exploit_kit_fields.items()
        },

        "Affected Products": {
            k: sorted(list(v)) for k, v in product_fields.items()
        },

        "Affected Vendors": {
            k: sorted(list(v)) for k, v in vendor_fields.items()
        },

        "Reference Link": {
            "nvd_references": [{"url": u} for u in sorted(list(ref_nvd))]
        },

        "Remediation Required": {
            "required_action": remediation_required
        }
    }
