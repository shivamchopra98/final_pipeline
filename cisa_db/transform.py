import re
from datetime import datetime

CLEAN_WS = re.compile(r"\s+")

def _clean_text(x):
    if x is None:
        return None
    s = str(x).replace("\r", " ").replace("\n", " ")
    s = CLEAN_WS.sub(" ", s).strip()
    return s if s != "" else None

def _extract_entries_from_cisa_raw(raw_obj):
    entries = None
    if isinstance(raw_obj, dict):
        for candidate in ("vulnerabilities", "knownExploitedVulnerabilities", "knownExploitedVulnerabilitiesList", "items"):
            if candidate in raw_obj and isinstance(raw_obj[candidate], list):
                entries = raw_obj[candidate]
                break
        if entries is None:
            for v in raw_obj.values():
                if isinstance(v, list) and v and isinstance(v[0], dict) and ("cveID" in v[0] or "cve" in v[0]):
                    entries = v
                    break
    elif isinstance(raw_obj, list):
        entries = raw_obj

    if entries is None:
        return []

    normalized = []
    for e in entries:
        if not isinstance(e, dict):
            continue

        def getf(*keys):
            for k in keys:
                if k in e:
                    return e[k]
                for ek in e.keys():
                    if ek.lower() == k.lower():
                        return e[ek]
            return None

        rec = {
            "cveID": _clean_text(getf("cveID", "cve", "vulnerabilityID", "cveId")),
            "vendorProject": _clean_text(getf("vendorProject", "vendor", "vendor_project", "vendorName")),
            "product": _clean_text(getf("product", "productName", "products")),
            "vulnerabilityName": _clean_text(getf("vulnerabilityName", "vulnerability_name", "vulnName")),
            "dateAdded": _clean_text(getf("dateAdded", "date_added", "datePublished")),
            "shortDescription": _clean_text(getf("shortDescription", "short_description")),
            "requiredAction": _clean_text(getf("requiredAction", "required_action")),
            "dueDate": _clean_text(getf("dueDate", "due_date")),
            "knownRansomwareCampaignUse": _clean_text(getf("knownRansomwareCampaignUse")),
            "notes": _clean_text(getf("notes", "note", "reference")),
            "cwes": _clean_text(getf("cwes", "cwe"))
        }

        # Find CVE if missing
        if not rec["cveID"]:
            CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", flags=re.IGNORECASE)
            found = None
            for v in e.values():
                s = str(v)
                m = CVE_RE.search(s)
                if m:
                    found = m.group(0).upper()
                    break
            if found:
                rec["cveID"] = found
            else:
                continue

        normalized.append(rec)

    return normalized


def transform_cisa_json(raw_json):
    """
    Transform raw JSON (in-memory) and return cleaned entries.
    """
    print("🔄 Transforming CISA data in-memory...")
    entries = _extract_entries_from_cisa_raw(raw_json)
    today = datetime.now().strftime("%Y-%m-%d")
    for r in entries:
        r.setdefault("uploaded_date", today)
    print(f"✅ Transformation complete: {len(entries)} records")
    return entries
