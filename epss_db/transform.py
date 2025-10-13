# transform_epss.py
from datetime import datetime
from typing import List, Dict, Any

def _date_only_from_iso(s: str) -> str:
    if not s:
        return None
    s = str(s).strip()
    if "T" in s:
        return s.split("T", 1)[0]
    if " " in s:
        return s.split(" ", 1)[0]
    if len(s) >= 10 and s[4] == "-" and s[7] == "-":
        return s[:10]
    return s

def transform_epss_api_responses(api_results: List[Dict[str, Any]]) -> (List[Dict[str, Any]], bytes):
    """
    Accept raw EPSS API responses (list of dicts) and return:
      - records: list of normalized dicts for DDB / baseline
      - json_bytes: canonical JSON bytes for baseline upload
    Each record will have fields:
      - cve (str)  -> primary key
      - epss (float or None)
      - percentile (float or None)
      - date (YYYY-MM-DD)  (date-only)
      - date_updated (YYYY-MM-DD) (the run date)
    """
    import json
    records = []
    today = datetime.utcnow().strftime("%Y-%m-%d")
    for entry in api_results:
        rec = {}
        # common keys
        cve = entry.get("cve") or entry.get("CVE") or entry.get("id") or entry.get("identifier")
        if not cve:
            # try nested
            if "data" in entry and isinstance(entry["data"], dict):
                cve = entry["data"].get("cve") or entry["data"].get("id")
                entry = entry["data"]
        if not cve:
            # skip if not found
            continue
        rec["cve"] = str(cve).strip().upper()
        # epss might be under 'epss' or 'score'
        rec["epss"] = entry.get("epss") if entry.get("epss") is not None else entry.get("score") or None
        rec["percentile"] = entry.get("percentile") or None
        # prefer 'date' field, normalize to date-only
        d = entry.get("date") or entry.get("timestamp") or entry.get("lastModified") or entry.get("published")
        rec["date"] = _date_only_from_iso(d) if d else None
        rec["date_updated"] = today
        records.append(rec)
    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"🔄 Transformed EPSS results: {len(records)} records (json {len(json_bytes)} bytes)")
    return records, json_bytes
