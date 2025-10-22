import json
from typing import List, Dict, Tuple, Any

def transform_nvd_json_to_records_and_json_bytes(json_text: str) -> Tuple[List[Dict[str, Any]], bytes]:
    """
    Transform the FKIE-CAD NVD JSON feed into a list of CVE records.
    Compatible with both 'CVE_Items' and 'cve_items' formats.
    """
    parsed = json.loads(json_text)
    records: List[Dict[str, Any]] = []

    # Handle both schemas
    items = parsed.get("CVE_Items") or parsed.get("cve_items") or parsed.get("items") or []

    for item in items:
        # FKIE format — top-level fields
        cve_id = item.get("id") or item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        if not cve_id:
            continue

        rec = {
            "cveID": cve_id,
            "sourceIdentifier": item.get("sourceIdentifier"),
            "published": item.get("published"),
            "lastModified": item.get("lastModified"),
            "vulnStatus": item.get("vulnStatus"),
            "descriptions": item.get("descriptions") or item.get("cve", {}).get("description", {}).get("description_data", []),
            "metrics": item.get("metrics") or item.get("impact", {}),
            "weaknesses": item.get("weaknesses", []),
            "references": item.get("references") or item.get("cve", {}).get("references", {}).get("reference_data", []),
            "cveTags": item.get("cveTags", []),
        }

        records.append(rec)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"🔄 Transformed NVD JSON -> records: {len(records)}, json bytes {len(json_bytes)}")
    return records, json_bytes