import json
from typing import List, Dict, Tuple, Any
from datetime import datetime, timezone

def transform_nvd_json_to_records_and_json_bytes(json_text: str) -> Tuple[List[Dict[str, Any]], bytes]:
    """
    Transform FKIE-CAD NVD JSON feed into list of records for incremental DynamoDB ETL.
    """
    parsed = json.loads(json_text)
    records: List[Dict[str, Any]] = []

    cve_items = parsed.get("cve_items", [])
    if not cve_items:
        print("⚠️ No 'cve_items' found in the feed. Possibly malformed or empty.")
    else:
        print(f"🔍 Found {len(cve_items)} CVE entries")

    # Capture ETL run time (for date_updated)
    etl_run_time = datetime.now(timezone.utc).isoformat()

    for item in cve_items:
        cve_id = item.get("id")
        record = {
            "id": cve_id,  # DynamoDB primary key
            "cveID": cve_id,
            "cveTags": item.get("tags"),
            "date_updated": etl_run_time,
            "lastModified": item.get("lastModified") or item.get("published"),
            "published": item.get("published"),
            "sourceIdentifier": item.get("sourceIdentifier"),
            "vulnStatus": item.get("vulnStatus"),
            "metrics": item.get("metrics"),
            "references": item.get("references"),
            "descriptions": item.get("descriptions"),
            "weaknesses": item.get("weaknesses"),
        }
        records.append(record)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"🔄 Transformed NVD JSON → records: {len(records)}, bytes: {len(json_bytes)}")
    return records, json_bytes
