# transform.py
import json
from decimal import Decimal
from datetime import datetime

def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def transform_nvd_items(nvd_items):
    """
    Transform raw NVD items into normalized records for S3/DynamoDB.
    """
    records = []
    today = datetime.utcnow().strftime("%Y-%m-%d")

    for item in nvd_items:
        rec = {
            "id": item.get("id"),
            "published": item.get("published"),
            "lastModified": item.get("lastModified"),
            "vulnStatus": item.get("vulnStatus"),
            "descriptions": item.get("descriptions", []),
            "metrics": item.get("metrics", {}),
            "references": item.get("references", []),
            "date_updated": today,
        }
        records.append(rec)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2, default=_decimal_default).encode("utf-8")
    print(f"🔄 Transformed NVD results: {len(records)} records (json {len(json_bytes)} bytes)")
    return records, json_bytes
