import json
from typing import Any, Dict, List, Tuple
from datetime import datetime

def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        return list(x.values())
    return [x]

def _expand_meta_to_keys(obj: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(obj)
    meta = out.get("meta")
    if isinstance(meta, dict):
        for mk, mv in meta.items():
            out[f"meta.{mk}"] = mv
    return out

def transform_json_text_to_records_and_json_bytes(json_text: str) -> Tuple[List[Dict[str, Any]], bytes]:
    parsed = json.loads(json_text)

    # Heuristics to find the cluster entries:
    clusters = []
    if isinstance(parsed, dict) and "values" in parsed:
        clusters = _ensure_list(parsed.get("values"))
    elif isinstance(parsed, dict) and "clusters" in parsed:
        clusters = _ensure_list(parsed.get("clusters"))
    elif isinstance(parsed, dict) and "value" in parsed:
        clusters = _ensure_list(parsed.get("value"))
    elif isinstance(parsed, list):
        clusters = parsed
    elif isinstance(parsed, dict):
        sample_vals = list(parsed.values())[:8]
        if sample_vals and all(isinstance(v, dict) for v in sample_vals):
            clusters = _ensure_list(parsed)

    records: List[Dict[str, Any]] = []
    today = datetime.utcnow().strftime("%Y-%m-%d")  # <-- only date
    for c in clusters:
        if not isinstance(c, dict):
            continue
        rec = {}
        for k, v in c.items():
            rec[k] = v
        rec = _expand_meta_to_keys(rec)
        if not rec.get("uuid"):
            rec["uuid"] = c.get("uuid") or c.get("id") or c.get("value")
        rec["date_updated"] = today  # <-- new date field
        records.append(rec)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"🔄 Transformed in-memory: records={len(records)} (json bytes={len(json_bytes)})")
    return records, json_bytes
