# transform.py
import json
from typing import Any, Dict, List, Tuple

def _ensure_list(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    if isinstance(x, dict):
        # mapping uuid->object case -> use values
        return list(x.values())
    return [x]

def _expand_meta_to_keys(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    If obj contains "meta" dict, expand each key into "meta.<key>" at top-level.
    Returns a shallow copy with meta.* keys added and original "meta" preserved (optional).
    """
    out = dict(obj)  # shallow copy
    meta = out.get("meta")
    if isinstance(meta, dict):
        for mk, mv in meta.items():
            out[f"meta.{mk}"] = mv
    return out

def transform_json_text_to_records_and_json_bytes(json_text: str) -> Tuple[List[Dict[str, Any]], bytes]:
    """
    Take raw MISP JSON text and produce:
      - records: list of dicts (each contains 'uuid' and expanded meta.* keys)
      - json_bytes: canonical baseline bytes for S3 upload
    We do not remove nested fields; we expand meta.* into top-level keys so they show as columns.
    """
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
    for c in clusters:
        if not isinstance(c, dict):
            continue
        rec = {}
        # copy all top-level keys
        for k, v in c.items():
            rec[k] = v
        # expand meta.* keys for easier column viewing
        rec = _expand_meta_to_keys(rec)
        # ensure uuid exists
        if not rec.get("uuid"):
            rec["uuid"] = c.get("uuid") or c.get("id") or c.get("value")
        records.append(rec)

    json_bytes = json.dumps(records, ensure_ascii=False, indent=2).encode("utf-8")
    print(f"🔄 Transformed in-memory: records={len(records)} (json bytes={len(json_bytes)})")
    return records, json_bytes

# convenience file-read function (for local tests)
def transform_misp_file(json_file_path: str):
    with open(json_file_path, "r", encoding="utf-8") as fh:
        txt = fh.read()
    return transform_json_text_to_records_and_json_bytes(txt)
