import boto3
import json
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

dynamodb = boto3.client("dynamodb")  # using low-level client for batch_get_item

BATCH_SIZE = 100  # batch_get_item supports up to 100 keys per request

from decimal import Decimal

def _clean_item(item):
    """Convert DynamoDB AttributeValues to plain Python types and make them JSON-safe."""
    from boto3.dynamodb.types import TypeDeserializer
    deserializer = TypeDeserializer()
    cleaned = {}

    def make_json_safe(v):
        # Recursively clean values
        if isinstance(v, Decimal):
            # convert to int if no decimal part, else float
            return int(v) if v % 1 == 0 else float(v)
        elif isinstance(v, set):
            return list(v)
        elif isinstance(v, bytes):
            try:
                return v.decode("utf-8")
            except Exception:
                return str(v)
        elif isinstance(v, dict):
            return {k: make_json_safe(vv) for k, vv in v.items()}
        elif isinstance(v, list):
            return [make_json_safe(x) for x in v]
        else:
            return v

    for k, v in item.items():
        try:
            py_val = deserializer.deserialize(v)
        except Exception:
            py_val = v
        py_val = make_json_safe(py_val)
        if py_val not in [None, "", [], {}, "null"]:
            cleaned[k] = py_val
    return cleaned

def _batch_get(table_name: str, keys: List[Dict[str, Any]]) -> Dict[str, Dict]:
    """
    Perform a single batch_get_item for up to 100 keys.
    keys: list of dicts like [{"cve_id": {"S":"CVE-2023-..."}}, ...] OR use Keys param
    We'll use Keys param with simple Key dicts: [{'cve_id': 'CVE-...'}, ...]
    Returns map: cve_id -> item (plain python, cleaned)
    """
    # Build Keys in DynamoDB JSON format expected by boto3 client (it accepts native python):
    request_keys = [{"cve_id": k} for k in keys]  # keys are strings
    request_items = {
        table_name: {
            "Keys": [{"cve_id": {"S": k}} if isinstance(k, str) else k for k in keys]
        }
    }

    # Use batch_get_item (note: unprocessed keys can be returned)
    response = dynamodb.batch_get_item(RequestItems=request_items)
    items = response.get("Responses", {}).get(table_name, [])

    # If unprocessed keys exist, try to re-request them (simple retry once)
    unproc = response.get("UnprocessedKeys", {}).get(table_name, {}).get("Keys", [])
    if unproc:
        # simple retry loop (one more try)
        retry_req = {"RequestItems": {table_name: {"Keys": unproc}}}
        resp2 = dynamodb.batch_get_item(**retry_req)
        items += resp2.get("Responses", {}).get(table_name, [])

    result = {}
    for it in items:
        cleaned = _clean_item(it)
        cve = cleaned.get("cve_id") or cleaned.get("CVE") or cleaned.get("cve")  # try multiple keys
        if cve:
            result[str(cve)] = cleaned
    return result

def batch_get_by_cves(table_name: str, cve_list: List[str], max_workers: int = 4) -> Dict[str, Dict]:
    """
    Fetch multiple CVE keyed records from dynamodb using batching and parallel requests.
    Returns dict: cve -> item (cleaned)
    """
    # unique cves
    unique = list(dict.fromkeys([c.strip() for c in cve_list if c and str(c).strip() != ""]))
    if not unique:
        return {}

    # chunk into batches of BATCH_SIZE
    batches = [unique[i:i+BATCH_SIZE] for i in range(0, len(unique), BATCH_SIZE)]
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(_batch_get, table_name, batch): batch for batch in batches}
        for fut in as_completed(futures):
            try:
                res = fut.result()
                results.update(res)
            except Exception as e:
                # log and continue
                print(f"batch error: {e}")

    return results

def extract_cwes_from_item(item: Dict[str, Any]) -> List[str]:
    """Scan item values to find CWE ids (strings containing 'CWE-' or numeric cwe keys)."""
    cwes = set()
    # scan keys and values
    for k, v in item.items():
        if isinstance(v, str):
            if "CWE-" in v:
                cwes.add(v.strip())
        elif isinstance(v, list):
            for val in v:
                if isinstance(val, str) and "CWE-" in val:
                    cwes.add(val.strip())
        elif isinstance(v, dict):
            # nested dict: stringify and look for CWE-
            for kk, vv in v.items():
                if isinstance(vv, str) and "CWE-" in vv:
                    cwes.add(vv.strip())
    # also check common numeric CWE fields, like 'cwe' : 79 -> convert to CWE-79
    for possible in ("cwe", "CWE", "weakness", "weaknesses"):
        if possible in item:
            val = item[possible]
            if isinstance(val, int):
                cwes.add(f"CWE-{val}")
            elif isinstance(val, str) and val.isdigit():
                cwes.add(f"CWE-{val}")
            elif isinstance(val, list):
                for v in val:
                    if isinstance(v, int):
                        cwes.add(f"CWE-{v}")
                    elif isinstance(v, str) and v.isdigit():
                        cwes.add(f"CWE-{v}")
    return list(cwes)

def extract_threats_from_item(item: Dict[str, Any]) -> Dict[str, Dict]:
    """
    Build nested Threat JSON using prefixes. All fields from DynamoDB are mapped.
    """

    prefix_groups = {
        "apt_": "APT",
        "attackerkb_": "AttackerKB",
        "chinese_": "Chinese",
        "cisa_": "CISA",
        "exploit_": "Exploit",
        "exploitkit_": "ExploitKit",
        "ibm_": "IBM",
        "intruder_": "Intruder",
        "mcafee1_": "McAfee1",
        "mcafee2_": "McAfee2",
        "mcafee3_": "McAfee3",
        "metasploit_": "Metasploit",
        "notes": "Notes",
        "nvd_": "NVD",
        "packet_": "Packet",
        "packetalone_": "PacketAlone",
        "product_": "Product",
        "ransomware_": "Ransomware",
        "references": "References",
        "threatinfo1_": "ThreatInfo1",
        "threatinfo2_": "ThreatInfo2",
        "threatinfo3_": "ThreatInfo3",
        "threatinfo4_": "ThreatInfo4",
        "threatinfo5_": "ThreatInfo5",
        "top10ransomware_": "Top10Ransomware",
        "vendor_": "Vendor",
        "weakness": "Weakness",
        "weaknesses": "Weaknesses",
    }

    nested_threats = {}

    for key, value in item.items():
        matched = False
        for prefix, group_name in prefix_groups.items():
            if key.startswith(prefix):
                matched = True
                if group_name not in nested_threats:
                    nested_threats[group_name] = {}
                nested_threats[group_name][key] = value
                break
        # If no prefix matched, put it in "Misc"
        if not matched:
            if "Misc" not in nested_threats:
                nested_threats["Misc"] = {}
            nested_threats["Misc"][key] = value

    return nested_threats
