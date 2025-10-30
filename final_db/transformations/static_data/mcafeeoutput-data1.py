"""
Transformation for `infoservices-cybersecurity-vuln-static-mcafeeoutput-data1` (static dataset)

- Cleans and normalizes McAfee static data into a strict schema.
- Maintains consistent structure with NVD join pipeline (includes `cve_id` key).
- Handles missing/null values gracefully.

Example input:
    {
        "S.No": "228",
        "Campaign": "null",
        "Exploit kits": "null",
        "Ransomware": "Hidden Tear -- Ransomware",
        "uploaded_date": "2025-10-30",
        "Vulnerabilities": "null"
    }

Example output:
    {
        "cve_id": None,
        "campaign": None,
        "exploit_kits": None,
        "ransomware": "Hidden Tear -- Ransomware",
        "uploaded_date": "2025-10-30",
        "vulnerabilities": None
    }
"""

import logging
from typing import Dict, Any, List, Iterable

log = logging.getLogger(__name__)

# Final schema for McAfee static dataset
MCAFEE_FINAL_COLUMNS = [
    "cve_id",
    "campaign",
    "exploit_kits",
    "ransomware",
    "uploaded_date",
    "vulnerabilities",
]


def _get_field(record: Dict[str, Any], names) -> Any:
    """Return the first present value for any of the given names."""
    if isinstance(names, str):
        names = [names]
    for n in names:
        if n in record and record[n] not in (None, "", "null", "NULL"):
            return record[n]
    return None


def _clean_str(v: Any) -> Any:
    """Trim and convert 'null' strings to None."""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip().strip('"').strip("'")
        if s.lower() == "null" or s == "":
            return None
        return s
    return v


RENAME_MAP = {
    "S.No": "s_no",
    "Campaign": "campaign",
    "Exploit kits": "exploit_kits",
    "Ransomware": "ransomware",
    "uploaded_date": "uploaded_date",
    "Vulnerabilities": "vulnerabilities",
}


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and normalize a McAfee dataset record.
    Since this dataset doesn’t contain CVEs, cve_id is kept as None.
    """
    out: Dict[str, Any] = {}

    # Set CVE ID (static dataset → no CVEs)
    out["cve_id"] = None

    for src, dest in RENAME_MAP.items():
        val = _get_field(record, src)
        if val is not None:
            out[dest] = _clean_str(val)

    # Fill missing columns with None
    for col in MCAFEE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out


def transform_batch(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Transform all McAfee records into the strict final schema."""
    transformed = [clean_and_rename(r) for r in records]
    log.info("Transformed %d McAfee static records", len(transformed))
    return transformed


if __name__ == "__main__":
    # Quick test with your sample
    sample = {
        "S.No": "228",
        "Campaign": "null",
        "Exploit kits": "null",
        "Ransomware": "Hidden Tear -- Ransomware",
        "uploaded_date": "2025-10-30",
        "Vulnerabilities": "null",
    }

    result = transform_batch([sample])
    for r in result:
        print(r)
