"""
Packet Output transformation (static dataset)
All mapped fields are prefixed with `packet_` to avoid collisions in the final table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # normalize CVE-YYYY-NNNN

log = logging.getLogger(__name__)

# Final strict schema for Packet Output dataset
PACKET_FINAL_COLUMNS = [
    "cve_id",
    "packet_base_score",
    "packet_cpes",
    "packet_cv3_attackvector",
    "packet_cv3_basescore",
    "packet_cwe",
    "packet_exploit_links",
    "packet_nvd_modified_date",
    "packet_nvd_published_date",
    "packet_product",
    "packet_vector_string",
    "packet_vendor",
    "packet_version",
    "packet_source",
]


def _get_field(record: Dict[str, Any], names):
    """Return the first present key from names (case-sensitive)."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Packet Output dataset records to match strict schema.
    - Always includes normalized CVE
    - Fills missing values with None
    - All mapped fields are prefixed with packet_
    """
    out: Dict[str, Any] = {}

    # Normalize CVE ID
    raw_cve = _get_field(record, ["cve_id", "CVE_ID", "CVE", "Name"])
    out["cve_id"] = normalize_cve(raw_cve) if raw_cve else None

    rename_map = {
        "base_score": "packet_base_score",
        "cpes": "packet_cpes",
        "cv3Attackvector": "packet_cv3_attackvector",
        "CV3BaseScore": "packet_cv3_basescore",
        "cwe": "packet_cwe",
        "Exploit_links": "packet_exploit_links",
        "NVD Modified Date": "packet_nvd_modified_date",
        "NVD Published Date": "packet_nvd_published_date",
        "product": "packet_product",
        "vector_string": "packet_vector_string",
        "vendor": "packet_vendor",
        "version": "packet_version",
    }

    # Apply renames
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            # Clean string fields — strip quotes, whitespace
            if isinstance(val, str):
                val = val.strip().strip('"').strip("'")
            out[new] = val

    # Add provenance marker
    out["packet_source"] = "packet-output"

    # Fill missing columns with None (→ DynamoDB NULL)
    for col in PACKET_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
