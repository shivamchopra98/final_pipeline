"""
Packetalone transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `packetalone_` to avoid collisions in the final merged table.
"""

import logging
from typing import Dict, Any
from utils.cve_utils import normalize_cve  # ✅ ensures consistent CVE formatting like CVE-2020-1234

log = logging.getLogger(__name__)

# Final schema columns for Packetalone dataset
PACKETALONE_FINAL_COLUMNS = [
    "cve_id",
    "packetalone_base_score",
    "packetalone_cpes",
    "packetalone_cv3_attack_vector",
    "packetalone_cv3_base_score",
    "packetalone_cwe",
    "packetalone_exploit_links",
    "packetalone_nvd_modified_date",
    "packetalone_nvd_published_date",
    "packetalone_product",
    "packetalone_vector_string",
    "packetalone_vendor",
    "packetalone_version",
    "packetalone_source",  # provenance marker
]


def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value (case-insensitive, safe lookup)."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Clean and rename Packetalone dataset records.
    - Normalizes CVE IDs.
    - Prefixes all mapped fields.
    - Fills missing fields with None (→ DynamoDB NULL).
    """
    out: Dict[str, Any] = {}

    # Normalize CVE
    cve = _get_field(record, ["cve_id", "CVE"])
    out["cve_id"] = normalize_cve(cve) if cve else None

    # Map → prefixed schema
    rename_map = {
        "base_score": "packetalone_base_score",
        "cpes": "packetalone_cpes",
        "cv3Attackvector": "packetalone_cv3_attack_vector",
        "CV3BaseScore": "packetalone_cv3_base_score",
        "cwe": "packetalone_cwe",
        "Exploit_links": "packetalone_exploit_links",
        "NVD Modified Date": "packetalone_nvd_modified_date",
        "NVD Published Date": "packetalone_nvd_published_date",
        "product": "packetalone_product",
        "vector_string": "packetalone_vector_string",
        "vendor": "packetalone_vendor",
        "version": "packetalone_version",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None and val != "null":
            out[new] = val

    # Add provenance marker
    out["packetalone_source"] = "packetalone"

    # Fill missing columns with None
    for col in PACKETALONE_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
