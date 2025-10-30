"""
Attackerkb transformation (static dataset — uses NULL for missing fields)
All mapped fields are prefixed with `attackerkb_` to avoid collisions in the final table.
"""

import logging
from typing import Dict, Any

log = logging.getLogger(__name__)

# Final strict schema for Attackerkb dataset
ATTACKERKB_FINAL_COLUMNS = [
    "cve_id",                       # normalized CVE (from Name or Reference CVE)
    "attackerkb_created",
    "attackerkb_cvssv3",
    "attackerkb_disclosure_date",
    "attackerkb_document",
    "attackerkb_editor_id",
    "attackerkb_exploitability_score",
    "attackerkb_id",
    "attackerkb_impact_score",
    "attackerkb_reference_link",
    "attackerkb_revision_date",
    "attackerkb_score",
    "attackerkb_tags",
    "attackerkb_vulnerable_versions",
    "attackerkb_source",            # set to "attackerkb" (provenance marker)
]


def _get_field(record: Dict[str, Any], names):
    """Return first present key from names (case-sensitive as stored in CSV → Dynamo item)."""
    for n in names:
        if n in record:
            return record[n]
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform one Attackerkb record (dict) into the canonical schema for the final table.
    - Always include cve_id (tries Name first, then Reference CVE)
    - Prefixes mapped columns with attackerkb_
    - Defaults missing values to None (→ DynamoDB NULL)
    """
    out: Dict[str, Any] = {}

    # CVE may exist in "Name" (primary) or "Reference CVE" (fallback)
    cve = _get_field(record, ["Name", "cve", "CVE", "cve_id"])
    out["cve_id"] = cve

    rename_map = {
        "Created": "attackerkb_created",
        "cvssV3": "attackerkb_cvssv3",
        "Disclosure Date": "attackerkb_disclosure_date",
        "Document": "attackerkb_document",
        "Editor Id": "attackerkb_editor_id",
        "Exploitability Score": "attackerkb_exploitability_score",
        "ID": "attackerkb_id",
        "Impact Score": "attackerkb_impact_score",
        "Reference Link": "attackerkb_reference_link",
        "Revision Date": "attackerkb_revision_date",
        "score": "attackerkb_score",
        "tags": "attackerkb_tags",
        "vulnerable-versions": "attackerkb_vulnerable_versions",
        "vulnerable_versions": "attackerkb_vulnerable_versions",
    }

    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    # Add provenance
    out["attackerkb_source"] = "attackerkb"

    # Fill missing columns with None (DynamoDB → NULL)
    for col in ATTACKERKB_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
