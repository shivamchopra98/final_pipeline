# transformations/metasploit_transform.py
"""
Metasploit transformation (strict final schema with logging):
- Keeps only mapped final columns (no extras)
- Normalizes common source field names into final names
- Adds debug logs for renames and missing primary key
"""

import logging
from typing import Dict, Any, Optional

# ===========================================================
# 🧾 Logging Setup
# ===========================================================
log = logging.getLogger(__name__)

# ===========================================================
# 🎯 Final Schema Columns
# ===========================================================
METASPLOIT_FINAL_COLUMNS = [
    "metasploit_module_name",
    "metasploit_ref_name",
    "metasploit_fullname",
    "metasploit_aliases",
    "rank",
    "metasploit_type",
    "metasploit_author",
    "metasploit_description",
    "metasploit_references",
    "metasploit_platform",
    "autofilter_services",
    "rport",
    "metasploit_path",

]

# ===========================================================
# 🧩 Utility helper
# ===========================================================
def _get_field(record: Dict[str, Any], names) -> Optional[Any]:
    """Return the first matching field value from the record."""
    for n in names:
        if n in record:
            return record[n]
    return None


# ===========================================================
# 🧱 Transformation
# ===========================================================
def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform a Metasploit record into the strict final schema.
    Only final columns are retained; unmapped source fields are ignored.
    """
    out: Dict[str, Any] = {}

    # Primary identifier (use metasploit_name as the canonical key)
    name = _get_field(record, ["name", "module", "ref_name", "refname", "module_name"])
    if name is not None:
        out["metasploit_name"] = name
    else:
        log.debug("⚠️ Missing metasploit_name in Metasploit record")

    # Mapping of final fields to candidate source keys
    mapping = {
        "fullname": "metasploit_fullname",
        "ref_name": "metasploit_ref_name",
        "module_name": "metasploit_module_name",
        "aliases": "metasploit_aliases",
        "rank": "rank",
        "type": "metasploit_type",
        "author": "metasploit_author",
        "description": "metasploit_description",
        "references": "metasploit_references",
        "platform": "metasploit_platform",
        "autofilter_services": "autofilter_services",
        "rport": "rport",
        "path": "metasploit_path",
    }

    for final_key, candidates in mapping.items():
        val = _get_field(record, candidates)
        if val is not None:
            out[final_key] = val
            log.debug(f"🪶 Mapped Metasploit field {candidates} → '{final_key}'")

    # Ensure strict output contains exactly the final columns (values may be None)
    strict_output: Dict[str, Optional[Any]] = {k: out.get(k) for k in METASPLOIT_FINAL_COLUMNS}

    # Log summary
    if strict_output.get("metasploit_name"):
        log.debug(f"✅ Transformed Metasploit record metasploit_name={strict_output['metasploit_name']}")
    else:
        log.debug("⚠️ Transformed Metasploit record without metasploit_name (will be skipped upstream if required)")

    return strict_output
