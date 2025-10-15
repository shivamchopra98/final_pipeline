# transformations/cisa_transform.py
"""
CISA transformation (strict final schema with logging):
- Standardizes field names for consistency
- Keeps only mapped columns (no extras)
- Adds detailed logs for traceability
"""

import logging
from typing import Dict, Any

# ===========================================================
# 🧾 Logging Setup
# ===========================================================
log = logging.getLogger(__name__)

# ===========================================================
# 🎯 Final Schema Columns
# ===========================================================
CISA_FINAL_COLUMNS = [
    "vendor_project",
    "product",
    "vulnerability_name",
    "short_description",
    "required_action",
    "cisa_dueDate",
    "known_ransomware_use",
    "notes",
    "cwes",
]

# ===========================================================
# 🧩 Utility Helper
# ===========================================================
def _get_field(record: Dict[str, Any], names):
    """Return the first matching field value from the record."""
    for n in names:
        if n in record:
            return record[n]
    return None


# ===========================================================
# 🧱 Transformation Logic
# ===========================================================
def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cleans and renames CISA fields.
    Retains only the standardized schema fields (no unmapped fields).
    """
    out: Dict[str, Any] = {}

    # --- Primary key standardization ---
    cve = _get_field(record, ["CVE ID", "cveID", "cve_id", "CVE"])
    if cve:
        out["cve_id"] = cve
    else:
        log.debug("⚠️ Missing CVE ID in CISA record")

    # --- Define strict rename map ---
    rename_map = {
        "vendorProject": "vendor_project",
        "product": "product",
        "vulnerabilityName": "vulnerability_name",
        "shortDescription": "short_description",
        "requiredAction": "required_action",
        "dueDate": "cisa_dueDate",
        "knownRansomwareCampaignUse": "known_ransomware_use",
        "notes": "notes",
        "cwes": "cwes",
    }

    # --- Apply rename mapping (strict mode) ---
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val
            log.debug(f"🪶 Renamed field '{old}' → '{new}'")

    # --- Retain only fields from final schema ---
    strict_output = {k: out.get(k) for k in CISA_FINAL_COLUMNS if k in out or k == "cve_id"}

    # --- Log summary ---
    if "cve_id" in strict_output:
        log.debug(f"✅ Transformed CISA record for CVE {strict_output['cve_id']}")
    else:
        log.debug("⚠️ Skipped CISA record (missing CVE ID)")

    return strict_output
