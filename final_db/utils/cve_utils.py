# utils/cve_utils.py
import re

CVE_PATTERN = re.compile(r"(?i)cve[-_\s]?(\d{4})[-_\s]?(\d+)$")

def normalize_cve(value: str | None) -> str | None:
    """Normalize any CVE-like string into 'CVE-YYYY-NNNN' format."""
    if not value or not isinstance(value, str):
        return None
    m = CVE_PATTERN.search(value.strip())
    if not m:
        return None
    return f"CVE-{m.group(1)}-{m.group(2).zfill(4)}"
