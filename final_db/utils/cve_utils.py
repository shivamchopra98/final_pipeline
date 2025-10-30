# utils/cve_utils.py
import re

# ✅ Matches one or more CVEs anywhere in a text string
CVE_PATTERN = re.compile(r"(?i)(CVE[-_\s]?\d{4}[-_\s]?\d{4,7})")

def normalize_cve(value: str | None) -> str | None:
    """Normalize a single CVE string into 'CVE-YYYY-NNNN' format."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    match = re.search(r"(?i)cve[-_\s]?(\d{4})[-_\s]?(\d{4,7})", value)
    if not match:
        return None
    return f"CVE-{match.group(1)}-{match.group(2).zfill(4)}"


def extract_cves(value: str | None) -> list[str]:
    """
    Extract and normalize all CVEs from a mixed field.
    Returns list of distinct, normalized CVEs (e.g., ['CVE-2006-1723', 'CVE-2006-1531'])
    """
    if not value or not isinstance(value, str):
        return []
    matches = CVE_PATTERN.findall(value)
    normalized = []
    for m in matches:
        n = normalize_cve(m)
        if n and n not in normalized:
            normalized.append(n)
    return normalized
