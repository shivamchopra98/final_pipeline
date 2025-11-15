# utils/cve_utils.py

import re

CVE_REGEX = re.compile(r"(?i)\bCVE[-_\s]?(\d{4})[-_\s]?(\d{1,7})\b")

def normalize_cve(cve: str):
    """
    Normalize CVE formats into CVE-YYYY-NNNN
    Examples:
        CVE-2017-14 → CVE-2017-0014
        CVE 2017 0143 → CVE-2017-0143
        CVE_2017_143  → CVE-2017-0143
    """
    if not cve or not isinstance(cve, str):
        return None

    m = CVE_REGEX.search(cve)
    if not m:
        return None

    year = m.group(1)
    num = m.group(2).zfill(4)  # pad to 4–7 digits

    return f"CVE-{year}-{num}"
