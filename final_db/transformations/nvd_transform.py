"""
NVD transformation (strict schema with logging):
- Extracts CVE ID and normalizes metrics
- Keeps only final schema fields
"""

import logging
from typing import Dict, Any, Optional
from utils.time_utils import iso_now

log = logging.getLogger(__name__)

NVD_FINAL_COLUMNS = [
    "cve_id",
    "nvd_references",
    "weakness",
    "nvd_descriptions",
    "metrics_cvssmetricv31",
    "metrics_cvssmetricv30",
    "metrics_cvssmetricv2",
    "metrics_cvssmetricv40",
    "uploaded_date",
]


def _get_field(record: Dict[str, Any], names):
    for n in names:
        if n in record:
            return record[n]
    return None


def extract_cvss(metric_section: Any) -> Optional[Dict[str, Any]]:
    if not metric_section or not isinstance(metric_section, dict):
        return None
    try:
        if "L" in metric_section and metric_section["L"]:
            first = metric_section["L"][0]
            metric = first.get("M", {})
            cvss_map = {}

            cvss_data = metric.get("cvssData", {}).get("M", {})
            for k, v in cvss_data.items():
                if isinstance(v, dict):
                    cvss_map[k] = list(v.values())[0]
                else:
                    cvss_map[k] = v
            return cvss_map
    except Exception as e:
        log.warning(f"⚠️ NVD extract_cvss error: {e}")
    return None


def clean_and_rename(record: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    cve_val = _get_field(record, ["id", "cveID", "CVE_ID", "CVE"])
    out["cve_id"] = cve_val

    rename_map = {
        "references": "nvd_references",
        "weakness": "weakness",
        "descriptions": "nvd_descriptions",
    }
    for old, new in rename_map.items():
        val = _get_field(record, [old])
        if val is not None:
            out[new] = val

    metrics = _get_field(record, ["metrics", "Metrics"])
    metric_versions = {
        "cvssMetricV31": "metrics_cvssmetricv31",
        "cvssMetricV30": "metrics_cvssmetricv30",
        "cvssMetricV2": "metrics_cvssmetricv2",
        "cvssMetricV40": "metrics_cvssmetricv40",
    }
    for src, dest in metric_versions.items():
        if isinstance(metrics, dict) and src in metrics:
            out[dest] = extract_cvss(metrics.get(src))

    out["uploaded_date"] = iso_now()

    # Fill missing fields with None
    for col in NVD_FINAL_COLUMNS:
        out.setdefault(col, None)

    return out
