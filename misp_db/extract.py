# extract.py
import requests

MISP_JSON_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"

def extract_misp_text(timeout: int = 60) -> str:
    """
    Download the MISP threat-actor JSON and return raw text (in-memory).
    """
    print(f"⬇️ Downloading MISP JSON from {MISP_JSON_URL}")
    resp = requests.get(MISP_JSON_URL, timeout=timeout)
    resp.raise_for_status()
    resp.encoding = resp.encoding or "utf-8"
    print("✅ Download complete")
    return resp.text


if __name__ == "__main__":
    print(extract_misp_text()[:200])
