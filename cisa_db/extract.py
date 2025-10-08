import requests

def extract_cisa_json(url: str):
    """
    Fetch JSON feed from the given URL and return the parsed JSON (in-memory).
    """
    print(f"⬇️ Fetching JSON from {url}")
    resp = requests.get(url, timeout=60)
    resp.raise_for_status()
    data = resp.json()
    print(f"✅ Downloaded JSON ({len(data) if isinstance(data, list) else 'object'})")
    return data
