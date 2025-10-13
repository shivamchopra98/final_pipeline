# extract_nvd.py
import lzma
import requests
import ijson

def extract_nvd_items(url: str):
    """
    Stream CVE items from the NVD JSON.xz feed in-memory.
    """
    print(f"⬇️ Downloading {url} (streaming in memory)")
    response = requests.get(url, stream=True)
    response.raise_for_status()

    with lzma.LZMAFile(response.raw) as f:
        for item in ijson.items(f, "cve_items.item"):
            yield item
