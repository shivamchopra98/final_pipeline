import requests
import lzma

LATEST_RELEASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest"

def extract_nvd_json(timeout: int = 300) -> str:
    """
    Download and decompress the latest NVD JSON feed (.xz) from FKIE-CAD GitHub releases.
    """
    print(f"⬇️ Resolving latest NVD feed from {LATEST_RELEASE_URL}")
    head_resp = requests.head(LATEST_RELEASE_URL, allow_redirects=True, timeout=timeout)
    latest_release_url = head_resp.url.rstrip("/")
    tag = latest_release_url.split("/")[-1]
    print(f"🔗 Latest release resolved: {latest_release_url}")

    download_url = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/{tag}/CVE-all.json.xz"
    print(f"⬇️ Downloading NVD JSON (.xz) from {download_url}")

    resp = requests.get(download_url, timeout=timeout)
    resp.raise_for_status()

    print("✅ Download complete, decompressing ...")
    decompressed = lzma.decompress(resp.content)
    text = decompressed.decode("utf-8")
    print("✅ Decompression complete")
    return text

if __name__ == "__main__":
    sample = extract_nvd_json()
    print(sample[:500])
