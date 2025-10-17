import requests
import lzma

LATEST_RELEASE_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest"

def extract_nvd_json(timeout: int = 300) -> str:
    """
    Download and decompress the latest NVD JSON feed (.xz).
    Automatically follows the latest release tag from GitHub.
    """
    print(f"⬇️ Resolving latest NVD feed from {LATEST_RELEASE_URL}")

    # Step 1: Get redirect to actual latest release tag
    head_resp = requests.head(LATEST_RELEASE_URL, allow_redirects=True, timeout=timeout)
    latest_release_url = head_resp.url.rstrip("/")
    print(f"🔗 Latest release resolved: {latest_release_url}")

    # Step 2: Extract release tag (e.g., v2025.10.15-000002)
    tag = latest_release_url.split("/")[-1]

    # Step 3: Construct correct download URL
    download_url = f"https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/{tag}/CVE-all.json.xz"
    print(f"⬇️ Downloading NVD JSON (.xz) from {download_url}")

    # Step 4: Download and decompress
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
