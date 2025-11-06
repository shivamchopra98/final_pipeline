import uuid
import hashlib

def generate_host_finding_id(host: str, plugin_id: str):
    """Generate a random hash (Host Findings ID) for each record."""
    unique_str = f"{host}-{plugin_id}-{uuid.uuid4()}"
    return hashlib.sha256(unique_str.encode()).hexdigest()[:16]
