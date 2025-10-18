# utils/time_utils.py
from datetime import datetime, timezone

def iso_now():
    """Return current UTC time in ISO 8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
