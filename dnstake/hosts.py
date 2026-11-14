"""Hostname normalization helpers."""


def normalize_host(name):
    """Normalize a hostname for comparison.

    Steps, in order:
    1. strip leading/trailing whitespace
    2. lowercase
    3. remove a single trailing dot (the root dot of a fully qualified
       domain name as written in DNS zone files)
    """
    if name is None:
        return None
    normalized = str(name).strip().lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    return normalized
