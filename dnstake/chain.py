"""CNAME chain helpers: normalization and resolution-loop detection."""

from .hosts import normalize_host


def normalize_chain(chain):
    """Normalize every link of a CNAME chain, preserving order."""
    return [normalize_host(link) for link in (chain or [])]


def find_cycle(domain, chain):
    """Return the repeated name if the chain loops, else None.

    A resolution loop exists when any name appears twice while walking
    from the domain itself through the CNAME chain. A chain that points
    back to the domain itself also counts as a loop.
    """
    seen = set()
    for name in [domain, *chain]:
        if name in seen:
            return name
        seen.add(name)
    return None
