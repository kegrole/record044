"""Per-domain evaluation: verdict, risk, provider, claimable account."""

from .chain import find_cycle, normalize_chain
from .fingerprint import fingerprint_matches, normalize_body
from .hosts import normalize_host
from .providers import claimable_account, match_provider


def _is_redirect(status):
    return isinstance(status, int) and 300 <= status <= 399


def _build_evidence(ns_entries, chain, addresses, http, cycle_name):
    parts = []
    if not ns_entries:
        parts.append("NS: none")
    else:
        segments = []
        for name, resolves in ns_entries:
            if resolves:
                segments.append(name + " (resolves)")
            else:
                segments.append(name + " (dead, does not resolve)")
        parts.append("NS: " + ", ".join(segments))
    parts.append("CNAME chain: " + (" -> ".join(chain) if chain else "none"))
    parts.append("A records: " + (", ".join(addresses) if addresses else "none"))
    if http is None:
        parts.append("HTTP: not observed")
    else:
        status = http.get("status")
        if _is_redirect(status):
            location = http.get("location")
            parts.append(
                "HTTP: %s (redirect not followed; location: %s)" % (status, location)
            )
        else:
            parts.append("HTTP: %s" % status)
    if cycle_name is not None:
        parts.append("resolution loop detected at " + cycle_name)
    return "; ".join(parts)


def evaluate(entry):
    """Evaluate one observation entry and return its report record."""
    domain = normalize_host(entry.get("domain"))
    chain = normalize_chain(entry.get("cname_chain"))
    addresses = [str(addr) for addr in (entry.get("a") or [])]
    http = entry.get("http")

    ns_entries = []
    for record in entry.get("ns") or []:
        ns_entries.append(
            (normalize_host(record.get("name")), bool(record.get("resolves")))
        )
    has_live_delegation = any(resolves for _, resolves in ns_entries)

    normalized_body = normalize_body(http.get("body")) if http else None
    status = http.get("status") if http else None
    redirect = _is_redirect(status)

    cycle_name = find_cycle(domain, chain)

    provider = None
    account = None
    matched_fingerprint = None
    if cycle_name is None and chain:
        tail = chain[-1]
        provider = match_provider(tail)
        if provider is not None:
            account = claimable_account(tail, provider["suffix"])
            if http is not None and not redirect:
                if fingerprint_matches(normalized_body, provider["fingerprint"]):
                    matched_fingerprint = provider["fingerprint"]

    if cycle_name is not None:
        verdict, risk = "unresolved", "unknown"
        provider_id, claimable, matched_fingerprint = None, None, None
    elif (
        provider is not None
        and account is not None
        and not addresses
        and http is not None
        and not redirect
        and status in provider["statuses"]
        and matched_fingerprint is not None
    ):
        verdict, risk = "takeover", "high"
        provider_id, claimable = provider["id"], account
    elif not addresses and not chain and not has_live_delegation:
        verdict, risk = "dangling", "medium"
        provider_id, claimable, matched_fingerprint = None, None, None
    else:
        verdict, risk = "normal", "none"
        provider_id, claimable = None, None

    evidence = _build_evidence(ns_entries, chain, addresses, http, cycle_name)

    return {
        "domain": domain,
        "verdict": verdict,
        "risk": risk,
        "provider": provider_id,
        "claimable": claimable,
        "chain": chain,
        "normalized_body": normalized_body,
        "matched_fingerprint": matched_fingerprint,
        "evidence": evidence,
    }
