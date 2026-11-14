"""Report assembly: per-domain records, findings, and summary."""

import json

from .verdict import evaluate

_VERDICTS = ("takeover", "dangling", "unresolved", "normal")
_RISKS = ("high", "medium", "unknown", "none")


def build_report(data):
    """Build the full report dict from parsed observations."""
    records = [evaluate(entry) for entry in (data.get("domains") or [])]

    findings = [
        {"domain": r["domain"], "verdict": r["verdict"], "risk": r["risk"]}
        for r in records
        if r["verdict"] != "normal"
    ]

    verdict_counts = {name: 0 for name in _VERDICTS}
    by_risk = {name: 0 for name in _RISKS}
    by_provider = {}
    accounts = set()
    for record in records:
        verdict_counts[record["verdict"]] += 1
        by_risk[record["risk"]] += 1
        if record["verdict"] == "takeover":
            provider_id = record["provider"]
            by_provider[provider_id] = by_provider.get(provider_id, 0) + 1
            accounts.add(record["claimable"])

    summary = {
        "domains": len(records),
        "takeover": verdict_counts["takeover"],
        "dangling": verdict_counts["dangling"],
        "unresolved": verdict_counts["unresolved"],
        "normal": verdict_counts["normal"],
        "by_provider": {key: by_provider[key] for key in sorted(by_provider)},
        "by_risk": by_risk,
        "accounts": len(accounts),
    }

    return {"domains": records, "findings": findings, "summary": summary}


def render_report(report):
    """Serialize a report deterministically (byte-identical across runs)."""
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False) + "\n"
