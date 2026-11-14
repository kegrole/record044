"""Command-line entry point.

Usage:
    python -m dnstake.cli --observations demo/observations.json --out out/report.json
"""

import argparse
import json
import os

from .report import build_report, render_report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="dnstake",
        description=(
            "Evaluate pre-collected DNS/HTTP observations for dangling "
            "records and subdomain takeover risks. Never performs live "
            "DNS queries or HTTP requests."
        ),
    )
    parser.add_argument("--observations", required=True,
                        help="path to the observations JSON file")
    parser.add_argument("--out", required=True,
                        help="path to write the JSON report to")
    args = parser.parse_args(argv)

    with open(args.observations, "r", encoding="utf-8") as handle:
        data = json.load(handle)

    report = build_report(data)
    text = render_report(report)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(text)

    summary = report["summary"]
    providers = ", ".join(
        "%s: %d" % (key, summary["by_provider"][key])
        for key in sorted(summary["by_provider"])
    ) or "none"
    print(
        "domains=%d takeover=%d medium_risk=%d providers=%s accounts=%d"
        % (
            summary["domains"],
            summary["takeover"],
            summary["dangling"],
            providers,
            summary["accounts"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
