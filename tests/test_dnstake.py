"""End-to-end and unit tests for dnstake, covering the 15 acceptance rules.

Run from the tests directory:
    python -m unittest test_dnstake -v
"""

import copy
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dnstake.chain import find_cycle, normalize_chain
from dnstake.fingerprint import normalize_body
from dnstake.hosts import normalize_host
from dnstake.providers import claimable_account, match_provider
from dnstake.report import build_report, render_report

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OBSERVATIONS_PATH = os.path.join(REPO_ROOT, "demo", "observations.json")

DOMAIN_FIELDS = {
    "domain", "verdict", "risk", "provider", "claimable",
    "chain", "normalized_body", "matched_fingerprint", "evidence",
}


def load_observations():
    with open(OBSERVATIONS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


class FixtureTestCase(unittest.TestCase):
    """Rule 1: the demo fixture itself must have exactly 14 entries."""

    def test_fixture_has_14_domains(self):
        data = load_observations()
        self.assertEqual(len(data["domains"]), 14)
        for entry in data["domains"]:
            self.assertEqual(
                set(entry), {"domain", "ns", "cname_chain", "a", "http"}
            )


class ReportTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = load_observations()
        cls.report = build_report(cls.data)
        cls.by_domain = {r["domain"]: r for r in cls.report["domains"]}

    def test_rule2_verdict_and_risk_distribution(self):
        verdicts = [r["verdict"] for r in self.report["domains"]]
        self.assertEqual(verdicts.count("takeover"), 4)
        self.assertEqual(verdicts.count("dangling"), 2)
        self.assertEqual(verdicts.count("unresolved"), 1)
        self.assertEqual(verdicts.count("normal"), 7)
        risks = [r["risk"] for r in self.report["domains"]]
        self.assertEqual(risks.count("high"), 4)
        self.assertEqual(risks.count("medium"), 2)
        self.assertEqual(risks.count("unknown"), 1)
        self.assertEqual(risks.count("none"), 7)

    def test_rule3_takeover_domains_providers_claimables(self):
        expected = [
            ("docs.example.com", "github-pages", "user"),
            ("old.example.net", "github-pages", "user"),
            ("app.example.com", "heroku", "myapp"),
            ("shop.example.com", "shopify", "shop"),
        ]
        for domain, provider, claimable in expected:
            record = self.by_domain[domain]
            self.assertEqual(record["verdict"], "takeover", domain)
            self.assertEqual(record["risk"], "high", domain)
            self.assertEqual(record["provider"], provider, domain)
            self.assertEqual(record["claimable"], claimable, domain)

    def test_rule4_shared_account_counted_once(self):
        self.assertEqual(self.report["summary"]["accounts"], 3)

    def test_rule5_matched_fingerprints_verbatim(self):
        expected = {
            "docs.example.com": "there isn't a github pages site here.",
            "old.example.net": "there isn't a github pages site here.",
            "app.example.com": "no such app",
            "shop.example.com": "sorry, this shop is currently unavailable",
        }
        for domain, fingerprint in expected.items():
            self.assertEqual(
                self.by_domain[domain]["matched_fingerprint"], fingerprint, domain
            )

    def test_rule6_normalized_bodies_byte_exact(self):
        expected = {
            "docs.example.com": "there isn't a github pages site here.",
            "old.example.net": "there isn't a github pages site here.",
            "app.example.com": "no such app",
            "shop.example.com": "sorry, this shop is currently unavailable.",
            "decoy.example.com": "404 not found",
        }
        for domain, body in expected.items():
            self.assertEqual(self.by_domain[domain]["normalized_body"], body, domain)

    def test_rule7_chain_normalized_order_preserved(self):
        self.assertEqual(
            self.by_domain["old.example.net"]["chain"],
            ["cdn.example.net", "user.github.io"],
        )

    def test_rule8_heroku_503_accepted(self):
        record = self.by_domain["app.example.com"]
        self.assertEqual(record["verdict"], "takeover")
        self.assertEqual(record["provider"], "heroku")

    def test_rule9_platform_root_not_claimable(self):
        record = self.by_domain["root.example.com"]
        self.assertEqual(record["verdict"], "normal")
        self.assertEqual(record["risk"], "none")
        self.assertIsNone(record["provider"])
        self.assertIsNone(record["claimable"])

    def test_rule10_redirect_not_followed(self):
        record = self.by_domain["redir.example.com"]
        self.assertEqual(record["verdict"], "normal")
        self.assertIsNone(record["matched_fingerprint"])
        self.assertIn("https://github.com/login", record["evidence"])
        self.assertIn("302", record["evidence"])

    def test_rule11_normal_domains(self):
        expected_normal = [
            "live.example.com", "decoy.example.com", "weird.example.com",
            "busy.example.com", "root.example.com", "redir.example.com",
            "plain.example.com",
        ]
        for domain in expected_normal:
            record = self.by_domain[domain]
            self.assertEqual(record["verdict"], "normal", domain)
            self.assertEqual(record["risk"], "none", domain)
            self.assertIsNone(record["provider"], domain)
            self.assertIsNone(record["claimable"], domain)

    def test_rule12_dangling_domains_and_dead_ns_evidence(self):
        for domain in ("bare.example.com", "deadns.example.com"):
            record = self.by_domain[domain]
            self.assertEqual(record["verdict"], "dangling", domain)
            self.assertEqual(record["risk"], "medium", domain)
        self.assertIn(
            "ns1.dead.example.org", self.by_domain["deadns.example.com"]["evidence"]
        )

    def test_rule13_cycle_is_unresolved(self):
        record = self.by_domain["cycle-a.example.com"]
        self.assertEqual(record["verdict"], "unresolved")
        self.assertEqual(record["risk"], "unknown")
        self.assertIsNone(record["provider"])
        self.assertIsNone(record["claimable"])
        self.assertIsNone(record["matched_fingerprint"])

    def test_rule14_report_shape_and_summary(self):
        self.assertEqual(set(self.report), {"domains", "findings", "summary"})
        for record in self.report["domains"]:
            self.assertEqual(set(record), DOMAIN_FIELDS)
            self.assertTrue(record["evidence"])
            self.assertIn("NS:", record["evidence"])
            self.assertIn("CNAME chain:", record["evidence"])
            self.assertIn("A records:", record["evidence"])
            self.assertIn("HTTP:", record["evidence"])
        findings = self.report["findings"]
        self.assertEqual(len(findings), 7)
        for finding in findings:
            self.assertEqual(set(finding), {"domain", "verdict", "risk"})
        self.assertEqual(sum(1 for f in findings if f["verdict"] == "takeover"), 4)
        self.assertEqual(sum(1 for f in findings if f["verdict"] == "dangling"), 2)
        self.assertEqual(sum(1 for f in findings if f["verdict"] == "unresolved"), 1)
        summary = self.report["summary"]
        self.assertEqual(summary["domains"], 14)
        self.assertEqual(summary["takeover"], 4)
        self.assertEqual(summary["dangling"], 2)
        self.assertEqual(summary["unresolved"], 1)
        self.assertEqual(summary["normal"], 7)
        self.assertEqual(
            summary["by_provider"],
            {"github-pages": 2, "heroku": 1, "shopify": 1},
        )
        self.assertEqual(
            summary["by_risk"], {"high": 4, "medium": 2, "unknown": 1, "none": 7}
        )
        self.assertEqual(summary["accounts"], 3)

    def test_rule15_modified_input(self):
        data = copy.deepcopy(self.data)
        for entry in data["domains"]:
            if entry["domain"] == "docs.example.com":
                entry["http"]["body"] = "<p>404 Not Found</p>"
            if entry["domain"] == "old.example.net":
                entry["cname_chain"] = ["user.github.io"]
        report = build_report(data)
        summary = report["summary"]
        self.assertEqual(summary["takeover"], 3)
        self.assertEqual(summary["normal"], 8)
        self.assertEqual(summary["dangling"], 2)
        self.assertEqual(summary["unresolved"], 1)
        by_domain = {r["domain"]: r for r in report["domains"]}
        docs = by_domain["docs.example.com"]
        self.assertEqual(docs["verdict"], "normal")
        self.assertEqual(docs["normalized_body"], "404 not found")
        old = by_domain["old.example.net"]
        self.assertEqual(old["verdict"], "takeover")
        self.assertEqual(old["claimable"], "user")
        self.assertEqual(old["chain"], ["user.github.io"])

    def test_deterministic_output(self):
        first = render_report(build_report(self.data))
        second = render_report(build_report(self.data))
        self.assertEqual(first, second)


class NormalizationTestCase(unittest.TestCase):
    def test_normalize_host(self):
        self.assertEqual(normalize_host("  CDN.Example.NET. "), "cdn.example.net")
        self.assertEqual(normalize_host("User.GitHub.IO"), "user.github.io")
        self.assertEqual(normalize_host("example.com"), "example.com")

    def test_normalize_body_order_tags_before_entities(self):
        # &lt;b&gt; decodes to literal text "<b>", not a tag, so it survives.
        self.assertEqual(normalize_body("&lt;b&gt;hi&lt;/b&gt;"), "<b>hi</b>")
        self.assertEqual(normalize_body("<b>hi</b>"), "hi")

    def test_normalize_body_entities_whitespace_case(self):
        self.assertEqual(
            normalize_body("A&amp;B &quot;c&quot; &apos;d&apos;\t\n  E"),
            "a&b \"c\" 'd' e",
        )

    def test_provider_matching(self):
        self.assertEqual(match_provider("user.github.io")["id"], "github-pages")
        self.assertEqual(match_provider("github.io")["id"], "github-pages")
        self.assertIsNone(match_provider("web.example.org"))
        self.assertIsNone(match_provider("notgithub.io"))

    def test_claimable_account(self):
        self.assertEqual(claimable_account("user.github.io", "github.io"), "user")
        self.assertEqual(claimable_account("a.b.github.io", "github.io"), "b")
        self.assertIsNone(claimable_account("github.io", "github.io"))

    def test_cycle_detection(self):
        self.assertEqual(
            find_cycle("a.example.com", ["b.example.com", "a.example.com"]),
            "a.example.com",
        )
        self.assertEqual(find_cycle("a.example.com", ["b.example.com",
                                                      "b.example.com"]),
                         "b.example.com")
        self.assertIsNone(find_cycle("a.example.com", ["b.example.com"]))


if __name__ == "__main__":
    unittest.main()
