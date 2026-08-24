"""Unit tests for analyze_url() scoring in app.py.

Covers each heuristic (fires on a crafted URL, stays silent on clean ones),
exact threshold boundaries (40 suspicious, 70 phishing), the risk cap at 100,
band field mapping, and the in-memory history semantics.

Run: python3 -m unittest discover -s tests -v   (or pytest)

Note: app.py is loaded by file path because the repo also ships an ``app/``
package (the Flask-SQLAlchemy factory), which would shadow ``import app``.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_APP_PATH = Path(__file__).resolve().parent.parent / "app.py"
_spec = importlib.util.spec_from_file_location("threatlens_app", _APP_PATH)
assert _spec is not None and _spec.loader is not None  # static path, always loadable
_app = importlib.util.module_from_spec(_spec)
sys.modules["threatlens_app"] = _app
_spec.loader.exec_module(_app)

analyze_url = _app.analyze_url


class AnalyzeURLTestCase(unittest.TestCase):
    """Shared behavior checks; history dicts reset before every test."""

    def setUp(self):
        _app.checked_links.clear()
        _app.checked_domains.clear()

    # ---- baseline -------------------------------------------------------

    def test_clean_https_url_is_baseline_safe(self):
        r = analyze_url("https://example.com/")
        self.assertEqual(r["risk"], 10)
        self.assertEqual(r["indicators"], [])
        self.assertEqual(r["threat_type"], "Safe")
        self.assertEqual(r["page_intent"], "Normal Browsing")
        self.assertEqual(r["explanation"], "")
        self.assertEqual(r["action"], "Link appears safe.")

    # ---- individual heuristics: fire + stay silent ----------------------

    def test_no_https_fires_and_silent_on_https(self):
        r = analyze_url("http://example.com/path")
        self.assertIn("No HTTPS Encryption", r["indicators"])
        self.assertEqual(r["risk"], 30)  # 10 base + 20
        clean = analyze_url("https://example.com/path")
        self.assertNotIn("No HTTPS Encryption", clean["indicators"])

    def test_shortened_url_fires_and_stays_silent_without_shortener(self):
        r = analyze_url("https://example.com/go?target=https://bit.ly/abc")
        self.assertIn("Shortened URL", r["indicators"])
        self.assertEqual(r["risk"], 40)  # 10 + 30
        clean = analyze_url("https://example.com/go?target=https://long.example.org/abc")
        self.assertNotIn("Shortened URL", clean["indicators"])
        self.assertEqual(clean["risk"], 10)

    def test_login_keyword_fires_but_alone_keeps_safe_band(self):
        r = analyze_url("https://example.com/login")
        self.assertIn("Login / Verification Keyword", r["indicators"])
        self.assertEqual(r["risk"], 35)  # 10 + 25 -> below the 40 band
        self.assertEqual(r["threat_type"], "Safe")
        clean = analyze_url("https://example.com/signup")
        self.assertNotIn("Login / Verification Keyword", clean["indicators"])

    def test_ip_based_url_fires_and_stays_silent_on_named_host(self):
        r = analyze_url("https://192.168.1.1/status")
        self.assertIn("IP-based URL", r["indicators"])
        self.assertEqual(r["risk"], 40)  # 10 + 30
        clean = analyze_url("https://example.com/status")
        self.assertNotIn("IP-based URL", clean["indicators"])

    def test_all_four_indicators_fire_in_source_order(self):
        r = analyze_url("http://192.168.1.1/login?u=https://bit.ly/x")
        self.assertEqual(
            r["indicators"],
            [
                "No HTTPS Encryption",
                "Shortened URL",
                "Login / Verification Keyword",
                "IP-based URL",
            ],
        )

    # ---- exact threshold boundaries -------------------------------------

    def test_risk_39_band_boundary_is_inclusive_at_40(self):
        # Highest reachable score below 40: https + keyword = 35 -> Safe.
        r = analyze_url("https://example.com/login")
        self.assertEqual((r["risk"], r["threat_type"]), (35, "Safe"))
        # 40 exactly (https + IP) -> Suspicious, inclusive lower bound.
        r = analyze_url("https://192.168.1.1/")
        self.assertEqual((r["risk"], r["threat_type"]), (40, "Suspicious Link"))

    def test_risk_70_phishing_boundary_is_inclusive(self):
        # 70 exactly (https + IP host + shortener in query) -> Phishing.
        r = analyze_url("https://192.168.1.1/?r=tinyurl.com/x")
        self.assertEqual((r["risk"], r["threat_type"]), (70, "Credential Phishing"))
        # 65 (https + keyword + shortener) stays one step below -> Suspicious.
        r = analyze_url("https://example.com/login?u=https://bit.ly/x")
        self.assertEqual((r["risk"], r["threat_type"]), (65, "Suspicious Link"))

    def test_risk_is_capped_at_100(self):
        # 10 + 20 + 30 + 25 + 30 = 115 raw.
        r = analyze_url("http://192.168.1.1/login?u=https://bit.ly/x")
        self.assertEqual(r["risk"], 100)
        self.assertEqual(r["threat_type"], "Credential Phishing")

    # ---- band field mapping ----------------------------------------------

    def test_suspicious_band_fields(self):
        r = analyze_url("https://192.168.1.1/")
        self.assertEqual(r["page_intent"], "Redirection / Verification")
        self.assertEqual(r["explanation"], "This link shows suspicious characteristics.")
        self.assertEqual(r["action"], "Proceed with caution.")

    def test_phishing_band_fields(self):
        r = analyze_url("https://192.168.1.1/?r=tinyurl.com/x")
        self.assertEqual(r["page_intent"], "Login / Account Verification")
        self.assertEqual(
            r["explanation"], "This link uses patterns commonly found in phishing attacks."
        )
        self.assertEqual(r["action"], "Do NOT click the link.")

    # ---- in-memory history semantics --------------------------------------

    def test_first_analysis_reports_no_history(self):
        r = analyze_url("https://example.com/")
        self.assertFalse(r["link_seen_before"])
        self.assertFalse(r["domain_seen_before"])
        self.assertIsNone(r["previous_link_result"])
        self.assertIsNone(r["previous_domain_result"])

    def test_repeated_link_is_flagged_with_previous_result(self):
        first = analyze_url("https://example.com/")
        second = analyze_url("https://example.com/")
        self.assertTrue(second["link_seen_before"])
        self.assertTrue(second["domain_seen_before"])
        self.assertEqual(second["previous_link_result"], first["threat_type"])

    def test_domain_history_spans_different_paths(self):
        analyze_url("https://example.com/one")
        second = analyze_url("https://example.com/two")
        self.assertFalse(second["link_seen_before"])  # new link
        self.assertTrue(second["domain_seen_before"])  # known domain
        self.assertIsNone(second["previous_link_result"])
        self.assertEqual(second["previous_domain_result"], "Safe")


if __name__ == "__main__":
    unittest.main()
