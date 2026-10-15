import unittest
from traceguard.engine import analyze_text, demo_log_text, parse_events, build_report

class EngineTests(unittest.TestCase):
    def test_demo_parses_events(self):
        result = analyze_text(demo_log_text())
        self.assertGreater(len(result["events"]), 0)
        self.assertGreater(len(result["findings"]), 0)

    def test_repeated_auth_failures_flagged(self):
        text = "\n".join([
            "2026-10-15 09:00:01 WARN 198.51.100.2 POST /login 401 authentication failed",
            "2026-10-15 09:00:02 WARN 198.51.100.2 POST /login 401 authentication failed",
            "2026-10-15 09:00:03 WARN 198.51.100.2 POST /login 401 authentication failed",
        ])
        result = analyze_text(text)
        self.assertTrue(any(f["title"] == "Repeated authentication failures" for f in result["findings"]))

    def test_empty_input(self):
        result = analyze_text("")
        self.assertEqual(result["events"], [])
        self.assertEqual(result["findings"], [])

    def test_report_has_limitations(self):
        report = build_report(analyze_text(demo_log_text()))
        self.assertIn("Limitations", report)

if __name__ == "__main__":
    unittest.main()
