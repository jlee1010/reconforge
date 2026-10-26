import unittest
from reconforge import parse_ports, markdown_report

class PortParserTests(unittest.TestCase):
    def test_single_and_range(self):
        self.assertEqual(parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])

    def test_deduplicates_and_sorts(self):
        self.assertEqual(parse_ports("80,22,80"), [22, 80])

    def test_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_rejects_reversed_range(self):
        with self.assertRaises(ValueError):
            parse_ports("90-80")

    def test_rejects_too_many_ports(self):
        with self.assertRaises(ValueError):
            parse_ports("1-5000")

class ReportTests(unittest.TestCase):
    def test_empty_report_has_context(self):
        report = {
            "target": "127.0.0.1", "resolved_ip": "127.0.0.1",
            "started_utc": "now", "completed_utc": "later",
            "method": "TCP connect scan",
            "summary": {"ports_open": 0, "ports_with_banners": 0},
            "open_ports": [],
        }
        text = markdown_report(report)
        self.assertIn("No open TCP ports", text)
        self.assertIn("not proof of a vulnerability", text)

if __name__ == "__main__":
    unittest.main()
