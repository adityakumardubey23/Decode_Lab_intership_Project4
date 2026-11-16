import unittest

from sysaudit.models import AuditReport, CheckResult


class AuditModelTests(unittest.TestCase):
    def test_result_serializes(self):
        result = CheckResult("FW-01", "Host firewall", "PASS", "Enabled", "Keep enabled")
        self.assertEqual(result.to_dict()["status"], "PASS")

    def test_report_contains_results(self):
        result = CheckResult("FW-01", "Host firewall", "UNKNOWN", "Not checked", "Verify manually")
        report = AuditReport.create("test-host", "Test OS", [result])
        payload = report.to_dict()
        self.assertEqual(payload["hostname"], "test-host")
        self.assertEqual(payload["results"][0]["check_id"], "FW-01")
        self.assertTrue(payload["generated_at"])


if __name__ == "__main__":
    unittest.main()
