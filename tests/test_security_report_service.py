import importlib.util
import tempfile
import unittest
from pathlib import Path

try:
    from app.services.security_report_service import SecurityReportService
except ModuleNotFoundError:
    MODULE_PATH = Path(__file__).with_name("security_report_service_hardened.py")
    spec = importlib.util.spec_from_file_location(
        "security_report_service_hardened",
        MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    SecurityReportService = module.SecurityReportService


class SecurityReportServiceHardeningTests(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.service = SecurityReportService(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sanitize_text_masks_apex_session_parameter(self):
        value = "POST /ords/r/app/page p_session=SECRET123&item=visible"
        result = self.service._sanitize_text(value)
        self.assertIn("p_session=[MASKED]", result)
        self.assertNotIn("SECRET123", result)
        self.assertIn("item=visible", result)

    def test_sanitize_url_masks_sensitive_values_in_query_path_and_fragment(self):
        value = (
            "https://example.test/ords/r/app/login;p_session=PATHSECRET"
            "?p_token=QUERYSECRET&item=visible#session=FRAGMENTSECRET"
        )
        result = self.service._sanitize_url(value)
        for secret in ("PATHSECRET", "QUERYSECRET", "FRAGMENTSECRET"):
            self.assertNotIn(secret, result)
        self.assertIn("[MASKED]", result)
        self.assertIn("item=visible", result)

    def test_sanitize_text_masks_auth_and_path_parameter_values(self):
        value = "/ords/r/app/p_session=PATHSECRET p_auth=AUTHSECRET"
        result = self.service._sanitize_text(value)
        self.assertNotIn("PATHSECRET", result)
        self.assertNotIn("AUTHSECRET", result)

    def test_sanitize_url_masks_userinfo(self):
        result = self.service._sanitize_url(
            "https://user:password123@example.test:8443/path"
        )
        self.assertNotIn("user", result)
        self.assertNotIn("password123", result)
        self.assertIn("[MASKED]@example.test:8443", result)

    def test_load_crawl_result_rejects_path_traversal_identifier(self):
        result = self.service._load_crawl_result({}, "../../outside")
        self.assertEqual(result, {})

    def test_template_replacement_does_not_reprocess_inserted_tokens(self):
        result = self.service._replace_template_tokens(
            "A=__A__; B=__B__",
            {"__A__": "__B__", "__B__": "safe"}
        )
        self.assertEqual(result, "A=__B__; B=safe")

    def test_chart_keeps_other_risk_separate_from_informational(self):
        finding = {"alert": "Unknown severity", "risk": "unclassified", "url": "https://example.test/"}
        chart = self.service._build_chart_data([{
            "risk_summary": {
                "high": 0, "medium": 0, "low": 0,
                "informational": 0, "other": 1
            },
            "total_findings": 1,
            "pages": [{"page_name": "Home", "findings": [finding]}]
        }])
        self.assertEqual(chart["totals"]["o"], 1)
        self.assertEqual(chart["totals"]["i"], 0)
        self.assertEqual(chart["total"], 1)
        self.assertEqual(chart["F"][0][2], "o")


if __name__ == "__main__":
    unittest.main(verbosity=2)
