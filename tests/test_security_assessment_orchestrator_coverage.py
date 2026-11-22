import unittest

from app.services.security_assessment_orchestrator import SecurityAssessmentOrchestrator
from app.services.security_coverage_service import SecurityCoverageService


class SecurityAssessmentCoverageIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.orchestrator = SecurityAssessmentOrchestrator.__new__(
            SecurityAssessmentOrchestrator
        )
        self.orchestrator.coverage_service = SecurityCoverageService()

    def test_complete_coverage_is_compact_and_weighted(self):
        assessment = {}
        applications = ["app_a", "app_b"]
        crawl_results = {
            "app_a": {
                "application": "app_a",
                "total_unique_configured_pages": 2,
                "total_attempted_urls": 2,
                "page_details": [
                    {"page_status": "visited", "elements": [{"tag": "button"}]},
                    {"page_status": "visited", "elements": []},
                ],
            },
            "app_b": {
                "application": "app_b",
                "total_unique_configured_pages": 8,
                "total_attempted_urls": 1,
                "page_details": [{"page_status": "visited"}],
            },
        }
        self.orchestrator._build_assessment_coverage(
            assessment, applications, crawl_results
        )
        self.assertEqual(assessment["coverage_status"], "complete")
        self.assertEqual(
            assessment["coverage_summary"]["summary"]["page_coverage_percent"], 30.0
        )
        self.assertEqual(
            assessment["coverage_by_application"]["app_a"]["summary"]["visited_pages"], 2
        )
        self.assertNotIn(
            "page_details",
            assessment["coverage_by_application"]["app_a"]["page_coverage"],
        )
        self.assertEqual(assessment["coverage_missing_applications"], [])

    def test_missing_application_produces_partial_coverage(self):
        assessment = {}
        crawl_results = {
            "app_a": {
                "application": "app_a",
                "total_unique_configured_pages": 1,
                "total_attempted_urls": 1,
                "page_details": [{"page_status": "visited"}],
            }
        }
        self.orchestrator._build_assessment_coverage(
            assessment, ["app_a", "app_b"], crawl_results
        )
        self.assertEqual(assessment["coverage_status"], "partial")
        self.assertEqual(assessment["coverage_missing_applications"], ["app_b"])
        self.assertEqual(
            assessment["coverage_summary"]["summary"]["page_coverage_percent"], 100.0
        )

    def test_no_valid_crawl_results_produces_unavailable_coverage(self):
        assessment = {}
        self.orchestrator._build_assessment_coverage(
            assessment, ["app_a"], {}
        )
        self.assertEqual(assessment["coverage_status"], "unavailable")
        self.assertIsNone(assessment["coverage_summary"])
        self.assertEqual(assessment["coverage_missing_applications"], ["app_a"])


if __name__ == "__main__":
    unittest.main()
