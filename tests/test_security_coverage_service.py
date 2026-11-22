import unittest

from app.services.security_coverage_service import SecurityCoverageService


class SecurityCoverageServiceTests(unittest.TestCase):

    def setUp(self):
        self.service = SecurityCoverageService()

    def test_page_coverage_uses_actual_browser_auth_page_statuses(self):
        crawl = {
            "application": "sample",
            "total_configured_pages": 6,
            "total_enabled_pages": 5,
            "total_unique_configured_pages": 5,
            "total_attempted_urls": 3,
            "total_pending_urls": 2,
            "attempted_urls": ["/a", "/b", "/c"],
            "visited_urls": ["/a"],
            "unavailable_urls": ["/b"],
            "configured_pages": [{"page_id": "a"}, {"page_id": "b"}],
            "disabled_pages": [{"page_id": "disabled"}],
            "limit_skipped_pages": [{"page_id": "pending"}],
            "duplicate_configured_pages": [],
            "page_details": [
                {"page_status": "visited", "elements": [], "forms": []},
                {"page_status": "unavailable", "elements": [], "forms": []},
                {"page_status": "error"},
            ],
        }

        report = self.service.build_report(crawl)

        self.assertEqual(report["summary"]["page_coverage_percent"], 20.0)
        self.assertEqual(report["page_coverage"]["attempted"], 3)
        self.assertEqual(report["page_coverage"]["visited"], 1)
        self.assertEqual(report["page_coverage"]["unavailable"], 1)
        self.assertEqual(report["page_coverage"]["error"], 1)
        self.assertEqual(report["page_coverage"]["pending_or_not_attempted"], 2)
        self.assertEqual(report["page_coverage"]["disabled_out_of_scope"], 1)

    def test_actual_browser_auth_element_form_and_network_schema(self):
        crawl = {
            "application": "sample",
            "total_unique_configured_pages": 1,
            "total_attempted_urls": 1,
            "page_details": [{
                "page_status": "visited",
                "elements": [
                    {
                        "tag": "button",
                        "type": "submit",
                        "id": "save",
                        "name": "",
                        "role": "",
                        "text": "Save",
                        "attributes": {},
                        "disabled": False,
                    },
                ],
                "forms": [
                    {
                        "action": "http://example.test/save",
                        "method": "POST",
                        "id": "form1",
                        "name": "",
                    },
                ],
                "javascript_candidates": ["/ords/x"],
                "frames_inspected": 1,
                "frame_errors": [],
            }],
            "observed_internal_links": {"page1": ["/a", "/b"]},
            "network_summary": {
                "total_requests": 2,
                "document_requests": 1,
                "xhr_requests": 1,
                "fetch_requests": 0,
                "failed_requests": 0,
            },
            "network_requests": [
                {
                    "method": "GET",
                    "url": "http://example.test/page",
                    "resource_type": "document",
                    "status": 200,
                    "failed": False,
                },
                {
                    "method": "POST",
                    "url": "http://example.test/save",
                    "resource_type": "xhr",
                    "status": 500,
                    "failed": False,
                },
            ],
        }

        report = self.service.build_report(crawl)

        self.assertEqual(report["summary"]["interactive_elements_observed"], 1)
        self.assertEqual(report["summary"]["forms_observed"], 1)
        self.assertEqual(report["summary"]["network_requests_observed"], 2)
        self.assertEqual(report["component_coverage"]["internal_links_observed"], 2)
        self.assertEqual(
            report["network_coverage"]["requests_by_status_class"],
            {"2xx": 1, "5xx": 1},
        )
        self.assertFalse(report["measurement"]["security_testing_claim"])
        self.assertIsNone(report["component_coverage"]["form_input_fields"]["count"])

    def test_masked_network_urls_are_not_deduplicated_again(self):
        crawl = {
            "total_unique_configured_pages": 1,
            "total_attempted_urls": 1,
            "page_details": [{"page_status": "visited"}],
            "network_requests": [
                {
                    "method": "GET",
                    "url": "http://example.test/page?session=***",
                    "resource_type": "document",
                    "status": 200,
                    "failed": False,
                },
                {
                    "method": "GET",
                    "url": "http://example.test/page?session=***",
                    "resource_type": "document",
                    "status": 302,
                    "failed": False,
                },
            ],
        }

        report = self.service.build_report(crawl)
        self.assertEqual(report["summary"]["network_requests_observed"], 2)

    def test_network_summary_fallback_when_request_records_are_absent(self):
        crawl = {
            "total_unique_configured_pages": 0,
            "network_summary": {
                "total_requests": 7,
                "document_requests": 2,
                "xhr_requests": 3,
                "fetch_requests": 2,
                "failed_requests": 1,
            },
            "network_requests": [],
        }

        report = self.service.build_report(crawl)
        self.assertEqual(report["summary"]["network_requests_observed"], 7)
        self.assertEqual(report["summary"]["failed_network_requests"], 1)
        self.assertEqual(
            report["network_coverage"]["evidence_status"],
            "aggregate_summary_only",
        )

    def test_zero_page_denominator_has_no_percentage(self):
        report = self.service.build_report({"application": "empty"})
        self.assertIsNone(report["summary"]["page_coverage_percent"])
        self.assertIsNone(report["summary"]["page_attempt_percent"])

    def test_overall_coverage_uses_weighted_totals(self):
        results = [
            {
                "application": "a",
                "total_unique_configured_pages": 2,
                "total_attempted_urls": 2,
                "page_details": [
                    {"page_status": "visited"},
                    {"page_status": "visited"},
                ],
            },
            {
                "application": "b",
                "total_unique_configured_pages": 8,
                "total_attempted_urls": 1,
                "page_details": [{"page_status": "visited"}],
            },
        ]

        report = self.service.build_overall_report(results)
        self.assertEqual(report["summary"]["page_coverage_percent"], 30.0)
        self.assertEqual(report["summary"]["page_attempt_percent"], 30.0)


if __name__ == "__main__":
    unittest.main()