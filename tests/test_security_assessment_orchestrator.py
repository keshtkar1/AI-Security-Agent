import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.security_assessment_orchestrator import SecurityAssessmentOrchestrator


class _FakeZapService:
    def get_passive_scan_status(self):
        return {"records_remaining": 0}


class SecurityAssessmentOrchestratorHardeningTests(unittest.TestCase):

    def test_partial_crawl_results_are_enough_for_passive_scan(self):
        orchestrator = SecurityAssessmentOrchestrator.__new__(
            SecurityAssessmentOrchestrator
        )
        orchestrator.zap_service = _FakeZapService()
        orchestrator.assessments = {}
        assessment = {
            "assessment_id": "assessment-1",
            "status": "crawl_completed_with_errors",
            "applications": ["app_a", "app_b"],
            "crawl_results": {"app_a": {"application": "app_a"}},
        }
        orchestrator.get_assessment = lambda assessment_id: assessment
        orchestrator._save_assessments = lambda: None
        orchestrator._now = lambda: "2026-11-22T00:00:00+00:00"

        result = orchestrator.wait_for_passive_scan("assessment-1")

        self.assertEqual(result["status"], "passive_scan_completed")
        self.assertEqual(assessment["status"], "passive_scan_completed")

    def test_passive_scan_rejects_when_no_valid_crawl_result_exists(self):
        orchestrator = SecurityAssessmentOrchestrator.__new__(
            SecurityAssessmentOrchestrator
        )
        orchestrator.zap_service = _FakeZapService()
        assessment = {
            "assessment_id": "assessment-2",
            "status": "crawl_completed_with_errors",
            "applications": ["app_a", "app_b"],
            "crawl_results": {"app_a": None, "other_app": {"application": "other_app"}},
        }
        orchestrator.get_assessment = lambda assessment_id: assessment

        with self.assertRaisesRegex(ValueError, "At least one valid"):
            orchestrator.wait_for_passive_scan("assessment-2")

    def test_corrupt_application_file_does_not_discard_other_results(self):
        orchestrator = SecurityAssessmentOrchestrator.__new__(
            SecurityAssessmentOrchestrator
        )
        orchestrator.project_directory = Path(tempfile.mkdtemp())
        orchestrator.assessments = {}
        assessment = {
            "assessment_id": "assessment-3",
            "applications": ["app_good", "app_broken"],
        }
        orchestrator.get_assessment = lambda assessment_id: assessment
        orchestrator._save_assessments = lambda: None
        orchestrator._now = lambda: "2026-11-22T00:00:00+00:00"
        orchestrator._build_assessment_coverage = lambda *args: None

        crawl_directory = (
            orchestrator.project_directory / "data" / "crawl_results"
        )
        crawl_directory.mkdir(parents=True)
        (crawl_directory / "app_good_crawl.json").write_text(
            json.dumps({"application": "app_good", "pages": []}),
            encoding="utf-8",
        )
        (crawl_directory / "app_broken_crawl.json").write_text(
            '{"application": "app_broken",',
            encoding="utf-8",
        )

        browser_auth = types.ModuleType("browser_auth")
        browser_auth.main = lambda **kwargs: {"completed": True}

        with patch.dict("sys.modules", {"browser_auth": browser_auth}):
            orchestrator._run_playwright_crawl(
                "assessment-3", ["app_good", "app_broken"]
            )

        self.assertIn("app_good", assessment["crawl_results"])
        self.assertNotIn("app_broken", assessment["crawl_results"])
        self.assertEqual(
            assessment["status"], "crawl_completed_with_errors"
        )
        self.assertEqual(
            assessment["crawl_errors"][0]["application"], "app_broken"
        )
        self.assertIn(
            "JSONDecodeError", assessment["crawl_errors"][0]["error"]
        )


if __name__ == "__main__":
    unittest.main()
