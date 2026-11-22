import json
import os
import tempfile
import time
import threading

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse
from uuid import uuid4

from app.services.zap_service import zap_service


class SecurityAssessmentOrchestrator:
    """
    Coordinates security assessments across authorized Oracle APEX applications.
    Persists assessment data to a local JSON file.
    """

    def __init__(self, zap_service):

        self.zap_service = zap_service
        self.assessments = {}
        self._crawl_threads = {}

        # Persistent storage
        self.project_directory = Path(__file__).resolve().parents[2]
        self.data_directory = self.project_directory / "data"
        self.storage_file = self.data_directory / "assessments.json"

        self.data_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self._load_assessments()

    # =================================
    # Time
    # =================================

    def _now(self):
        return datetime.now(timezone.utc).isoformat()

    # =================================
    # Load Persistent Assessments
    # =================================

    def _load_assessments(self):

        if not self.storage_file.exists():
            self.assessments = {}
            return

        try:

            with self.storage_file.open(
                "r",
                encoding="utf-8"
            ) as file:

                data = json.load(file)

            if not isinstance(data, dict):
                raise ValueError(
                    "Invalid assessment storage format"
                )

            for assessment_id, assessment in data.items():

                if not isinstance(assessment, dict):
                    raise ValueError(
                        "Invalid assessment record"
                    )

                if assessment.get("assessment_id") != assessment_id:
                    raise ValueError(
                        "Assessment ID mismatch in storage"
                    )

            self.assessments = data

        except Exception as error:

            raise RuntimeError(
                "Unable to load persistent assessments"
            ) from error

    # =================================
    # Save Persistent Assessments
    # =================================

    def _save_assessments(self):

        temporary_path = None

        try:

            file_descriptor, temporary_path = tempfile.mkstemp(
                prefix="assessments_",
                suffix=".tmp",
                dir=str(self.data_directory)
            )

            with os.fdopen(
                file_descriptor,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.assessments,
                    file,
                    ensure_ascii=False,
                    indent=2
                )

                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_path,
                self.storage_file
            )

            temporary_path = None

        except Exception as error:

            raise RuntimeError(
                "Unable to save persistent assessments"
            ) from error

        finally:

            if (
                temporary_path
                and os.path.exists(temporary_path)
            ):

                try:
                    os.remove(temporary_path)
                except OSError:
                    pass

    # =================================
    # Save Single Assessment
    # =================================

    def save_assessment(self, assessment):

        # Accept either an assessment ID or the assessment dictionary.
        if isinstance(assessment, str):

            assessment_id = assessment.strip()

            if not assessment_id:
                raise ValueError("Invalid assessment ID")

            assessment = self.assessments.get(assessment_id)

            if assessment is None:
                raise ValueError("Assessment not found")

        elif isinstance(assessment, dict):

            assessment_id = assessment.get("assessment_id")

            if (
                not isinstance(assessment_id, str)
                or not assessment_id.strip()
            ):
                raise ValueError("Invalid assessment ID")

            if assessment_id not in self.assessments:
                raise ValueError("Assessment not found")

            self.assessments[assessment_id] = assessment

        else:
            raise ValueError("Invalid assessment data")

        self._save_assessments()

        return assessment

    # =================================
    # Create Assessment
    # =================================

    def create_assessment(self, applications):

        if not isinstance(applications, list) or not applications:
            raise ValueError(
                "Applications must be a non-empty list"
            )

        if not all(
            isinstance(app, str) and app.strip()
            for app in applications
        ):
            raise ValueError(
                "Every application must have a valid name"
            )

        requested_apps = {
            app.strip()
            for app in applications
        }

        unauthorized_apps = (
            requested_apps - self.zap_service.allowed_apps
        )

        if unauthorized_apps:
            raise ValueError(
                "Unauthorized applications: "
                + ", ".join(sorted(unauthorized_apps))
            )

        now = self._now()
        assessment_id = str(uuid4())

        assessment = {
            "assessment_id": assessment_id,
            "status": "created",
            "applications": sorted(requested_apps),
            "created_at": now,
            "updated_at": now,
            "results": [],
            "findings_by_application": {},
            "spider_results": {},
            "crawl_results": {},
            "crawl_summary": {},
            "crawl_errors": [],
            "collection_errors": []
        }

        self.assessments[assessment_id] = assessment

        self._save_assessments()

        return assessment

    # =================================
    # Get Assessment
    # =================================

    def get_assessment(self, assessment_id):

        assessment = self.assessments.get(assessment_id)

        if assessment is None:
            raise ValueError("Assessment not found")

        return assessment

    # =================================
    # List Assessments
    # =================================

    def list_assessments(self):

        return list(self.assessments.values())

    # =================================
    # Validate Alert URL Scope
    # =================================

    def _is_alert_in_application_scope(
        self,
        alert,
        target_url
    ):

        if not isinstance(alert, dict):
            return False

        alert_url = alert.get("url")

        if (
            not isinstance(alert_url, str)
            or not alert_url.strip()
        ):
            return False

        try:

            parsed_alert = urlparse(alert_url)
            parsed_target = urlparse(target_url)

            if (
                parsed_alert.scheme.lower()
                != parsed_target.scheme.lower()

                or not parsed_alert.hostname

                or parsed_alert.hostname.lower()
                != parsed_target.hostname.lower()

                or parsed_alert.port != parsed_target.port

                or parsed_alert.username is not None

                or parsed_alert.password is not None
            ):
                return False

        except ValueError:
            return False

        if (
            "\\" in parsed_alert.path
            or "%" in parsed_alert.path
        ):
            return False

        application_path = parsed_target.path.rstrip("/")
        alert_path = parsed_alert.path.rstrip("/")

        return (
            alert_path == application_path
            or alert_path.startswith(application_path + "/")
        )

    # =================================
    # Playwright Crawl Worker
    # =================================

    def start_playwright_crawl(self, assessment_id):

        assessment = self.get_assessment(assessment_id)

        if assessment.get("status") != "created":
            raise ValueError(
                "Playwright crawl can only start from created status"
            )

        thread = getattr(self, "_crawl_threads", {}).get(assessment_id)

        if thread is not None and thread.is_alive():
            raise ValueError("A crawl is already running for this assessment")

        if not hasattr(self, "_crawl_threads"):
            self._crawl_threads = {}

        assessment["status"] = "crawl_starting"
        assessment["crawl_results"] = {}
        assessment["crawl_summary"] = {}
        assessment["crawl_errors"] = []
        assessment["spider_results"] = {}
        assessment["collection_errors"] = []
        assessment["updated_at"] = self._now()
        self._save_assessments()

        thread = threading.Thread(
            target=self._run_playwright_crawl,
            args=(assessment_id, list(assessment["applications"])),
            name=f"playwright-crawl-{assessment_id}",
            daemon=True
        )

        self._crawl_threads[assessment_id] = thread
        thread.start()

        return {
            "assessment_id": assessment_id,
            "status": "crawl_starting",
            "applications": assessment["applications"],
            "message": "مرورگر در پس‌زمینه اجرا می‌شود؛ ورود، CAPTCHA و OTP را در پنجره مرورگر/ترمینال تکمیل کنید."
        }

    def _run_playwright_crawl(self, assessment_id, applications):

        assessment = self.get_assessment(assessment_id)

        try:
            assessment["status"] = "crawl_running"
            assessment["updated_at"] = self._now()
            self._save_assessments()

            # Import lazily: browser_auth reads its .env configuration at import time.
            import browser_auth

            summary = browser_auth.main(
                application_ids=applications,
                wait_for_exit=True
            )

            crawl_directory = (
                self.project_directory
                / "data"
                / "crawl_results"
            )

            crawl_results = {}
            crawl_errors = []

            for application in applications:
                result_file = crawl_directory / f"{application}_crawl.json"

                if not result_file.is_file():
                    crawl_errors.append({
                        "application": application,
                        "error": "Playwright crawl result file was not created"
                    })
                    continue

                with result_file.open("r", encoding="utf-8") as file:
                    result = json.load(file)

                if (
                    not isinstance(result, dict)
                    or result.get("application") != application
                ):
                    crawl_errors.append({
                        "application": application,
                        "error": "Invalid Playwright crawl result"
                    })
                    continue

                crawl_results[application] = result

                if result.get("termination_reason") == "application_failed":
                    crawl_errors.append({
                        "application": application,
                        "error": "Playwright could not complete this application's crawl"
                    })

            assessment["crawl_results"] = crawl_results
            assessment["crawl_summary"] = (
                summary if isinstance(summary, dict) else {}
            )
            assessment["crawl_errors"] = crawl_errors

            all_results_present = (
                len(crawl_results) == len(applications)
            )

            assessment["status"] = (
                "crawl_completed"
                if all_results_present and not crawl_errors
                else "crawl_completed_with_errors"
            )

        except Exception as error:

            assessment["status"] = "crawl_failed"
            assessment["crawl_errors"] = [{
                "application": application,
                "error": (
                    "Playwright crawler failed: "
                    + type(error).__name__
                )
            } for application in applications]

        finally:
            assessment["updated_at"] = self._now()
            self._save_assessments()

    # =================================
    # Wait For Passive Scan
    # =================================

    def run_spider_assessment(
        self,
        assessment_id,
        timeout=1800,
        poll_interval=5
    ):

        assessment = self.get_assessment(assessment_id)

        if assessment["status"] != "created":
            raise ValueError(
                "Spider assessment can only start from created status"
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or timeout <= 0
        ):
            raise ValueError("Invalid Spider timeout")

        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, int)
            or poll_interval <= 0
        ):
            raise ValueError("Invalid poll interval")

        assessment["status"] = "spider_running"
        assessment["updated_at"] = self._now()

        assessment["spider_results"] = {}
        assessment["collection_errors"] = []

        self._save_assessments()

        spider_results = assessment["spider_results"]
        collection_errors = assessment["collection_errors"]

        for application in assessment["applications"]:

            scan_id = None

            try:

                target_url = self.zap_service.get_application_url(
                    application
                )

                # Start Spider for the authorized application.
                spider_result = self.zap_service.start_spider(
                    target_url
                )

                if not isinstance(spider_result, dict):
                    raise RuntimeError(
                        "Invalid Spider response"
                    )

                if spider_result.get("target") != target_url:
                    raise RuntimeError(
                        "Spider target mismatch"
                    )

                scan_id = spider_result.get("scan_id")

                if (
                    scan_id is None
                    or not str(scan_id).strip()
                ):
                    raise RuntimeError(
                        "ZAP did not return a Spider scan ID"
                    )

                scan_id = str(scan_id)
                started_at = time.monotonic()

                while True:

                    status_result = (
                        self.zap_service.get_spider_status(
                            scan_id
                        )
                    )

                    if not isinstance(status_result, dict):
                        raise RuntimeError(
                            "Invalid Spider status response"
                        )

                    if status_result.get("scan_id") != scan_id:
                        raise RuntimeError(
                            "Spider scan ID mismatch"
                        )

                    try:

                        progress = int(
                            status_result.get("progress")
                        )

                    except (TypeError, ValueError):

                        raise RuntimeError(
                            "Invalid Spider progress value"
                        )

                    if progress < 0 or progress > 100:
                        raise RuntimeError(
                            "Spider returned invalid progress"
                        )

                    if progress == 100:
                        break

                    if (
                        time.monotonic() - started_at
                        >= timeout
                    ):
                        raise TimeoutError(
                            "Spider execution timed out"
                        )

                    time.sleep(poll_interval)

                spider_results[application] = {
                    "status": "completed",
                    "scan_id": scan_id,
                    "progress": 100
                }

            except Exception:

                spider_results[application] = {
                    "status": "failed",
                    "scan_id": scan_id,
                    "progress": None
                }

                collection_errors.append({
                    "application": application,
                    "error": (
                        "Spider execution failed or timed out"
                    )
                })

            # Persist each application's result immediately.
            assessment["updated_at"] = self._now()
            self._save_assessments()

        assessment["status"] = (
            "spider_completed"
            if not collection_errors
            else "spider_completed_with_errors"
        )

        assessment["updated_at"] = self._now()

        self._save_assessments()

        return {
            "assessment_id": assessment_id,
            "status": assessment["status"],
            "spider_results": spider_results,
            "collection_errors": collection_errors
        }

    # =================================
    # Wait For Passive Scan
    # =================================

    def wait_for_passive_scan(
        self,
        assessment_id,
        timeout=1800,
        poll_interval=5
    ):

        assessment = self.get_assessment(assessment_id)

        if assessment["status"] not in (
            "crawl_completed",
            "crawl_completed_with_errors"
        ):
            raise ValueError(
                "Playwright crawl must complete before passive scanning"
            )

        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, int)
            or timeout <= 0
        ):
            raise ValueError(
                "Invalid passive scan timeout"
            )

        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, int)
            or poll_interval <= 0
        ):
            raise ValueError(
                "Invalid passive scan poll interval"
            )

        started_at = time.monotonic()

        while True:

            status_result = (
                self.zap_service.get_passive_scan_status()
            )

            if not isinstance(status_result, dict):
                raise RuntimeError(
                    "Invalid passive scan response"
                )

            try:

                remaining = int(
                    status_result.get("records_remaining")
                )

            except (TypeError, ValueError):

                raise RuntimeError(
                    "Invalid passive scan queue status"
                )

            if remaining < 0:
                raise RuntimeError(
                    "Invalid passive scan queue value"
                )

            if remaining == 0:

                assessment["status"] = (
                    "passive_scan_completed"
                )

                assessment["updated_at"] = self._now()

                self._save_assessments()

                return {
                    "assessment_id": assessment_id,
                    "status": "passive_scan_completed",
                    "remaining_records": 0
                }

            if (
                time.monotonic() - started_at
                >= timeout
            ):

                assessment["status"] = (
                    "passive_scan_timeout"
                )

                assessment["updated_at"] = self._now()

                self._save_assessments()

                raise TimeoutError(
                    "Passive scan processing timed out"
                )

            time.sleep(poll_interval)

    # =================================
    # Collect ZAP Findings
    # =================================

    def collect_zap_findings(self, assessment_id):

        assessment = self.get_assessment(assessment_id)

        if assessment["status"] != "passive_scan_completed":
            raise ValueError(
                "Passive scan must complete before collecting findings"
            )

        findings_by_application = {}
        collection_errors = list(
            assessment["collection_errors"]
        )

        assessment["findings_by_application"] = (
            findings_by_application
        )

        self._save_assessments()

        for application in assessment["applications"]:

            if application not in assessment.get("crawl_results", {}):

                collection_errors.append({
                    "application": application,
                    "error": "Playwright crawl result is unavailable; ZAP alerts were not treated as zero findings"
                })

                assessment["updated_at"] = self._now()
                assessment["collection_errors"] = collection_errors
                self._save_assessments()
                continue

            try:

                expected_target = (
                    self.zap_service.get_application_url(
                        application
                    )
                )

                result = (
                    self.zap_service.get_application_alerts(
                        application
                    )
                )

                if not isinstance(result, dict):
                    raise RuntimeError(
                        "Invalid ZAP application response"
                    )

                if result.get("application") != application:
                    raise RuntimeError(
                        "ZAP application mismatch"
                    )

                if result.get("target") != expected_target:
                    raise RuntimeError(
                        "ZAP target mismatch"
                    )

                alerts = result.get("alerts")

                if not isinstance(alerts, list):
                    raise RuntimeError(
                        "Invalid ZAP alerts response"
                    )

                for alert in alerts:

                    if not self._is_alert_in_application_scope(
                        alert,
                        expected_target
                    ):
                        raise RuntimeError(
                            "Alert outside authorized application scope"
                        )

                findings_by_application[application] = alerts

            except Exception:

                findings_by_application[application] = []

                collection_errors.append({
                    "application": application,
                    "error": (
                        "Unable to collect or validate ZAP alerts"
                    )
                })

            assessment["findings_by_application"] = (
                findings_by_application
            )

            assessment["collection_errors"] = (
                collection_errors
            )

            assessment["updated_at"] = self._now()

            # Save findings after every application.
            self._save_assessments()

        assessment["findings_by_application"] = (
            findings_by_application
        )

        assessment["collection_errors"] = (
            collection_errors
        )

        assessment["status"] = (
            "collected"
            if not collection_errors
            else "collection_completed_with_errors"
        )

        assessment["updated_at"] = self._now()

        self._save_assessments()

        total_findings = sum(
            len(findings)
            for findings in findings_by_application.values()
        )

        return {
            "assessment_id": assessment_id,
            "status": assessment["status"],
            "total_applications": len(
                assessment["applications"]
            ),
            "total_findings": total_findings,
            "findings_by_application": (
                findings_by_application
            ),
            "collection_errors": collection_errors
        }


# =================================
# Service Initialization
# =================================

security_assessment_orchestrator = SecurityAssessmentOrchestrator(
    zap_service=zap_service
)
