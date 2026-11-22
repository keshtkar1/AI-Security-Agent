
import os
import logging

from datetime import datetime, timezone
from uuid import UUID

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.services.zap_service import zap_service
from app.services.ai import ai_service

from app.services.security_assessment_orchestrator import (
    security_assessment_orchestrator
)

from app.services.security_analysis_service import (
    security_analysis_service
)

from app.services.security_report_service import (
    security_report_service
)


logger = logging.getLogger(__name__)


# =================================
# Environment Configuration
# =================================

def get_required_env(name):

    value = os.getenv(name)

    if not value or not value.strip():
        raise ValueError(
            f"Environment variable {name} is not configured"
        )

    return value.strip()


APP_TITLE = get_required_env("APP_TITLE")
APP_DESCRIPTION = get_required_env("APP_DESCRIPTION")
APP_VERSION = get_required_env("APP_VERSION")

API_HOME_PATH = get_required_env("API_HOME_PATH")
API_HEALTH_PATH = get_required_env("API_HEALTH_PATH")
API_ZAP_STATUS_PATH = get_required_env("API_ZAP_STATUS_PATH")
API_AI_ANALYZE_PATH = get_required_env("API_AI_ANALYZE_PATH")


# =================================
# FastAPI Application
# =================================

app = FastAPI(
    title=APP_TITLE,
    description=APP_DESCRIPTION,
    version=APP_VERSION
)


# =================================
# Request Models
# =================================

class AIRequest(BaseModel):
    prompt: str = Field(min_length=1)


class AssessmentRequest(BaseModel):
    applications: list[str] = Field(min_length=1)


class FindingsRequest(BaseModel):
    findings_by_application: dict[str, list[dict]] = Field(
        default_factory=dict
    )


# =================================
# Helper Functions
# =================================

def get_collection_errors(assessment):

    collection_errors = assessment.get(
        "collection_errors", []
    )

    if not isinstance(collection_errors, list):
        return set()

    return {
        item["application"]
        for item in collection_errors
        if (
            isinstance(item, dict)
            and isinstance(item.get("application"), str)
        )
    }


def safe_count(value):

    if (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ):
        return value

    return 0


# =================================
# Existing API Endpoints
# =================================

@app.get(API_HOME_PATH)
def home():

    return {
        "application": APP_TITLE,
        "status": "running",
        "version": APP_VERSION,
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat()
    }


@app.get(API_HEALTH_PATH)
def health():

    return {
        "status": "healthy"
    }


@app.get(API_ZAP_STATUS_PATH)
def zap_status():

    return zap_service.is_connected()


# =================================
# ZAP Passive Scan Status
# =================================

@app.get("/zap/passive-scan/status")
def get_passive_scan_status():

    try:

        return zap_service.get_passive_scan_status()

    except Exception:

        logger.exception(
            "Failed to get ZAP passive scan status"
        )

        raise HTTPException(
            status_code=502,
            detail="Failed to get ZAP passive scan status"
        )


# =================================
# AI Analysis Endpoint
# =================================

@app.post(API_AI_ANALYZE_PATH)
def ai_analyze(request: AIRequest):

    try:

        result = ai_service.analyze(
            request.prompt
        )

        return {
            "status": "success",
            "model": ai_service.model,
            "analysis": result
        }

    except Exception:

        logger.exception("AI service request failed")

        raise HTTPException(
            status_code=502,
            detail="AI service request failed"
        )


# =================================
# Assessment Management
# =================================

@app.post("/assessments")
def create_assessment(request: AssessmentRequest):

    try:

        return security_assessment_orchestrator.create_assessment(
            request.applications
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/assessments")
def list_assessments():

    assessments = (
        security_assessment_orchestrator.list_assessments()
    )

    return {
        "total": len(assessments),
        "assessments": assessments
    }


# =================================
# JSON-Driven Playwright Crawl
# =================================

@app.post("/assessments/{assessment_id}/crawl")
def start_assessment_crawl(assessment_id: str):

    try:
        return security_assessment_orchestrator.start_playwright_crawl(
            assessment_id
        )

    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error))

    except Exception:
        logger.exception("Playwright crawl could not be started")
        raise HTTPException(
            status_code=500,
            detail="Playwright crawl could not be started"
        )


# =================================
# Collect ZAP Findings
# =================================

@app.post("/assessments/{assessment_id}/collect")
def collect_assessment_findings(assessment_id: str):

    try:

        return security_assessment_orchestrator.collect_zap_findings(
            assessment_id
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    except Exception:

        logger.exception("ZAP findings collection failed")

        raise HTTPException(
            status_code=502,
            detail="ZAP findings collection failed"
        )


# =================================
# Spider Assessment Only
# =================================

@app.post("/assessments/{assessment_id}/spider")
def run_spider_only(assessment_id: str):

    raise HTTPException(
        status_code=410,
        detail="ZAP Spider is disabled. Start the JSON-driven Playwright crawl using /assessments/{assessment_id}/crawl."
    )


# =================================
# Passive Scan Assessment Only
# =================================

@app.post("/assessments/{assessment_id}/passive-scan")
def run_passive_scan_only(assessment_id: str):

    try:

        assessment = (
            security_assessment_orchestrator.get_assessment(
                assessment_id
            )
        )

        if assessment.get("applications") != ["sakha_register"]:

            raise HTTPException(
                status_code=400,
                detail=(
                    "This test endpoint only supports "
                    "sakha_register"
                )
            )

        result = (
            security_assessment_orchestrator.wait_for_passive_scan(
                assessment_id
            )
        )

        return result

    except HTTPException:
        raise

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except TimeoutError as error:

        raise HTTPException(
            status_code=504,
            detail=str(error)
        )

    except Exception:

        logger.exception(
            "Passive scan assessment failed"
        )

        raise HTTPException(
            status_code=502,
            detail="Passive scan assessment failed"
        )


# =================================
# Full Security Assessment
# =================================

@app.post("/assessments/{assessment_id}/run")
def run_full_assessment(assessment_id: str):

    """Start the Playwright crawl asynchronously.

    CAPTCHA/OTP are manual, so subsequent stages are invoked after
    the crawl has completed and its status is visible on GET assessment.
    """

    try:
        return security_assessment_orchestrator.start_playwright_crawl(
            assessment_id
        )

    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error))

    except Exception:
        logger.exception("Assessment crawl could not be started")
        raise HTTPException(
            status_code=500,
            detail="Assessment crawl could not be started"
        )


# =================================
# Get Assessment
# =================================

@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str):

    try:

        return security_assessment_orchestrator.get_assessment(
            assessment_id
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )


# =================================
# Security Analysis
# =================================

@app.post("/assessments/{assessment_id}/analyze")
def analyze_assessment(
    assessment_id: str,
    request: FindingsRequest | None = None
):

    try:

        assessment = (
            security_assessment_orchestrator.get_assessment(
                assessment_id
            )
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    applications = assessment.get(
        "applications", []
    )

    if (
        not isinstance(applications, list)
        or not applications
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid assessment applications"
        )

    if request is None:

        allowed_statuses = {
            "collected",
            "collection_completed_with_errors",
            "analyzed",
            "analyzed_with_collection_errors"
        }

        if assessment.get("status") not in allowed_statuses:

            raise HTTPException(
                status_code=409,
                detail=(
                    "ZAP findings must be collected before "
                    "security analysis"
                )
            )

    if request is not None:

        findings_by_application = (
            request.findings_by_application
        )

    else:

        findings_by_application = assessment.get(
            "findings_by_application",
            {}
        )

    if not isinstance(findings_by_application, dict):

        raise HTTPException(
            status_code=400,
            detail="Invalid findings data"
        )

    requested_apps = set(
        findings_by_application.keys()
    )

    authorized_apps = set(applications)

    invalid_apps = requested_apps - authorized_apps

    if invalid_apps:

        raise HTTPException(
            status_code=400,
            detail={
                "message": (
                    "Applications are not part of this assessment"
                ),
                "applications": sorted(invalid_apps)
            }
        )

    if request is not None:

        missing_apps = authorized_apps - requested_apps

        if missing_apps:

            raise HTTPException(
                status_code=400,
                detail={
                    "message": (
                        "Manual analysis data must be provided "
                        "for every application in the assessment"
                    ),
                    "missing_applications": sorted(missing_apps)
                }
            )

    try:

        analyses = []

        collection_errors = get_collection_errors(
            assessment
        )

        for application in applications:

            if (
                request is None
                and application in collection_errors
            ):

                analyses.append({
                    "application": application,
                    "status": "collection_failed",
                    "total_findings": 0,
                    "analyzed_findings": 0,
                    "truncated": False,
                    "risk_summary": {
                        "high": 0,
                        "medium": 0,
                        "low": 0,
                        "informational": 0,
                        "other": 0
                    },
                    "analysis": (
                        "دریافت یافته‌های امنیتی این اپلیکیشن "
                        "از ZAP با خطا مواجه شده است. "
                        "بنابراین تحلیل انجام نشد."
                    )
                })

                continue

            findings = findings_by_application.get(
                application,
                []
            )

            result = security_analysis_service.analyze_findings(
                application=application,
                findings=findings
            )

            analyses.append(result)

        assessment["results"] = analyses

        assessment["status"] = (
            "analyzed_with_collection_errors"
            if request is None and collection_errors
            else "analyzed"
        )

        assessment["updated_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        security_assessment_orchestrator.save_assessment(
            assessment_id
        )

        total_findings = sum(
            safe_count(item.get("total_findings", 0))
            for item in analyses
        )

        return {
            "assessment_id": assessment_id,
            "status": assessment["status"],
            "total_applications": len(analyses),
            "total_findings": total_findings,
            "analyses": analyses
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        logger.exception("Security analysis failed")

        raise HTTPException(
            status_code=502,
            detail="Security analysis service failed"
        ) from error


# =================================
# Security Report Generation
# =================================

@app.post("/assessments/{assessment_id}/report")
def generate_assessment_report(assessment_id: str):

    try:

        assessment = (
            security_assessment_orchestrator.get_assessment(
                assessment_id
            )
        )

    except ValueError as error:

        raise HTTPException(
            status_code=404,
            detail=str(error)
        )

    allowed_statuses = {
        "analyzed",
        "analyzed_with_collection_errors"
    }

    if assessment.get("status") not in allowed_statuses:

        raise HTTPException(
            status_code=409,
            detail=(
                "Security analysis must be completed "
                "before generating the report"
            )
        )

    analyses = assessment.get("results")

    if not isinstance(analyses, list):

        raise HTTPException(
            status_code=409,
            detail="Security analysis results are unavailable"
        )

    try:

        report = security_report_service.generate_report(
            assessment=assessment,
            analyses=analyses
        )

        security_report_service.save_json_report(
            report
        )

        security_report_service.save_html_report(
            report
        )

        assessment["report_id"] = report["report_id"]
        assessment["updated_at"] = datetime.now(
            timezone.utc
        ).isoformat()

        security_assessment_orchestrator.save_assessment(
            assessment_id
        )

        return {
            "assessment_id": assessment_id,
            "report_id": report["report_id"],
            "status": "success",
            "reports": {
                "json": (
                    f"/reports/{report['report_id']}/json"
                ),
                "html": (
                    f"/reports/{report['report_id']}/html"
                )
            }
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        logger.exception("Report generation failed")

        raise HTTPException(
            status_code=500,
            detail="Report generation failed"
        )


# =================================
# Download Security Reports
# =================================

@app.get("/reports/{report_id}/{report_format}")
def download_security_report(
    report_id: str,
    report_format: str
):

    try:

        safe_report_id = str(
            UUID(report_id)
        )

    except (ValueError, TypeError, AttributeError):

        raise HTTPException(
            status_code=400,
            detail="Invalid report ID"
        )

    if report_format not in ("json", "html"):

        raise HTTPException(
            status_code=400,
            detail="Unsupported report format"
        )

    report_directory = (
        security_report_service.report_directory
    )

    file_path = (
        report_directory
        / f"{safe_report_id}.{report_format}"
    )

    if not file_path.is_file():

        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    media_type = (
        "application/json"
        if report_format == "json"
        else "text/html"
    )

    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=file_path.name
    )
