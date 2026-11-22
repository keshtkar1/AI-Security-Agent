
import hashlib
import json
import re

from pathlib import Path
from uuid import UUID
from datetime import datetime, timezone
from html import escape
from urllib.parse import (
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode
)


class _SafeHTML(str):
    """
    Marker for HTML fragments that must be emitted as-is
    instead of being escaped by _html().
    """

    pass


class SecurityReportService:
    """
    Generates sanitized security assessment reports
    in JSON and HTML formats.
    """

    def __init__(self, report_directory="app/reports"):

        self.report_directory = Path(report_directory)
        self.report_directory.mkdir(
            parents=True,
            exist_ok=True
        )

        self.sensitive_parameter_names = {
            "session",
            "sessionid",
            "session_id",
            "sid",
            "jsessionid",
            "phpsessid",
            "aspsessionid",
            "access_token",
            "refresh_token",
            "token",
            "authorization",
            "auth",
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "cookie"
        }

        self.risk_labels = {
            "high": "High / Critical",
            "medium": "Medium",
            "low": "Low",
            "informational": "Informational",
            "other": "Other"
        }

    # =================================
    # Validation Helpers
    # =================================

    def _validate_report_id(self, report_id):

        if not isinstance(report_id, str):
            raise ValueError("Invalid report ID")

        try:
            return str(UUID(report_id))
        except (
            ValueError,
            TypeError,
            AttributeError
        ):
            raise ValueError("Invalid report ID format")

    def _safe_count(self, value):

        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        ):
            return value

        return 0

    def _to_persian_digits(self, value):

        persian = "۰۱۲۳۴۵۶۷۸۹"
        return "".join(
            persian[int(ch)] if ch.isdigit() else ch
            for ch in str(value)
        )

    def _safe_string(self, value, default="نامشخص"):

        if value is None:
            return default

        if isinstance(value, (dict, list, tuple)):
            value = json.dumps(
                value,
                ensure_ascii=False,
                default=str
            )

        return str(value)

    # =================================
    # Sensitive Information Protection
    # =================================

    def _is_sensitive_parameter(self, name):

        if not isinstance(name, str):
            return False

        normalized = name.strip().lower()

        if normalized in self.sensitive_parameter_names:
            return True

        patterns = (
            r".*session.*",
            r".*token.*",
            r".*password.*",
            r".*secret.*",
            r".*credential.*",
            r".*api[_-]?key.*",
            r".*cookie.*"
        )

        return any(
            re.fullmatch(pattern, normalized)
            for pattern in patterns
        )

    def _sanitize_text(self, value):

        if not isinstance(value, str):
            return value

        pattern = re.compile(
            r"(?i)"
            r"([?&])"
            r"((?:session|sessionid|session_id|sid|"
            r"jsessionid|phpsessid|aspsessionid|"
            r"access_token|refresh_token|token|"
            r"authorization|auth|password|passwd|"
            r"secret|api_key|apikey|cookie)"
            r"=)"
            r"([^&#\s\"'<>]*)"
        )

        sanitized = pattern.sub(
            lambda match: (
                match.group(1)
                + match.group(2)
                + "[MASKED]"
            ),
            value
        )

        sanitized = re.sub(
            r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+",
            r"\1[MASKED]",
            sanitized
        )

        sanitized = re.sub(
            r"(?i)((?:Cookie|Set-Cookie)\s*:\s*)"
            r"[^\r\n]+",
            r"\1[MASKED]",
            sanitized
        )

        return sanitized

    def _sanitize_url(self, value):

        if not isinstance(value, str) or not value.strip():
            return value

        try:

            parsed = urlsplit(value)
            sanitized_query = []

            for key, parameter_value in parse_qsl(
                parsed.query,
                keep_blank_values=True
            ):

                if self._is_sensitive_parameter(key):
                    sanitized_query.append(
                        (key, "[MASKED]")
                    )
                else:
                    sanitized_query.append(
                        (
                            key,
                            self._sanitize_text(parameter_value)
                        )
                    )

            return urlunsplit((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                urlencode(sanitized_query),
                parsed.fragment
            ))

        except Exception:
            return self._sanitize_text(value)

    def _sanitize_data(self, value, key=None):

        if (
            key is not None
            and self._is_sensitive_parameter(str(key))
        ):
            return "[MASKED]"

        if isinstance(value, str):

            if key is not None and str(key).lower() == "url":
                return self._sanitize_url(value)

            return self._sanitize_text(value)

        if isinstance(value, list):
            return [
                self._sanitize_data(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return [
                self._sanitize_data(item)
                for item in value
            ]

        if isinstance(value, dict):

            sanitized = {}

            for item_key, item_value in value.items():

                key_string = str(item_key)

                sanitized[key_string] = self._sanitize_data(
                    item_value,
                    key=key_string
                )

            return sanitized

        if isinstance(value, (int, float, bool)) or value is None:
            return value

        return self._sanitize_text(str(value))

    # =================================
    # Page Helpers
    # =================================

    def _get_page_path(self, url):

        if not isinstance(url, str) or not url.strip():
            return "نامشخص"

        try:
            parsed = urlsplit(url)
            return parsed.path or "/"
        except Exception:
            return "نامشخص"

    def _group_findings_by_page(self, findings):

        pages = {}

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            url = finding.get("url", "")
            page_path = self._get_page_path(url)

            if page_path not in pages:

                pages[page_path] = {
                    "page_path": page_path,
                    "url": self._sanitize_url(url),
                    "findings": []
                }

            pages[page_path]["findings"].append(finding)

        return list(pages.values())

    def _url_identity(self, value):

        if not isinstance(value, str) or not value.strip():
            return None

        try:
            parsed = urlsplit(value.strip())
            if not parsed.scheme or not parsed.netloc:
                return None
            return (
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                (parsed.path or "/").rstrip("/") or "/"
            )
        except Exception:
            return None

    def _load_crawl_result(self, assessment, application):

        crawl_results = assessment.get("crawl_results", {})

        if isinstance(crawl_results, dict):
            candidate = crawl_results.get(application)
            if isinstance(candidate, dict):
                return candidate

        project_directory = Path(__file__).resolve().parents[2]
        crawl_file = (
            project_directory
            / "data"
            / "crawl_results"
            / f"{application}_crawl.json"
        )

        if not crawl_file.is_file():
            return {}

        try:
            with crawl_file.open("r", encoding="utf-8") as file:
                data = json.load(file)
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError, TypeError):
            return {}

    def _build_configured_pages(self, assessment, application, findings):

        crawl_result = self._load_crawl_result(
            assessment,
            application
        )

        configured_pages = crawl_result.get("configured_pages", [])
        page_details = crawl_result.get("page_details", [])

        if not isinstance(configured_pages, list):
            configured_pages = []

        if not isinstance(page_details, list):
            page_details = []

        details_by_id = {}
        for detail in page_details:
            if isinstance(detail, dict):
                page_id = detail.get("page_id")
                if page_id is not None:
                    details_by_id[str(page_id)] = detail

        pages = []

        # configured_pages is intentionally traversed without sorting.
        for configured in configured_pages:
            if not isinstance(configured, dict):
                continue

            page_id = configured.get("page_id", "")
            detail = details_by_id.get(str(page_id), {})
            if not isinstance(detail, dict):
                detail = {}

            configured_url = (
                configured.get("url")
                or detail.get("configured_url")
                or ""
            )
            actual_url = detail.get("actual_url") or ""
            accepted_urls = {
                identity
                for identity in (
                    self._url_identity(configured_url),
                    self._url_identity(actual_url)
                )
                if identity is not None
            }

            page_findings = []
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                finding_identity = self._url_identity(
                    finding.get("url", "")
                )
                if finding_identity in accepted_urls:
                    page_findings.append(finding)

            pages.append({
                "page_id": page_id,
                "page_name": (
                    configured.get("page_name")
                    or detail.get("page_name")
                    or page_id
                    or "صفحه بدون عنوان"
                ),
                "description": detail.get("description", ""),
                "page_path": self._get_page_path(
                    actual_url or configured_url
                ),
                "url": self._sanitize_url(
                    actual_url or configured_url
                ),
                "page_status": detail.get("page_status", "unknown"),
                "findings": page_findings
            })

        return pages

    def _get_page_title(self, page, page_index):

        title = self._safe_string(
            page.get("page_name", f"صفحه {page_index}")
        ).strip()
        title = re.sub(r"(?i)\bOWASP\s+ZAP\b|\bZAP\b", "", title)
        title = re.sub(r"\s{2,}", " ", title).strip(" -–—:")
        return title or f"صفحه {page_index}"

    # =================================
    # Finding Helpers
    # =================================

    def _get_finding_title(self, finding):

        raw_title = self._safe_string(
            finding.get(
                "alert",
                finding.get("name", "یافته امنیتی بدون عنوان")
            )
        ).strip()

        # Present scanner rule names as clear, user-facing Persian titles.
        title_map = {
            "Content Security Policy (CSP) Header Not Set": "سیاست امنیتی محتوا (CSP) تنظیم نشده است",
            "Absence of Anti-CSRF Tokens": "توکن محافظت در برابر جعل درخواست (CSRF) وجود ندارد",
            "Information Disclosure - Sensitive Information in URL": "افشای اطلاعات حساس در نشانی صفحه",
            "Information Disclosure - Suspicious Comments": "وجود توضیحات مشکوک حاوی اطلاعات داخلی",
            "Modern Web Application": "شناسایی قابلیت‌های برنامه وب مدرن",
            "User Controllable HTML Element Attribute (Potential XSS)": "احتمال تزریق اسکریپت از طریق ویژگی‌های قابل‌کنترل عناصر HTML",
            "Cookie without SameSite Attribute": "تنظیم‌نشدن ویژگی SameSite برای کوکی",
            "Session Management Response Identified": "شناسایی پاسخ مرتبط با مدیریت نشست کاربر",
            "Missing Anti-clickjacking Header": "سربرگ محافظت در برابر Clickjacking تنظیم نشده است",
        }
        if raw_title in title_map:
            return title_map[raw_title]

        # Remove tool branding if it appears in an otherwise unknown title.
        cleaned = re.sub(r"(?i)\bOWASP\s+ZAP\b|\bZAP\b", "", raw_title)
        cleaned = re.sub(r"\s{2,}", " ", cleaned).strip(" -–—:")
        return cleaned or "یافته امنیتی بدون عنوان"

    def _get_finding_id(self, finding):

        finding_id = finding.get("finding_id")

        if isinstance(finding_id, str) and finding_id:
            return finding_id

        identity = {
            "alert": finding.get(
                "alert",
                finding.get("name", "")
            ),
            "pluginId": finding.get("pluginId", ""),
            "alertRef": finding.get("alertRef", ""),
            "page": self._get_page_path(
                finding.get("url", "")
            ),
            "method": str(
                finding.get("method", "")
            ).upper(),
            "param": finding.get("param", "")
        }

        serialized = json.dumps(
            identity,
            ensure_ascii=False,
            sort_keys=True,
            default=str
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()[:16]

    def _build_finding_groups(self, findings):

        groups = {}

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            finding_id = self._get_finding_id(finding)

            if finding_id not in groups:

                groups[finding_id] = {
                    "finding_id": finding_id,
                    "alert": self._get_finding_title(finding),
                    "risk": finding.get("risk", "نامشخص"),
                    "page_path": self._get_page_path(
                        finding.get("url", "")
                    ),
                    "method": finding.get("method", "نامشخص"),
                    "param": finding.get("param", "نامشخص"),
                    "occurrences": 0
                }

            groups[finding_id]["occurrences"] += 1

        return list(groups.values())

    # =================================
    # Risk Helpers
    # =================================

    def _normalize_risk(self, value):

        risk = str(value or "").strip().lower()

        if risk in ("high", "critical"):
            return "high"

        if risk == "medium":
            return "medium"

        if risk == "low":
            return "low"

        if risk in ("informational", "info"):
            return "informational"

        return "other"

    def _count_risks(self, findings):

        counts = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "other": 0
        }

        for finding in findings:

            if not isinstance(finding, dict):
                continue

            risk = self._normalize_risk(
                finding.get("risk")
            )

            counts[risk] += 1

        return counts

    def _normalize_risk_summary(self, value):

        result = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "other": 0
        }

        if not isinstance(value, dict):
            return result

        for key in result:
            result[key] = self._safe_count(
                value.get(key, 0)
            )

        return result

    # =================================
    # Build Report Summary
    # =================================

    def _build_summary(self, assessment, analyses):

        risk_summary = {
            "high": 0,
            "medium": 0,
            "low": 0,
            "informational": 0,
            "other": 0
        }

        total_findings = 0
        unique_findings = 0
        analyzed_findings = 0
        truncated_applications = 0
        completed_analyses = 0
        failed_analyses = 0

        for item in analyses:

            if not isinstance(item, dict):
                continue

            total_findings += self._safe_count(
                item.get("total_findings", 0)
            )

            unique_findings += self._safe_count(
                item.get(
                    "unique_findings",
                    item.get("total_findings", 0)
                )
            )

            analyzed_findings += self._safe_count(
                item.get(
                    "analyzed_findings",
                    item.get("total_findings", 0)
                )
            )

            if item.get("truncated") is True:
                truncated_applications += 1

            if item.get("status") == "completed":
                completed_analyses += 1
            else:
                failed_analyses += 1

            item_risks = self._normalize_risk_summary(
                item.get("risk_summary")
            )

            for risk in risk_summary:
                risk_summary[risk] += item_risks[risk]

        collection_errors = assessment.get(
            "collection_errors",
            []
        )

        if not isinstance(collection_errors, list):
            collection_errors = []

        applications = assessment.get(
            "applications",
            []
        )

        if not isinstance(applications, list):
            applications = []

        return {
            "total_applications": len(applications),
            "total_findings": total_findings,
            "unique_findings": unique_findings,
            "analyzed_findings": analyzed_findings,
            "risk_summary": risk_summary,
            "completed_analyses": completed_analyses,
            "failed_analyses": failed_analyses,
            "truncated_applications": truncated_applications,
            "collection_errors": len(collection_errors)
        }

    # =================================
    # Build Application Reports
    # =================================

    def _build_application_reports(self, assessment, analyses):

        raw_findings = assessment.get(
            "findings_by_application",
            {}
        )

        if not isinstance(raw_findings, dict):
            raw_findings = {}

        analysis_by_application = {}

        for item in analyses:

            if not isinstance(item, dict):
                continue

            application = item.get("application")

            if isinstance(application, str):
                analysis_by_application[application] = item

        applications = assessment.get(
            "applications",
            []
        )

        result = []

        for application in applications:

            analysis_item = analysis_by_application.get(
                application,
                {}
            )

            if not isinstance(analysis_item, dict):
                analysis_item = {}

            findings = analysis_item.get("findings")

            if not isinstance(findings, list):
                findings = raw_findings.get(application, [])

            if not isinstance(findings, list):
                findings = []

            sanitized_findings = [
                self._sanitize_data(finding)
                for finding in findings
                if isinstance(finding, dict)
            ]

            pages = self._build_configured_pages(
                assessment,
                application,
                sanitized_findings
            )

            finding_groups = self._build_finding_groups(
                sanitized_findings
            )

            analysis_structured = self._sanitize_data(
                analysis_item.get("analysis_structured")
            )

            if not isinstance(analysis_structured, dict):
                analysis_structured = None

            result.append({
                "application": application,
                "analysis_status": analysis_item.get(
                    "status",
                    "not_analyzed"
                ),
                "total_findings": self._safe_count(
                    analysis_item.get(
                        "total_findings",
                        len(sanitized_findings)
                    )
                ),
                "unique_findings": self._safe_count(
                    analysis_item.get(
                        "unique_findings",
                        len(finding_groups)
                    )
                ),
                "analyzed_findings": self._safe_count(
                    analysis_item.get(
                        "analyzed_findings",
                        0
                    )
                ),
                "truncated": (
                    analysis_item.get("truncated") is True
                ),
                "risk_summary": self._normalize_risk_summary(
                    analysis_item.get("risk_summary")
                    if isinstance(
                        analysis_item.get("risk_summary"),
                        dict
                    )
                    else self._count_risks(sanitized_findings)
                ),
                "analysis": self._sanitize_data(
                    analysis_item.get("analysis", "")
                ),
                "analysis_structured": analysis_structured,
                "structured_analysis_status": (
                    analysis_item.get(
                        "structured_analysis_status",
                        "unavailable"
                    )
                ),
                "findings": sanitized_findings,
                "finding_groups": finding_groups,
                "pages": pages
            })

        return result

    # =================================
    # Generate Report
    # =================================

    def generate_report(self, assessment, analyses=None):

        if not isinstance(assessment, dict):
            raise ValueError("Invalid assessment data")

        report_id = self._validate_report_id(
            assessment.get("assessment_id")
        )

        applications = assessment.get("applications")

        if not isinstance(applications, list) or not applications:
            raise ValueError("No applications found in assessment")

        if not all(
            isinstance(app, str) and app.strip()
            for app in applications
        ):
            raise ValueError("Invalid application data")

        if analyses is None:
            analyses = []

        if not isinstance(analyses, list):
            raise ValueError("Analyses must be a list")

        if not all(
            isinstance(item, dict)
            for item in analyses
        ):
            raise ValueError("Invalid analysis data")

        summary = self._build_summary(
            assessment,
            analyses
        )

        application_reports = self._build_application_reports(
            assessment,
            analyses
        )

        # Sanitize copies. Original assessment is not modified.
        sanitized_assessment = self._sanitize_data(
            assessment
        )

        sanitized_analyses = self._sanitize_data(
            analyses
        )

        return {
            "report_id": report_id,
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "assessment": sanitized_assessment,
            "summary": summary,
            "analyses": sanitized_analyses,
            "application_reports": application_reports
        }

    # =================================
    # Save JSON Report
    # =================================

    def save_json_report(self, report):

        if not isinstance(report, dict):
            raise ValueError("Invalid report data")

        report_id = self._validate_report_id(
            report.get("report_id")
        )

        safe_report = self._sanitize_data(report)

        file_path = (
            self.report_directory
            / f"{report_id}.json"
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                safe_report,
                file,
                ensure_ascii=False,
                indent=4
            )

        return str(file_path)

    # =================================
    # HTML Helpers
    # =================================

    def _html(self, value, default="نامشخص"):

        if isinstance(value, _SafeHTML):
            return str(value)

        return escape(
            self._safe_string(value, default)
        )

    def _render_table(self, headers, rows):

        header_html = "".join(
            f"<th>{self._html(header)}</th>"
            for header in headers
        )

        if not rows:
            rows = [
                ["اطلاعاتی برای نمایش وجود ندارد."]
            ]

        rows_html = ""

        for row in rows:

            cells = "".join(
                f"<td>{self._html(value)}</td>"
                for value in row
            )

            rows_html += f"<tr>{cells}</tr>"

        return f"""
            <div class="table-wrapper">
                <table>
                    <thead>
                        <tr>{header_html}</tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
        """

    def _render_risk_table(self, risk_summary):

        risk_summary = self._normalize_risk_summary(
            risk_summary
        )

        rows = [
            [
                _SafeHTML(
                    f'<span class="badge '
                    f'{self._risk_css_class(risk)}">'
                    f'{self._html(label)}</span>'
                ),
                risk_summary[risk]
            ]
            for risk, label in self.risk_labels.items()
        ]

        return self._render_table(
            ["سطح ریسک", "تعداد رخدادها"],
            rows
        )

    def _render_metadata(self, assessment, report):

        rows = [
            ["شناسه ارزیابی", report.get("report_id", "")],
            ["وضعیت ارزیابی", assessment.get("status", "نامشخص")],
            ["زمان ایجاد ارزیابی", assessment.get("created_at", "")],
            ["آخرین به‌روزرسانی", assessment.get("updated_at", "")],
            ["زمان تولید گزارش", report.get("generated_at", "")]
        ]

        return self._render_table(
            ["عنوان", "مقدار"],
            rows
        )

    # =================================
    # Structured AI Rendering
    # =================================

    def _render_string_list(self, items):

        if not isinstance(items, list) or not items:
            return "<p class='muted'>موردی ثبت نشده است.</p>"

        result = "<ul>"

        for item in items:
            result += f"<li>{self._html(item)}</li>"

        return result + "</ul>"

    def _render_finding_analysis(self, items):

        if not isinstance(items, list) or not items:
            return (
                "<p class='muted'>"
                "تحلیل تفصیلی یافته‌ها موجود نیست."
                "</p>"
            )

        result = ""

        for item in items:

            if not isinstance(item, dict):
                continue

            result += f"""
                <article class="finding-analysis">

                    <div class="finding-id">
                        شناسه یافته:
                        {self._html(item.get("finding_id"))}
                    </div>

                    <h4>{self._html(item.get("title"))}</h4>

                    <p>
                        <strong>شرح فنی:</strong>
                        {self._html(item.get("technical_description"))}
                    </p>

                    <p>
                        <strong>اثر امنیتی:</strong>
                        {self._html(item.get("security_impact"))}
                    </p>

                    <p>
                        <strong>ارزیابی اطمینان:</strong>
                        {self._html(item.get("confidence_assessment"))}
                    </p>

                    <p>
                        <strong>نیازمند راستی‌آزمایی:</strong>
                        {self._html(item.get("verification_needed"))}
                    </p>

                    <p>
                        <strong>راهکار اصلاح:</strong>
                        {self._html(item.get("recommended_action"))}
                    </p>

                    <p>
                        <strong>روش تأیید رفع:</strong>
                        {self._html(item.get("verification_method"))}
                    </p>

                </article>
            """

        return result or (
            "<p class='muted'>تحلیل تفصیلی موجود نیست.</p>"
        )

    def _render_false_positives(self, items):

        if not isinstance(items, list) or not items:
            return (
                "<p class='muted'>"
                "مورد مشکوکی ثبت نشده است."
                "</p>"
            )

        rows = []

        for item in items:

            if not isinstance(item, dict):
                continue

            rows.append([
                item.get("finding_id", ""),
                item.get("reason", ""),
                item.get("required_review", "")
            ])

        return self._render_table(
            [
                "شناسه یافته",
                "دلیل احتمال مثبت کاذب",
                "بررسی موردنیاز"
            ],
            rows
        )

    def _render_remediation(self, items):

        if not isinstance(items, list) or not items:
            return (
                "<p class='muted'>"
                "اقدام اصلاحی ثبت نشده است."
                "</p>"
            )

        rows = []

        for item in items:

            if not isinstance(item, dict):
                continue

            related_ids = item.get(
                "related_finding_ids",
                []
            )

            if isinstance(related_ids, list):
                related_ids = ", ".join(
                    str(value)
                    for value in related_ids
                )
            else:
                related_ids = ""

            rows.append([
                item.get("priority", ""),
                item.get("title", ""),
                item.get("description", ""),
                related_ids
            ])

        return self._render_table(
            [
                "اولویت",
                "عنوان اقدام",
                "شرح اقدام",
                "شناسه یافته‌های مرتبط"
            ],
            rows
        )

    def _render_verification_plan(self, items):

        if not isinstance(items, list) or not items:
            return (
                "<p class='muted'>"
                "برنامه راستی‌آزمایی ثبت نشده است."
                "</p>"
            )

        rows = []

        for item in items:

            if not isinstance(item, dict):
                continue

            rows.append([
                item.get("title", ""),
                item.get("description", "")
            ])

        return self._render_table(
            ["عنوان", "روش بررسی"],
            rows
        )

    def _render_structured_analysis(self, structured):

        if not isinstance(structured, dict):
            structured = {}

        overall = structured.get(
            "overall_security",
            {}
        )

        if not isinstance(overall, dict):
            overall = {}

        exec_summary = structured.get("executive_summary")
        if exec_summary:
            exec_html = f'<p>{self._html(exec_summary)}</p>'
        else:
            exec_html = (
                '<p class="empty" style="margin:0">'
                'خلاصه مدیریتی در خروجی AI موجود نیست.'
                '</p>'
            )

        assessment_val = overall.get("assessment")
        risk_level_val = overall.get("risk_level")
        reason_val = overall.get("reason")

        return f"""
            <div class="executive-summary" style="background:#fbfdfa;border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:10px 0 16px">

                <h3 style="margin-top:0">خلاصه مدیریتی</h3>

                {exec_html}

            </div>

            <div class="overall-card" style="background:#fbfdfa;border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:10px 0 16px">

                <h4 style="margin:0 0 10px;font-size:14px;color:#2f4d22">ارزیابی کلی</h4>

                <p style="margin:6px 0">
                    <strong>نتیجه:</strong>
                    {self._html(assessment_val, 'ارزیابی کلی ارائه نشده است.')}
                </p>

                <p style="margin:6px 0">
                    <strong>سطح ریسک ارزیابی‌شده:</strong>
                    {self._html(risk_level_val, 'نامشخص')}
                </p>

                <p style="margin:6px 0">
                    <strong>دلیل:</strong>
                    {self._html(reason_val, 'خروجی ساختاریافته ناقص است.')}
                </p>

            </div>

            <h3>توزیع ریسک</h3>

            {self._render_risk_table(
                structured.get("risk_distribution", {})
            )}

            <h3>تحلیل تفصیلی یافته‌ها</h3>

            {self._render_finding_analysis(
                structured.get("finding_analysis", [])
            )}

            <h3>موارد مشکوک به False Positive</h3>

            {self._render_false_positives(
                structured.get("false_positive_candidates", [])
            )}

            <h3>موارد نیازمند بررسی بیشتر</h3>

            {self._render_string_list(
                structured.get("further_investigation", [])
            )}

            <h3>راهکارهای اصلاحی اولویت‌بندی‌شده</h3>

            {self._render_remediation(
                structured.get("prioritized_remediation", [])
            )}

            <h3>برنامه راستی‌آزمایی</h3>

            {self._render_verification_plan(
                structured.get("verification_plan", [])
            )}

            <h3>محدودیت‌های تحلیل</h3>

            {self._render_string_list(
                structured.get("limitations", [])
            )}
        """

    # =================================
    # Render Finding Details
    # =================================

    def _render_finding_details(self, findings):

        if not isinstance(findings, list) or not findings:
            return (
                "<p class='muted'>"
                "یافته‌ای برای نمایش وجود ندارد."
                "</p>"
            )

        result = ""

        for index, finding in enumerate(findings, start=1):

            if not isinstance(finding, dict):
                continue

            url = self._sanitize_url(
                self._safe_string(
                    finding.get("url", ""),
                    ""
                )
            )

            result += f"""
                <article class="zap-finding">

                    <div class="finding-header">

                        <span class="finding-number">
                            رخداد {index}
                        </span>

                        <span class="risk-label">
                            {self._html(finding.get("risk"))}
                        </span>

                    </div>

                    <h4>{self._html(self._get_finding_title(finding))}</h4>

                    <div class="technical-grid">

                        <div>
                            <strong>شناسه یافته:</strong>
                            <code>{self._html(self._get_finding_id(finding))}</code>
                        </div>

                        <div>
                            <strong>سطح میزان اطمینان:</strong>
                            {self._html(finding.get("confidence"))}
                        </div>

                        <div>
                            <strong>روش درخواست:</strong>
                            {self._html(finding.get("method"))}
                        </div>

                        <div>
                            <strong>پارامتر:</strong>
                            <code>{self._html(finding.get("param"))}</code>
                        </div>

                        <div>
                            <strong>Plugin ID:</strong>
                            <code>{self._html(finding.get("pluginId"))}</code>
                        </div>

                        <div>
                            <strong>Alert Ref:</strong>
                            <code>{self._html(finding.get("alertRef"))}</code>
                        </div>

                    </div>

                    <div class="technical-block">

                        <strong>URL:</strong>

                        <div class="ltr">
                            <code>{self._html(url)}</code>
                        </div>

                    </div>

                    <p>
                        <strong>شرح هشدار:</strong>
                        {self._html(finding.get("description"))}
                    </p>

                    <p><strong>Evidence:</strong></p>

                    <pre class="ltr">{self._html(finding.get("evidence"))}</pre>

                    <p><strong>Attack:</strong></p>

                    <pre class="ltr">{self._html(finding.get("attack"))}</pre>

                    <p>
                        <strong>راهکار پیشنهادی:</strong>
                        {self._html(finding.get("solution"))}
                    </p>

                </article>
            """

        return result or (
            "<p class='muted'>یافته‌ای برای نمایش وجود ندارد.</p>"
        )

    # =================================
    # Render Page Sections
    # =================================

    def _render_pages(self, pages):

        if not isinstance(pages, list) or not pages:
            return (
                "<p class='muted'>"
                "اطلاعات صفحه‌ای ثبت نشده است."
                "</p>"
            )

        result = ""

        for index, page in enumerate(pages, start=1):

            if not isinstance(page, dict):
                continue

            page_path = self._html(
                page.get("page_path")
            )

            url = self._html(
                page.get("url", "")
            )

            findings = page.get("findings", [])

            if not isinstance(findings, list):
                findings = []

            groups = self._build_finding_groups(findings)

            result += f"""
                <section class="page-section">

                    <h3>صفحه {index}: {page_path}</h3>

                    <div class="ltr page-url">{url}</div>

                    <p>
                        تعداد رخدادها:
                        <strong>{len(findings)}</strong>
                    </p>

                    <p>
                        تعداد گروه‌های یافته:
                        <strong>{len(groups)}</strong>
                    </p>

                    <h4>دسته‌بندی یافته‌های امنیتی</h4>

                    {self._render_table(
                        [
                            "عنوان هشدار",
                            "ریسک",
                            "روش",
                            "پارامتر",
                            "تعداد رخداد"
                        ],
                        [
                            [
                                group.get("alert"),
                                group.get("risk"),
                                group.get("method"),
                                group.get("param"),
                                group.get("occurrences")
                            ]
                            for group in groups
                        ]
                    )}

                    <h4>جزئیات یافته‌های امنیتی</h4>

                    {self._render_finding_details(findings)}

                </section>
            """

        return result

    # =================================
    # Render Application
    # =================================

    def _render_application(self, item):

        application = self._html(
            item.get("application")
        )

        status = self._html(
            item.get("analysis_status")
        )

        total = self._safe_count(
            item.get("total_findings", 0)
        )

        unique = self._safe_count(
            item.get("unique_findings", 0)
        )

        analyzed = self._safe_count(
            item.get("analyzed_findings", 0)
        )

        truncated = (
            "بله"
            if item.get("truncated") is True
            else "خیر"
        )

        findings = item.get("findings", [])
        pages = item.get("pages", [])

        if not isinstance(findings, list):
            findings = []

        if not isinstance(pages, list):
            pages = []

        structured = item.get("analysis_structured")

        if not isinstance(structured, dict):
            structured = None

        return f"""
            <section class="application-section">

                <div class="application-header">

                    <h2>{application}</h2>

                    <span class="status-label">{status}</span>

                </div>

                <div class="stats-grid">

                    <div class="stat-card">
                        <span>کل رخدادها</span>
                        <strong>{total}</strong>
                    </div>

                    <div class="stat-card">
                        <span>گروه‌های یافته</span>
                        <strong>{unique}</strong>
                    </div>

                    <div class="stat-card">
                        <span>تحلیل‌شده توسط AI</span>
                        <strong>{analyzed}</strong>
                    </div>

                    <div class="stat-card">
                        <span>محدودیت تحلیل</span>
                        <strong>{truncated}</strong>
                    </div>

                </div>

                <h3>توزیع ریسک</h3>

                {self._render_risk_table(
                    item.get("risk_summary", {})
                )}

                <h3>تحلیل هوش مصنوعی</h3>

                {self._render_structured_analysis(structured)}

                <h3>جزئیات نمای کلی صفحات و یافته‌های امنیتی</h3>

                {self._render_pages(pages)}

            </section>
        """

    # =================================
    # Save HTML Report
    # =================================

    def _risk_css_class(self, risk):

        normalized = self._normalize_risk(risk)
        return {
            "high": "b-crit",
            "medium": "b-med",
            "low": "b-low",
            "informational": "b-info",
            "other": "b-muted"
        }.get(normalized, "b-muted")

    def _risk_persian_label(self, risk):

        normalized = self._normalize_risk(risk)
        return {
            "high": "زیاد / بحرانی",
            "medium": "متوسط",
            "low": "کم",
            "informational": "اطلاع‌رسانی",
            "other": "سایر"
        }.get(normalized, "نامشخص")

    def _render_badge(self, risk):

        return (
            f'<span class="badge {self._risk_css_class(risk)}">'
            f'{self._html(self._risk_persian_label(risk))}</span>'
        )

    def _render_stats(self, values):

        parts = []
        for item in values:
            label = item[0]
            value = item[1]
            style = ""
            if len(item) > 2 and item[2]:
                style = f' style="{self._html(item[2])}"'
            parts.append(
                f'<div class="stat"><div class="lbl">'
                f'{self._html(label)}</div>'
                f'<div class="val"{style}>'
                f'{self._html(value)}</div></div>'
            )

        return '<div class="stats">' + "".join(parts) + '</div>'

    def _render_page_tree(self, application_item, app_index):

        pages = application_item.get("pages", [])
        if not isinstance(pages, list) or not pages:
            return '<p class="empty">صفحه پیکربندی‌شده‌ای برای این اپلیکیشن ثبت نشده است.</p>'

        items_html = []
        for page_index, page in enumerate(pages, start=1):
            if not isinstance(page, dict):
                continue
            findings = page.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            groups = self._build_finding_groups(findings)
            page_target = f"page-{app_index}-{page_index}"
            page_name = self._html(self._get_page_title(page, page_index))
            count_text = str(len(findings)) if findings else "—"
            risk = "other"
            if findings:
                risk_counts = self._count_risks(findings)
                risk = max(risk_counts, key=risk_counts.get)

            children = []
            for group_index, group in enumerate(groups, start=1):
                finding_target = f"f-{app_index}-{page_index}-{group_index}"
                group_risk = self._normalize_risk(group.get("risk"))
                dot_class = self._risk_css_class(group_risk).replace("b-", "rd-")
                children.append(
                    f'''<li><a class="node" href="#{finding_target}">'''
                    f'''<span class="icon">🔎</span>{self._html(group.get("alert"))}'''
                    f'''<span class="count">{group.get("occurrences", 0)}</span>'''
                    f'''<span class="riskdot {dot_class}"></span></a></li>'''
                )

            # Finding nodes are kept collapsed by default. The user can expand
            # this branch independently for each configured page.
            child_html = (
                f'<details class="tree-branch"><summary>یافته‌ها '
                f'<span class="count">{len(groups)}</span></summary>'
                f'<ul>{"".join(children)}</ul></details>'
                if children else ""
            )
            risk_dot = ""
            if findings:
                risk_dot = f'<span class="riskdot {self._risk_css_class(risk).replace("b-", "rd-")}"></span>'

            items_html.append(
                f'''<li><a class="node" href="#{page_target}">'''
                f'''<span class="page-row-number">{page_index}.</span>'''
                f'''<span class="icon">📄</span><span>{page_name}</span>'''
                f'''<span class="count">{count_text}</span>{risk_dot}</a>{child_html}</li>'''
            )

        return (
            f'<div class="tree-wrap">'
            f'<p class="tree-title">📁 {self._html(application_item.get("application"))} '
            f'— درخت صفحات و یافته‌ها (برای رفتن به هر مورد کلیک کنید)</p>'
            f'<ul class="tree">{"".join(items_html)}</ul></div>'
        )

    def _render_page_sections(self, application_item, app_index):

        pages = application_item.get("pages", [])
        if not isinstance(pages, list) or not pages:
            return '<p class="empty">اطلاعات صفحات پیکربندی‌شده موجود نیست.</p>'

        result = []
        for page_index, page in enumerate(pages, start=1):
            if not isinstance(page, dict):
                continue

            findings = page.get("findings", [])
            if not isinstance(findings, list):
                findings = []
            groups = self._build_finding_groups(findings)
            page_target = f"page-{app_index}-{page_index}"
            page_name = self._html(self._get_page_title(page, page_index))
            url = self._html(page.get("url", ""), "نشانی ثبت نشده است")
            risk_counts = self._count_risks(findings)
            page_risk = max(risk_counts, key=risk_counts.get) if findings else "other"

            rows = [[
                group.get("alert", ""),
                _SafeHTML(self._render_badge(group.get("risk"))),
                group.get("method", "—"),
                group.get("param", "—"),
                group.get("occurrences", 0)
            ] for group in groups]

            grouped_table = self._render_table(
                ["عنوان هشدار", "ریسک", "روش", "پارامتر", "تعداد"], rows
            ) if rows else '<p class="empty">برای این صفحه یافته امنیتی ثبت نشده است.</p>'

            grouped_findings = {}
            for finding in findings:
                if isinstance(finding, dict):
                    grouped_findings.setdefault(self._get_finding_id(finding), []).append(finding)

            group_details = []
            for group_index, group in enumerate(groups, start=1):
                finding_target = f"f-{app_index}-{page_index}-{group_index}"
                group_items = grouped_findings.get(group.get("finding_id"), [])
                first = group_items[0] if group_items else {}
                evidence_html = ""
                if first.get("evidence"):
                    evidence_html = f'<p><strong>شواهد:</strong></p><pre class="ev">{self._html(first.get("evidence"))}</pre>'
                attack_html = ""
                if first.get("attack"):
                    attack_html = f'<p><strong>درخواست حمله:</strong></p><pre class="ev">{self._html(first.get("attack"))}</pre>'

                group_details.append(f'''<details class="finding" id="{finding_target}"><summary><span class="idx">#{group_index}</span><span class="title">{self._html(group.get("alert"))}</span>{self._render_badge(group.get("risk"))}<span class="arrow">▼</span></summary><div class="body"><div class="meta-grid"><div><strong>شناسه یافته</strong><code>{self._html(group.get("finding_id"))}</code></div><div><strong>میزان اطمینان</strong>{self._html(first.get("confidence", "نامشخص"))}</div><div><strong>روش</strong>{self._html(first.get("method", "—"))}</div><div><strong>پارامتر</strong><code>{self._html(first.get("param", "—"))}</code></div><div><strong>Plugin ID</strong><code>{self._html(first.get("pluginId", "—"))}</code></div><div><strong>Alert Ref</strong><code>{self._html(first.get("alertRef", "—"))}</code></div></div><div class="url-box">{self._html(self._sanitize_url(first.get("url", "")), "—")}</div><p><strong>شرح:</strong> {self._html(first.get("description", "شرح ثبت نشده است."))}</p>{evidence_html}{attack_html}<div class="fix"><strong>راهکار پیشنهادی:</strong> {self._html(first.get("solution", "برای این هشدار راهکار اختصاصی ثبت نشده است."))}</div>{f'<p class="empty">تعداد رخدادهای مشابه: {len(group_items)}</p>' if len(group_items) > 1 else ''}</div></details>''')

            status_html = (
                '<span class="badge b-muted">یافته تفصیلی ثبت نشده</span>'
                if not findings else self._render_badge(page_risk)
            )
            page_status = page.get("page_status", "unknown")
            status_text = {
                "visited": "بازدید موفق",
                "unavailable": "در دسترس نبود",
                "error": "خطا در بازدید"
            }.get(page_status, "وضعیت نامشخص")
            description_html = (
                f'<p>{self._html(page.get("description"))}</p>'
                if page.get("description") else ""
            )
            details_html = (
                '<h4 style="margin:20px 0 8px;font-size:14px;color:#2f4d22">جزئیات یافته‌های امنیتی</h4>' + "".join(group_details)
                if group_details else ""
            )

            result.append(f'''<section class="card page-section" id="{page_target}"><h3><span class="pnum">{page_index}</span>{page_name}</h3><div class="page-meta"><span><strong>تعداد رخدادها:</strong> {len(findings)}</span><span><strong>گروه‌های یافته:</strong> {len(groups)}</span><span><strong>وضعیت پیمایش:</strong> {self._html(status_text)}</span><span><strong>سطح کلی:</strong> {status_html}</span></div><div class="url-box">{url}</div>{description_html}<h4 style="margin:16px 0 8px;font-size:14px;color:#2f4d22">دسته‌بندی یافته‌های امنیتی</h4>{grouped_table}{details_html}</section>''')

        return "".join(result)



    def _render_kpi_strip(self, summary):

        """Render the KPI strip shown between hero and layout."""

        risk = self._normalize_risk_summary(
            summary.get("risk_summary", {})
        )

        kpis = [
            ("", self._safe_count(summary.get("total_applications")), "اپلیکیشن"),
            ("", self._safe_count(summary.get("total_findings")), "کل رخدادها"),
            ("", self._safe_count(summary.get("unique_findings")), "گروه یافته"),
            ("med", risk["medium"], "ریسک متوسط"),
            ("crit", risk["high"], "ریسک بحرانی"),
            ("info", risk["informational"], "اطلاع‌رسانی"),
        ]

        items = []
        for css_class, value, label in kpis:
            cls_attr = f" {css_class}" if css_class else ""
            items.append(
                f'<div class="kpi{cls_attr}">'
                f'<div class="v">{self._html(value)}</div>'
                f'<div class="l">{self._html(label)}</div></div>'
            )

        return '<div class="kpi-strip">' + "".join(items) + '</div>'

    def _build_chart_data(self, application_reports):

        """Aggregate findings/pages data for donut, bars and heatmap."""

        risk_totals = {"h": 0, "m": 0, "l": 0, "i": 0}
        total = 0
        findings_map = {}
        pages_data = []

        risk_code_map = {
            "high": "h",
            "medium": "m",
            "low": "l",
            "informational": "i"
        }

        for application_item in application_reports:

            if not isinstance(application_item, dict):
                continue

            rs = self._normalize_risk_summary(
                application_item.get("risk_summary", {})
            )
            risk_totals["h"] += rs["high"]
            risk_totals["m"] += rs["medium"]
            risk_totals["l"] += rs["low"]
            risk_totals["i"] += rs["informational"]
            total += self._safe_count(
                application_item.get("total_findings", 0)
            )

            pages = application_item.get("pages", [])
            if not isinstance(pages, list):
                pages = []

            for page in pages:

                if not isinstance(page, dict):
                    continue

                page_findings = page.get("findings", [])
                if not isinstance(page_findings, list):
                    page_findings = []

                groups = self._build_finding_groups(page_findings)

                page_d = {}
                for group in groups:
                    fid = group.get("finding_id", "")
                    page_d[fid] = group.get("occurrences", 0)
                    if fid not in findings_map:
                        risk_norm = self._normalize_risk(
                            group.get("risk")
                        )
                        findings_map[fid] = {
                            "title": group.get("alert", ""),
                            "risk": risk_code_map.get(risk_norm, "i"),
                        }

                pages_data.append({
                    "n": self._get_page_title(
                        page, len(pages_data) + 1
                    ),
                    "e": len(page_findings),
                    "d": page_d,
                })

        risk_order = {"h": 0, "m": 1, "l": 2, "i": 3}
        sorted_findings = sorted(
            findings_map.items(),
            key=lambda kv: risk_order.get(kv[1]["risk"], 99)
        )
        f_data = [
            [fid, info["title"], info["risk"]]
            for fid, info in sorted_findings
        ]

        return {
            "totals": risk_totals,
            "total": total,
            "F": f_data,
            "P": pages_data,
        }



    def _render_kpi_strip(self, summary):

        """Render the KPI strip shown between hero and layout."""

        risk = self._normalize_risk_summary(
            summary.get("risk_summary", {})
        )

        kpis = [
            ("", self._safe_count(summary.get("total_applications")), "اپلیکیشن"),
            ("", self._safe_count(summary.get("total_findings")), "کل رخدادها"),
            ("", self._safe_count(summary.get("unique_findings")), "گروه یافته"),
            ("med", risk["medium"], "ریسک متوسط"),
            ("crit", risk["high"], "ریسک بحرانی"),
            ("info", risk["informational"], "اطلاع‌رسانی"),
        ]

        items = []
        for css_class, value, label in kpis:
            cls_attr = f" {css_class}" if css_class else ""
            items.append(
                f'<div class="kpi{cls_attr}">'
                f'<div class="v">{self._html(value)}</div>'
                f'<div class="l">{self._html(label)}</div></div>'
            )

        return '<div class="kpi-strip">' + "".join(items) + '</div>'

    def _build_chart_data(self, application_reports):

        """Aggregate findings/pages data for donut, bars and heatmap."""

        risk_totals = {"h": 0, "m": 0, "l": 0, "i": 0}
        total = 0
        findings_map = {}
        pages_data = []

        risk_code_map = {
            "high": "h",
            "medium": "m",
            "low": "l",
            "informational": "i"
        }

        for application_item in application_reports:

            if not isinstance(application_item, dict):
                continue

            rs = self._normalize_risk_summary(
                application_item.get("risk_summary", {})
            )
            risk_totals["h"] += rs["high"]
            risk_totals["m"] += rs["medium"]
            risk_totals["l"] += rs["low"]
            risk_totals["i"] += rs["informational"]
            total += self._safe_count(
                application_item.get("total_findings", 0)
            )

            pages = application_item.get("pages", [])
            if not isinstance(pages, list):
                pages = []

            for page in pages:

                if not isinstance(page, dict):
                    continue

                page_findings = page.get("findings", [])
                if not isinstance(page_findings, list):
                    page_findings = []

                groups = self._build_finding_groups(page_findings)

                page_d = {}
                for group in groups:
                    fid = group.get("finding_id", "")
                    page_d[fid] = group.get("occurrences", 0)
                    if fid not in findings_map:
                        risk_norm = self._normalize_risk(
                            group.get("risk")
                        )
                        findings_map[fid] = {
                            "title": group.get("alert", ""),
                            "risk": risk_code_map.get(risk_norm, "i"),
                        }

                pages_data.append({
                    "n": self._get_page_title(
                        page, len(pages_data) + 1
                    ),
                    "e": len(page_findings),
                    "d": page_d,
                })

        risk_order = {"h": 0, "m": 1, "l": 2, "i": 3}
        sorted_findings = sorted(
            findings_map.items(),
            key=lambda kv: risk_order.get(kv[1]["risk"], 99)
        )
        f_data = [
            [fid, info["title"], info["risk"]]
            for fid, info in sorted_findings
        ]

        return {
            "totals": risk_totals,
            "total": total,
            "F": f_data,
            "P": pages_data,
        }

    def save_html_report(self, report):

        if not isinstance(report, dict):
            raise ValueError("Invalid report data")

        report_id = self._validate_report_id(report.get("report_id"))
        report = self._sanitize_data(report)
        assessment = report.get("assessment", {})
        summary = report.get("summary", {})
        application_reports = report.get("application_reports")

        if not isinstance(assessment, dict):
            raise ValueError("Invalid assessment data")
        if not isinstance(summary, dict):
            raise ValueError("Invalid summary data")
        if not isinstance(application_reports, list):
            application_reports = self._build_application_reports(
                assessment,
                report.get("analyses", [])
            )

        # --- Metadata table (manual, for mono + badge styling) ---
        metadata_html = (
            '<div class="tbl-wrap"><table>'
            '<thead><tr><th>عنوان</th><th>مقدار</th></tr></thead>'
            '<tbody>'
            + f'<tr><td>شناسه ارزیابی</td>'
            f'<td class="mono">{self._html(report_id)}</td></tr>'
            + f'<tr><td>وضعیت ارزیابی</td><td>'
            f'<span class="badge b-ok">'
            f'{self._html(assessment.get("status", "نامشخص"))}'
            f'</span></td></tr>'
            + f'<tr><td>زمان ایجاد</td>'
            f'<td class="mono">'
            f'{self._html(assessment.get("created_at", ""))}'
            f'</td></tr>'
            + f'<tr><td>آخرین به‌روزرسانی</td>'
            f'<td class="mono">'
            f'{self._html(assessment.get("updated_at", ""))}'
            f'</td></tr>'
            + f'<tr><td>زمان تولید گزارش</td>'
            f'<td class="mono">'
            f'{self._html(report.get("generated_at", ""))}'
            f'</td></tr>'
            + '</tbody></table></div>'
        )

        # --- Summary stats ---
        summary_stats = self._render_stats([
            ("تعداد اپلیکیشن‌ها", self._safe_count(summary.get("total_applications"))),
            ("کل رخدادهای امنیتی", self._safe_count(summary.get("total_findings"))),
            ("گروه‌های یافته یکتا", self._safe_count(summary.get("unique_findings"))),
            ("تحلیل‌شده توسط AI", self._safe_count(summary.get("analyzed_findings"))),
            ("تحلیل موفق", self._safe_count(summary.get("completed_analyses")), "color:var(--low)"),
            ("تحلیل ناموفق", self._safe_count(summary.get("failed_analyses")), "color:var(--crit)"),
            ("محدودیت تحلیل", self._safe_count(summary.get("truncated_applications"))),
            ("خطای جمع‌آوری", self._safe_count(summary.get("collection_errors")))
        ])

        # --- KPI strip ---
        kpi_html = self._render_kpi_strip(summary)

        # --- Chart data for donut / bars / heatmap ---
        chart_data = self._build_chart_data(application_reports)
        totals_json = json.dumps(
            chart_data["totals"], ensure_ascii=False
        )
        total_json = str(chart_data["total"])
        f_json = json.dumps(
            chart_data["F"], ensure_ascii=False
        )
        p_json = json.dumps(
            chart_data["P"], ensure_ascii=False
        )

        # --- Apps list ---
        applications = assessment.get("applications", [])
        if not isinstance(applications, list):
            applications = []
        app_list = ''.join(
            '<li><strong>' + self._html(app) + '</strong> — وضعیت: '
            '<span class="badge b-ok">ارزیابی‌شده</span></li>'
            for app in applications
        ) or '<li>اپلیکیشنی ثبت نشده است.</li>'

        # --- Collection errors ---
        collection_errors = assessment.get("collection_errors", [])
        if not isinstance(collection_errors, list):
            collection_errors = []
        error_rows = [
            [item.get("application", "نامشخص"), item.get("error", "خطای نامشخص")]
            for item in collection_errors if isinstance(item, dict)
        ]
        errors_html = (
            self._render_table(["اپلیکیشن", "شرح خطا"], error_rows)
            if error_rows else '<p class="empty">خطایی در جمع‌آوری اطلاعات ثبت نشده است.</p>'
        )

        # --- Details + pages sections per application ---
        details_html = []
        pages_html = []
        for app_index, item in enumerate(application_reports, start=1):
            if not isinstance(item, dict):
                continue
            application = self._html(item.get("application"))
            findings_count = self._safe_count(item.get("total_findings"))
            groups_count = self._safe_count(item.get("unique_findings"))
            analyzed_count = self._safe_count(item.get("analyzed_findings"))
            truncated = "بله" if item.get("truncated") else "خیر"
            structured = item.get("analysis_structured")
            if not isinstance(structured, dict):
                structured = {}

            details_html.append(
                '<section class="card" id="details-' + str(app_index) + '">'
                '<h2><span class="num">' + str(app_index) + '</span> نتایج تفصیلی ارزیابی — ' + application + '</h2>'
                + self._render_stats([
                    ("کل رخدادها", findings_count),
                    ("گروه‌های یافته", groups_count),
                    ("تحلیل‌شده توسط AI", analyzed_count),
                    ("محدودیت تحلیل", truncated, "font-size:16px")
                ])
                + '<h3>تحلیل هوش مصنوعی</h3>'
                + self._render_structured_analysis(structured)
                + '</section>'
            )

            pages_html.append(
                '<section class="card page-index-section" id="page-index-' + str(app_index) + '">'
                '<h2><span class="num">' + str(app_index) + '</span> نمای کلی صفحات و یافته‌های امنیتی — '
                + application + '</h2>'
                + self._render_page_tree(item, app_index)
                + '</section>'
                + self._render_page_sections(item, app_index)
            )

        if not details_html:
            details_html = ['<p class="empty">نتیجه تفصیلی برای اپلیکیشن‌ها موجود نیست.</p>']
        if not pages_html:
            pages_html = ['<p class="empty">صفحه‌ای برای نمایش ثبت نشده است.</p>']

        generated_date = self._html(
            str(report.get("generated_at", ""))[:10],
            datetime.now(timezone.utc).strftime("%Y-%m-%d")
        )
        created_id = self._html(report_id[:8])
        app_first = (
            self._html(applications[0])
            if applications
            else self._html("Security Assessment")
        )

        # Hero chips: first app chip gets a .dot indicator.
        app_chips = ""
        for idx, app in enumerate(applications):
            dot = '<span class="dot"></span>' if idx == 0 else ""
            app_chips += (
                f'<span class="chip">{dot}اپلیکیشن: {self._html(app)}</span>'
            )
        status_chip = (
            f'<span class="chip">وضعیت: '
            f'{self._html(assessment.get("status", "تحلیل‌شده"))}'
            f'</span>'
        )
        date_chip = f'<span class="chip">تاریخ: {generated_date}</span>'
        id_chip = f'<span class="chip">شناسه: {created_id}</span>'

        # Persian-digit section numbers.
        sec_nums = [self._to_persian_digits(i) for i in range(1, 10)]

        # --- CSS (verbatim from target) ---
        report_css = ':root {\n  --brand: #1e4d0f;\n  --brand-mid: #2e6b14;\n  --brand-light: #e8f2e2;\n  --brand-border: #cfe0c5;\n  --ink: #1c2a23;\n  --muted: #5f6f65;\n  --line: #e0e6e2;\n  --bg: #f2f6ef;\n  --card: #ffffff;\n  --crit: #a7281c;\n  --high: #b8501a;\n  --med: #b0790a;\n  --low: #4a6e1a;\n  --info: #0d5c8a;\n  --radius: 14px;\n  --shadow: 0 2px 8px rgba(0,0,0,.05);\n}\n* { box-sizing: border-box; }\nhtml { scroll-behavior: smooth; }\nbody {\n  margin: 0;\n  background: var(--bg);\n  color: var(--ink);\n  font-family: Vazirmatn, Tahoma, Arial, sans-serif;\n  direction: rtl;\n  line-height: 1.85;\n  font-size: 14px;\n}\n.wrap { max-width: 1240px; margin: 0 auto; padding: 20px 16px 60px; }\n\n/* ===== Hero ===== */\n.hero {\n  background: linear-gradient(135deg, #1e4d0f 0%, #2e6b14 55%, #3f8420 100%);\n  color: #fff;\n  border-radius: var(--radius);\n  padding: 30px 28px;\n  position: relative;\n  overflow: hidden;\n  box-shadow: 0 8px 28px rgba(30,77,15,.22);\n}\n.hero::after {\n  content: "";\n  position: absolute;\n  inset: auto -70px -90px auto;\n  width: 280px; height: 280px;\n  background: rgba(255,255,255,.07);\n  border-radius: 50%;\n}\n.hero::before {\n  content: "";\n  position: absolute;\n  inset: -60px auto auto -40px;\n  width: 200px; height: 200px;\n  background: rgba(255,255,255,.04);\n  border-radius: 50%;\n}\n.hero h1 { margin: 0 0 4px; font-size: 25px; font-weight: 800; }\n.hero .sub { margin: 0 0 18px; color: #d9ebd1; font-size: 13.5px; }\n.chips { display: flex; flex-wrap: wrap; gap: 8px; position: relative; z-index: 1; }\n.chip {\n  background: rgba(255,255,255,.15);\n  border: 1px solid rgba(255,255,255,.28);\n  padding: 5px 14px;\n  border-radius: 30px;\n  font-size: 12px;\n  backdrop-filter: blur(4px);\n  display: inline-flex; align-items: center; gap: 6px;\n}\n.chip .dot { width: 7px; height: 7px; border-radius: 50%; background: #a6e07f; }\n\n/* ===== KPI strip ===== */\n.kpi-strip {\n  display: grid;\n  grid-template-columns: repeat(6, 1fr);\n  gap: 10px;\n  margin-top: 18px;\n}\n.kpi {\n  background: var(--card);\n  border: 1px solid var(--line);\n  border-radius: 12px;\n  padding: 14px 12px;\n  text-align: center;\n  box-shadow: var(--shadow);\n  transition: transform .15s, box-shadow .15s;\n}\n.kpi:hover { transform: translateY(-2px); box-shadow: 0 6px 16px rgba(0,0,0,.08); }\n.kpi .v { font-size: 22px; font-weight: 800; color: var(--brand); line-height: 1.2; }\n.kpi .l { font-size: 11px; color: var(--muted); margin-top: 3px; }\n.kpi.crit .v { color: var(--crit); }\n.kpi.med .v { color: var(--med); }\n.kpi.info .v { color: var(--info); }\n\n/* ===== Layout ===== */\n.layout {\n  display: grid;\n  grid-template-columns: 240px 1fr;\n  gap: 20px;\n  margin-top: 22px;\n  align-items: start;\n}\n.toc {\n  position: sticky; top: 14px;\n  background: var(--card);\n  border: 1px solid var(--line);\n  border-radius: var(--radius);\n  padding: 16px;\n  font-size: 13px;\n  box-shadow: var(--shadow);\n}\n.toc h3 { margin: 0 0 12px; font-size: 14px; color: var(--brand); display: flex; align-items: center; gap: 8px; }\n.toc h3::before { content: "☰"; font-size: 15px; }\n.toc ol { margin: 0; padding: 0; list-style: none; display: flex; flex-direction: column; gap: 2px; }\n.toc a {\n  display: block; padding: 7px 10px; border-radius: 8px;\n  color: #33423a; font-size: 12.5px; text-decoration: none;\n  transition: background .15s, color .15s;\n}\n.toc a:hover { background: var(--brand-light); color: var(--brand); }\n.toc a.active { background: var(--brand); color: #fff; }\n\n/* ===== Cards ===== */\n.card {\n  background: var(--card);\n  border: 1px solid var(--line);\n  border-radius: var(--radius);\n  padding: 22px 24px;\n  margin-bottom: 18px;\n  box-shadow: var(--shadow);\n  scroll-margin-top: 16px;\n}\n.card h2 {\n  margin: 0 0 16px; font-size: 18px; color: var(--brand);\n  display: flex; align-items: center; gap: 10px;\n}\n.card h2 .num {\n  background: var(--brand-light); color: var(--brand);\n  font-size: 12px; font-weight: 800;\n  width: 28px; height: 28px; border-radius: 50%;\n  display: inline-flex; align-items: center; justify-content: center;\n  flex: 0 0 auto;\n}\n.card h3 { margin: 18px 0 10px; font-size: 15px; color: #2f4d22; }\n\n/* ===== Tables ===== */\n.tbl-wrap { overflow-x: auto; border-radius: 10px; border: 1px solid var(--line); }\ntable { width: 100%; border-collapse: collapse; font-size: 13px; background: #fff; }\nthead th {\n  background: var(--brand-light); color: var(--brand);\n  font-weight: 700; text-align: right; padding: 11px 14px;\n  border-bottom: 2px solid var(--brand-border); white-space: nowrap;\n}\ntbody td { padding: 10px 14px; border-bottom: 1px solid var(--line); vertical-align: top; }\ntbody tr:nth-child(even) { background: #fafcf8; }\ntbody tr:hover { background: #f2f9ee; }\ntbody tr:last-child td { border-bottom: none; }\n.mono, .url-box {\n  font-family: Consolas, monospace; font-size: 12px;\n  direction: ltr; text-align: left; unicode-bidi: plaintext;\n  overflow-wrap: anywhere;\n}\n\n/* ===== Stats ===== */\n.stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 14px 0; }\n.stat {\n  background: linear-gradient(180deg, #f8fbf6 0%, #fff 100%);\n  border: 1px solid var(--brand-border); border-radius: 10px;\n  padding: 14px 16px;\n}\n.stat .lbl { font-size: 12px; color: var(--muted); margin-bottom: 4px; }\n.stat .val { font-size: 23px; font-weight: 800; color: var(--brand); line-height: 1.2; }\n\n/* ===== Risk bar ===== */\n.riskbar {\n  display: flex; height: 16px; border-radius: 10px; overflow: hidden;\n  margin: 12px 0 8px; border: 1px solid var(--line);\n}\n.riskbar span { display: block; height: 100%; }\n.rb-crit { background: var(--crit); }\n.rb-high { background: var(--high); }\n.rb-med { background: #e6a23c; }\n.rb-low { background: #8fbc4f; }\n.rb-info { background: #7fb3d5; }\n.legend { display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; color: var(--muted); margin-top: 6px; }\n.legend i { display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-left: 6px; vertical-align: middle; }\n\n/* ===== Badges ===== */\n.badge {\n  display: inline-block; padding: 2px 11px; border-radius: 20px;\n  font-size: 11.5px; font-weight: 700; white-space: nowrap;\n}\n.b-crit { background: #fbe6e4; color: var(--crit); }\n.b-high { background: #fcece1; color: var(--high); }\n.b-med { background: #fdf2e0; color: var(--med); }\n.b-low { background: #eef6e2; color: var(--low); }\n.b-info { background: #e6f2fa; color: var(--info); }\n.b-ok { background: var(--brand-light); color: var(--brand); }\n.b-muted { background: #eef1f0; color: #5b6b63; }\n\n/* ===== Page tree ===== */\n.tree-wrap {\n  background: #fbfdfa; border: 1px solid var(--line);\n  border-radius: 12px; padding: 16px 18px; margin: 14px 0 22px;\n}\n.tree-title { font-size: 13px; color: var(--muted); margin: 0 0 12px; font-weight: 700; }\n.tree, .tree ul { list-style: none; margin: 0; padding-right: 20px; }\n.tree > li { padding-right: 0; }\n.tree li { position: relative; padding: 3px 0; font-size: 13.5px; }\n.tree li > .node {\n  display: inline-flex; align-items: center; gap: 8px;\n  padding: 6px 12px; border-radius: 8px; cursor: pointer;\n  transition: background .15s, color .15s; color: #2f3d34;\n  text-decoration: none; font-size: 13px;\n}\n.tree li > .node:hover { background: var(--brand-light); color: var(--brand); }\n.tree li > .node .icon { font-size: 12px; color: var(--brand); width: 14px; text-align: center; }\n.tree li > .node .count {\n  background: #eef2ee; color: #4a5a50; font-size: 10.5px;\n  padding: 1px 8px; border-radius: 10px; font-weight: 700;\n}\n.tree li > .node .riskdot { width: 8px; height: 8px; border-radius: 50%; flex: 0 0 auto; }\n.rd-crit { background: var(--crit); }\n.rd-med { background: var(--med); }\n.rd-low { background: var(--low); }\n.rd-info { background: var(--info); }\n.tree ul { position: relative; }\n.tree ul:before {\n  content: ""; position: absolute; top: 0; bottom: 8px;\n  right: 6px; border-right: 1px dashed #cfe0c5;\n}\n.tree ul li:before {\n  content: ""; position: absolute; top: 18px; right: -14px;\n  width: 14px; border-top: 1px dashed #cfe0c5;\n}\n.tree-branch { margin: 2px 0 4px 28px; font-size: 12px; }\n.tree-branch > summary {\n  display: inline-flex; align-items: center; gap: 7px;\n  cursor: pointer; color: var(--muted); padding: 3px 8px;\n  border-radius: 7px; list-style: none; font-size: 12px;\n}\n.tree-branch > summary::-webkit-details-marker { display: none; }\n.tree-branch > summary:before { content: "＋"; font-size: 11px; color: var(--brand); }\n.tree-branch[open] > summary:before { content: "−"; }\n.tree-branch > summary:hover { background: var(--brand-light); color: var(--brand); }\n\n/* ===== Page sections ===== */\n.page-section {\n  scroll-margin-top: 16px; border-top: 3px solid var(--brand-light);\n  padding-top: 18px; margin-top: 26px;\n}\n.page-section h3 {\n  display: flex; align-items: center; gap: 10px;\n  font-size: 16px; color: var(--brand);\n  border-bottom: 2px solid var(--brand-border);\n  padding-bottom: 8px; margin: 0 0 12px;\n}\n.pnum {\n  background: var(--brand); color: #fff; font-size: 11px;\n  width: 24px; height: 24px; border-radius: 50%;\n  display: inline-flex; align-items: center; justify-content: center;\n  flex: 0 0 auto;\n}\n.page-meta {\n  display: flex; flex-wrap: wrap; gap: 16px;\n  font-size: 12.5px; color: var(--muted); margin-bottom: 10px;\n}\n.page-meta strong { color: #33423a; }\n.url-box {\n  background: #f1f4f2; border: 1px solid #e1e6e3;\n  border-radius: 6px; padding: 9px 12px; margin: 8px 0;\n}\n\n/* ===== Findings ===== */\n.finding {\n  border: 1px solid var(--line); border-radius: 10px;\n  margin: 12px 0; background: #fff; overflow: hidden;\n  break-inside: avoid;\n  transition: box-shadow .15s;\n}\n.finding:hover { box-shadow: 0 2px 10px rgba(0,0,0,.06); }\n.finding > summary {\n  cursor: pointer; list-style: none; padding: 13px 15px;\n  display: flex; align-items: center; gap: 10px;\n  flex-wrap: wrap; background: #fbfdfa;\n  transition: background .15s;\n}\n.finding > summary:hover { background: #f4faf0; }\n.finding > summary::-webkit-details-marker { display: none; }\n.finding .idx {\n  background: var(--brand-light); color: var(--brand);\n  font-size: 11.5px; font-weight: 800; border-radius: 6px; padding: 2px 9px;\n}\n.finding .title { font-weight: 700; font-size: 13.5px; color: #2c3a30; flex: 1 1 auto; }\n.finding .arrow { color: var(--muted); font-size: 11px; transition: transform .2s; }\n.finding[open] .arrow { transform: rotate(180deg); }\n.finding .body { padding: 4px 15px 18px; border-top: 1px solid var(--line); }\n.meta-grid {\n  display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;\n  margin: 14px 0; background: #f7faf5; border: 1px solid #e6eee1;\n  border-radius: 8px; padding: 12px;\n}\n.meta-grid div { font-size: 12px; }\n.meta-grid strong {\n  color: #5b6b60; font-weight: 400; display: block;\n  font-size: 11px; margin-bottom: 2px;\n}\n.meta-grid code {\n  background: #e9efec; padding: 2px 7px; border-radius: 4px;\n  font-size: 11.5px; font-family: Consolas, monospace;\n}\n.ev {\n  background: #f5f7f6; border: 1px solid #e4e9e6;\n  border-radius: 6px; padding: 9px 11px; font-size: 11.5px;\n  direction: ltr; text-align: left; white-space: pre-wrap;\n  word-break: break-word; overflow-wrap: anywhere;\n  margin: 6px 0; font-family: Consolas, monospace;\n  max-height: 180px; overflow-y: auto;\n}\n.fix {\n  background: #f4faf1; border: 1px solid #dcebd3;\n  border-radius: 6px; padding: 10px 12px; font-size: 12.5px; margin: 10px 0;\n}\n.fix strong { color: var(--brand); }\n.note {\n  background: #fbfaf3; border: 1px solid #eee6cc;\n  border-radius: 8px; padding: 12px 14px; font-size: 13px; color: #6b5b2e;\n}\n.empty { color: var(--muted); font-size: 13px; font-style: italic; }\nfooter { text-align: center; color: var(--muted); font-size: 12px; padding: 30px 0 0; }\n\n/* ===== Filter bar ===== */\n.filter-bar {\n  display: flex; flex-wrap: wrap; gap: 8px; margin: 14px 0;\n  align-items: center;\n}\n.filter-bar .flabel { font-size: 12px; color: var(--muted); margin-left: 4px; }\n.fbtn {\n  background: #fff; border: 1px solid var(--line);\n  padding: 5px 14px; border-radius: 20px; font-size: 12px;\n  cursor: pointer; font-family: inherit; transition: all .15s;\n  color: #3a4a3a;\n}\n.fbtn:hover { border-color: var(--brand-border); background: var(--brand-light); }\n.fbtn.active { background: var(--brand); color: #fff; border-color: var(--brand); }\n\n/* ===== Responsive ===== */\n@media (max-width: 1000px) {\n  .kpi-strip { grid-template-columns: repeat(3, 1fr); }\n}\n@media (max-width: 900px) {\n  .layout { grid-template-columns: 1fr; }\n  .toc { position: static; }\n}\n@media (max-width: 760px) {\n  .stats { grid-template-columns: repeat(2, 1fr); }\n  .kpi-strip { grid-template-columns: repeat(2, 1fr); }\n}\n@media (max-width: 640px) {\n  .meta-grid { grid-template-columns: 1fr; }\n  .hero h1 { font-size: 20px; }\n  .card { padding: 18px 16px; }\n}\n@media (max-width: 420px) {\n  .stats { grid-template-columns: 1fr; }\n  .kpi-strip { grid-template-columns: 1fr; }\n}\n@media print {\n  body { background: #fff; }\n  .toc, .filter-bar, .tree-wrap { display: none; }\n  .layout { grid-template-columns: 1fr; }\n  .card, .finding { box-shadow: none; break-inside: avoid; }\n  .hero { box-shadow: none; }\n}\n\n.rk{--h:#b3261e;--m:#d97706;--l:#6a9a2a;--i:#0284c7}\n.rk-two{display:grid;grid-template-columns:minmax(260px,1fr) 2fr;gap:22px;align-items:center;margin-bottom:6px}@media(max-width:820px){.rk-two{grid-template-columns:1fr}}\n.rk-donutbox{display:flex;align-items:center;gap:20px;flex-wrap:wrap;justify-content:center}\n.rk-donut{width:170px;height:170px;border-radius:50%;position:relative;flex:0 0 auto}.rk-donut:after{content:"";position:absolute;inset:26px;background:var(--card);border-radius:50%}\n.rk-donut b{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:1;font-size:26px;line-height:1.2}.rk-donut b small{font-size:11px;font-weight:normal;color:var(--muted)}\n.rk-leg{display:grid;gap:7px;font-size:13px}.rk-leg div{display:flex;align-items:center;gap:8px}.rk-leg i{width:11px;height:11px;border-radius:3px}.rk-leg span{margin-right:auto;color:var(--muted);padding-right:14px}\n.rk-bars{display:grid;gap:12px}.rk-row{display:grid;grid-template-columns:120px 1fr 40px;gap:10px;align-items:center;font-size:13px}.rk-track{display:flex;height:18px;border-radius:9px;overflow:hidden;background:var(--line)}.rk-track span{height:100%}\n@media(max-width:560px){.rk-row{grid-template-columns:90px 1fr 34px}}\n.rk-heat{overflow-x:auto}.rk-heat table{border-collapse:separate;border-spacing:4px;width:100%;font-size:12.5px;min-width:600px;background:transparent}\n.rk-heat th{font-weight:normal;color:var(--muted);padding:2px 6px;text-align:center;background:transparent;border:0}.rk-heat td{text-align:center;border-radius:7px;padding:6px 4px;font-weight:bold;border:0}\n.rk-heat td:first-child{text-align:right;min-width:230px;font-weight:normal}.rk-heat tbody tr,.rk-heat tbody tr:hover{background:transparent}.rk-c0{color:var(--muted);font-weight:normal}'

        # --- Static JS (verbatim from target) ---
        report_js_static = '(function(){\n  // TOC active state on scroll\n  var tocLinks = document.querySelectorAll(\'.toc a\');\n  var sections = [];\n  tocLinks.forEach(function(link){\n    var id = link.getAttribute(\'href\').substring(1);\n    var el = document.getElementById(id);\n    if(el) sections.push({id: id, el: el, link: link});\n  });\n  function updateToc(){\n    var scrollPos = window.scrollY + 120;\n    var current = sections[0];\n    for(var i=0;i<sections.length;i++){\n      if(sections[i].el.offsetTop <= scrollPos) current = sections[i];\n    }\n    tocLinks.forEach(function(l){ l.classList.remove(\'active\'); });\n    if(current) current.link.classList.add(\'active\');\n  }\n  window.addEventListener(\'scroll\', updateToc);\n  updateToc();\n\n  // Smooth scroll for tree nodes\n  document.querySelectorAll(\'.tree a.node\').forEach(function(a){\n    a.addEventListener(\'click\', function(e){\n      var target = document.querySelector(this.getAttribute(\'href\'));\n      if(target){\n        e.preventDefault();\n        target.scrollIntoView({behavior:\'smooth\', block:\'start\'});\n        // briefly highlight\n        target.style.transition = \'box-shadow .3s\';\n        target.style.boxShadow = \'0 0 0 3px #2e6b14\';\n        setTimeout(function(){ target.style.boxShadow = \'\'; }, 1200);\n      }\n    });\n  });\n\n  // Risk filter (optional simple)\n  var filterBar = document.createElement(\'div\');\n  filterBar.className = \'filter-bar\';\n  filterBar.innerHTML = \'<span class="flabel">فیلتر ریسک:</span>\';\n  var levels = [\n    {key:\'all\', label:\'همه\', cls:\'\'},\n    {key:\'crit\', label:\'بحرانی\', cls:\'b-crit\'},\n    {key:\'med\', label:\'متوسط\', cls:\'b-med\'},\n    {key:\'low\', label:\'کم\', cls:\'b-low\'},\n    {key:\'info\', label:\'اطلاع\u200cرسانی\', cls:\'b-info\'}\n  ];\n  levels.forEach(function(lv){\n    var btn = document.createElement(\'button\');\n    btn.className = \'fbtn\' + (lv.key===\'all\'?\' active\':\'\');\n    btn.textContent = lv.label;\n    btn.dataset.level = lv.key;\n    btn.addEventListener(\'click\', function(){\n      document.querySelectorAll(\'.filter-bar .fbtn\').forEach(function(b){ b.classList.remove(\'active\'); });\n      this.classList.add(\'active\');\n      var lvl = this.dataset.level;\n      document.querySelectorAll(\'.finding\').forEach(function(f){\n        if(lvl === \'all\'){ f.style.display = \'\'; return; }\n        var badge = f.querySelector(\'.badge\');\n        if(!badge){ f.style.display = \'\'; return; }\n        var cls = badge.className;\n        var match = false;\n        if(lvl === \'crit\' && cls.indexOf(\'b-crit\') !== -1) match = true;\n        if(lvl === \'med\' && cls.indexOf(\'b-med\') !== -1) match = true;\n        if(lvl === \'low\' && cls.indexOf(\'b-low\') !== -1) match = true;\n        if(lvl === \'info\' && cls.indexOf(\'b-info\') !== -1) match = true;\n        f.style.display = match ? \'\' : \'none\';\n      });\n    });\n    filterBar.appendChild(btn);\n  });\n  var pagesSection = document.getElementById(\'pages\');\n  if(pagesSection){\n    var firstCard = pagesSection.querySelector(\'.card\');\n    if(firstCard) firstCard.parentNode.insertBefore(filterBar, firstCard.nextSibling);\n  }\n\n  // Expand all / collapse all (light)\n  var ctrl = document.createElement(\'div\');\n  ctrl.style.cssText = \'display:flex;gap:8px;margin:10px 0;flex-wrap:wrap\';\n  var btnExpand = document.createElement(\'button\');\n  btnExpand.className = \'fbtn\';\n  btnExpand.textContent = \'باز کردن همه یافته\u200cها\';\n  btnExpand.addEventListener(\'click\', function(){\n    document.querySelectorAll(\'.finding\').forEach(function(f){ f.open = true; });\n  });\n  var btnCollapse = document.createElement(\'button\');\n  btnCollapse.className = \'fbtn\';\n  btnCollapse.textContent = \'بستن همه یافته\u200cها\';\n  btnCollapse.addEventListener(\'click\', function(){\n    document.querySelectorAll(\'.finding\').forEach(function(f){ f.open = false; });\n  });\n  ctrl.appendChild(btnExpand);\n  ctrl.appendChild(btnCollapse);\n  if(filterBar.parentNode) filterBar.parentNode.insertBefore(ctrl, filterBar.nextSibling);\n})();'

        # --- Chart JS (target template with dynamic data injected) ---
        report_js_charts = (
            '(function(){\nconst RISK={h:{n:\'زیاد / بحرانی\',c:\'--h\',b:\'b-crit\'},m:{n:\'متوسط\',c:\'--m\',b:\'b-med\'},l:{n:\'کم\',c:\'--l\',b:\'b-low\'},i:{n:\'اطلاع\u200cرسانی\',c:\'--i\',b:\'b-info\'}};\nconst totals=__TOTALS__,TOTAL=__TOTAL__,ORD=\'hmli\';\nconst F=__F_DATA__.map(a=>({id:a[0],t:a[1],r:a[2]}));\nconst P=__P_DATA__;\nconst fa=n=>Number(n).toLocaleString(\'fa-IR\'),$=id=>document.getElementById(id),V=c=>\'var(\'+c+\')\';\nconst fm={};F.forEach(f=>fm[f.id]=f);\nconst pr=(p,r)=>Object.keys(p.d).reduce((a,k)=>a+(fm[k].r===r?p.d[k]:0),0);\nlet acc=0;const seg=ORD.split(\'\').map(k=>{const a=acc;acc+=totals[k]/TOTAL*100;return V(RISK[k].c)+\' \'+a+\'% \'+acc+\'%\'});\n$(\'rkDonut\').style.background=\'conic-gradient(\'+seg.join(\',\')+\')\';\n$(\'rkDonut\').innerHTML=\'<b>\'+fa(TOTAL)+\'<small>رخداد</small></b>\';\n$(\'rkLeg\').innerHTML=ORD.split(\'\').map(k=>\'<div><i style="background:\'+V(RISK[k].c)+\'"></i>\'+RISK[k].n+\'<span>\'+fa(totals[k])+\' (\'+fa((totals[k]/TOTAL*100).toFixed(1))+\'٪)</span></div>\').join(\'\');\nconst mx=Math.max.apply(null,P.map(p=>p.e));\n$(\'rkBars\').innerHTML=P.map(p=>\'<div class="rk-row"><div>\'+p.n+\'</div><div class="rk-track">\'+ORD.split(\'\').map(r=>{const v=pr(p,r);return v?\'<span title="\'+RISK[r].n+\': \'+fa(v)+\'" style="width:\'+v/mx*100+\'%;background:\'+V(RISK[r].c)+\'"></span>\':\'\'}).join(\'\')+\'</div><b>\'+fa(p.e)+\'</b></div>\').join(\'\');\nconst hf=F.slice().sort((a,b)=>ORD.indexOf(a.r)-ORD.indexOf(b.r));\n$(\'rkHeat\').innerHTML=\'<table><thead><tr><th></th>\'+P.map((p,i)=>\'<th>\'+fa(i+1)+\'. \'+p.n+\'</th>\').join(\'\')+\'</tr></thead><tbody>\'+hf.map(f=>\'<tr><td><span class="badge \'+RISK[f.r].b+\'">\'+RISK[f.r].n+\'</span> \'+f.t+\'</td>\'+P.map(p=>{const v=p.d[f.id]||0;if(!v)return \'<td class="rk-c0">–</td>\';const o=Math.round(Math.min(.18+v/25*.6,.78)*100);return \'<td style="background:color-mix(in srgb,\'+V(RISK[f.r].c)+\' \'+o+\'%,transparent);color:\'+(f.r===\'h\'||v>12?\'#fff\':\'var(--ink)\')+\'">\'+fa(v)+\'</td>\'}).join(\'\')+\'</tr>\').join(\'\')+\'</tbody></table>\';\n})();'
            .replace("__TOTALS__", totals_json)
            .replace("__TOTAL__", total_json)
            .replace("__F_DATA__", f_json)
            .replace("__P_DATA__", p_json)
        )

        # --- HTML body (plain string + .replace for dynamic values) ---
        html_template = """<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>داشبورد ارزیابی امنیتی | __APP_FIRST__</title>
<style>
__CSS__
</style>
</head>
<body>
<div class="wrap">

  <header class="hero">
    <h1>گزارش ارزیابی امنیتی</h1>
    <p class="sub">تحلیل امنیتی اپلیکیشن‌های Oracle APEX با کمک هوش مصنوعی</p>
    <div class="chips">
      __APP_CHIPS____ID_CHIP____STATUS_CHIP____DATE_CHIP__
    </div>
  </header>

  __KPI_HTML__

  <div class="layout">
    <nav class="toc" aria-label="فهرست مطالب">
      <h3>فهرست مطالب</h3>
      <ol>
        <li><a href="#info" class="active">__S1__. اطلاعات ارزیابی</a></li>
        <li><a href="#summary">__S2__. خلاصه مدیریتی</a></li>
        <li><a href="#risk">__S3__. توزیع ریسک</a></li>
        <li><a href="#page-events">__S4__. رخدادها به تفکیک صفحه</a></li>
        <li><a href="#matrix">__S5__. ماتریس یافته × صفحه</a></li>
        <li><a href="#apps">__S6__. اپلیکیشن‌های ارزیابی‌شده</a></li>
        <li><a href="#errors">__S7__. خطاهای جمع‌آوری</a></li>
        <li><a href="#details">__S8__. نتایج تفصیلی</a></li>
        <li><a href="#pages">__S9__. صفحات و یافته‌ها</a></li>
      </ol>
    </nav>

    <main>

      <section class="card" id="info">
        <h2><span class="num">__S1__</span> اطلاعات ارزیابی</h2>
        __METADATA_HTML__
      </section>

      <section class="card" id="summary">
        <h2><span class="num">__S2__</span> خلاصه مدیریتی و شاخص‌های ارزیابی</h2>
        __SUMMARY_STATS__
      </section>

      <section class="card rk" id="risk">
        <h2><span class="num">__S3__</span> توزیع سطح ریسک</h2>
        <div class="rk-donutbox"><div class="rk-donut" id="rkDonut"></div><div class="rk-leg" id="rkLeg"></div></div>
      </section>

      <section class="card rk" id="page-events">
        <h2><span class="num">__S4__</span> رخدادها به تفکیک صفحه</h2>
        <div class="rk-bars" id="rkBars"></div>
      </section>

      <section class="card rk" id="matrix">
        <h2><span class="num">__S5__</span> ماتریس یافته × صفحه</h2>
        <div class="rk-heat" id="rkHeat"></div>
      </section>

      <section class="card" id="apps">
        <h2><span class="num">__S6__</span> اپلیکیشن‌های ارزیابی‌شده</h2>
        <ul style="margin:0;padding-right:20px">__APP_LIST__</ul>
      </section>

      <section class="card" id="errors">
        <h2><span class="num">__S7__</span> خطاهای جمع‌آوری اطلاعات</h2>
        __ERRORS_HTML__
      </section>

      <section id="details">
        <h2 style="font-size:19px;color:var(--brand);display:flex;align-items:center;gap:10px;margin:0 0 14px"><span class="num" style="background:var(--brand-light);color:var(--brand);font-size:12px;font-weight:800;width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center">__S8__</span> نتایج تفصیلی ارزیابی</h2>
        __DETAILS_HTML__
      </section>

      <section id="pages">
        <h2 style="font-size:19px;color:var(--brand);display:flex;align-items:center;gap:10px;margin:26px 0 14px"><span class="num" style="background:var(--brand-light);color:var(--brand);font-size:12px;font-weight:800;width:28px;height:28px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center">__S9__</span> صفحات و یافته‌های امنیتی</h2>
        __PAGES_HTML__
      </section>

      <footer>
        <p>گزارش ارزیابی امنیتی — __APP_FIRST__ | شناسه: __CREATED_ID__ | تولید شده در __GENERATED_DATE__</p>
      </footer>

    </main>
  </div>
</div>

<script>
__JS_STATIC__
</script>
<script>
__JS_CHARTS__
</script>
</body></html>"""

        html_content = html_template \
            .replace("__APP_FIRST__", app_first) \
            .replace("__CSS__", report_css) \
            .replace("__APP_CHIPS__", app_chips) \
            .replace("__ID_CHIP__", id_chip) \
            .replace("__STATUS_CHIP__", status_chip) \
            .replace("__DATE_CHIP__", date_chip) \
            .replace("__KPI_HTML__", kpi_html) \
            .replace("__S1__", sec_nums[0]) \
            .replace("__S2__", sec_nums[1]) \
            .replace("__S3__", sec_nums[2]) \
            .replace("__S4__", sec_nums[3]) \
            .replace("__S5__", sec_nums[4]) \
            .replace("__S6__", sec_nums[5]) \
            .replace("__S7__", sec_nums[6]) \
            .replace("__S8__", sec_nums[7]) \
            .replace("__S9__", sec_nums[8]) \
            .replace("__METADATA_HTML__", metadata_html) \
            .replace("__SUMMARY_STATS__", summary_stats) \
            .replace("__APP_LIST__", app_list) \
            .replace("__ERRORS_HTML__", errors_html) \
            .replace("__DETAILS_HTML__", "".join(details_html)) \
            .replace("__PAGES_HTML__", "".join(pages_html)) \
            .replace("__CREATED_ID__", created_id) \
            .replace("__GENERATED_DATE__", generated_date) \
            .replace("__JS_STATIC__", report_js_static) \
            .replace("__JS_CHARTS__", report_js_charts)

        file_path = self.report_directory / f"{report_id}.html"
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(html_content)
        return str(file_path)


# =================================
# Service Initialization
# =================================

security_report_service = SecurityReportService()
