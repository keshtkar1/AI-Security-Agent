
import os
import re
import requests

from dotenv import load_dotenv
from urllib.parse import (
    urlparse,
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode
)


# =================================
# Load Environment Variables
# =================================
load_dotenv()


def get_required_env(name):

    value = os.getenv(name)

    if not value or not value.strip():
        raise ValueError(
            f"Environment variable {name} is not configured"
        )

    return value.strip()


# =================================
# ZAP Service
# =================================
class ZAPService:

    def __init__(self):

        self.base_url = get_required_env(
            "ZAP_BASE_URL"
        ).rstrip("/")

        self.api_key = get_required_env(
            "ZAP_API_KEY"
        )

        self.target_base_url = get_required_env(
            "TARGET_BASE_URL"
        ).rstrip("/")

        self.target_workspace = get_required_env(
            "TARGET_WORKSPACE"
        )

        self.allowed_apps = {
            app.strip()
            for app in get_required_env(
                "TARGET_APPS"
            ).split(",")
            if app.strip()
        }

        self.timeout = int(
            get_required_env("HTTP_TIMEOUT")
        )

        self.alert_page_size = 500

        self._validate_configuration()

    # =================================
    # Configuration Validation
    # =================================
    def _validate_configuration(self):

        zap_url = urlparse(self.base_url)

        target_url = urlparse(
            self.target_base_url
        )

        if (
            zap_url.scheme not in ("http", "https")
            or not zap_url.hostname
            or zap_url.username is not None
            or zap_url.password is not None
            or zap_url.query
            or zap_url.fragment
        ):
            raise ValueError("Invalid ZAP_BASE_URL")

        if (
            target_url.scheme not in ("http", "https")
            or not target_url.hostname
            or target_url.path not in ("", "/")
            or target_url.username is not None
            or target_url.password is not None
            or target_url.query
            or target_url.fragment
        ):
            raise ValueError("Invalid TARGET_BASE_URL")

        if not re.fullmatch(
            r"[A-Za-z0-9_-]+",
            self.target_workspace
        ):
            raise ValueError("Invalid TARGET_WORKSPACE")

        if not self.allowed_apps:
            raise ValueError("TARGET_APPS is empty")

        for application in self.allowed_apps:

            if not re.fullmatch(
                r"[A-Za-z0-9_-]+",
                application
            ):
                raise ValueError(
                    "Invalid application name in TARGET_APPS"
                )

        if self.timeout <= 0:
            raise ValueError(
                "HTTP_TIMEOUT must be greater than zero"
            )

    # =================================
    # ZAP API Request
    # =================================
    def _request(
        self,
        component,
        section,
        action,
        params=None
    ):

        url = (
            f"{self.base_url}/JSON/"
            f"{component}/{section}/{action}/"
        )

        request_params = {
            "apikey": self.api_key
        }

        if params:
            request_params.update(params)

        response = requests.get(
            url,
            params=request_params,
            timeout=self.timeout
        )

        response.raise_for_status()

        result = response.json()

        if not isinstance(result, dict):
            raise RuntimeError(
                "Invalid response from ZAP API"
            )

        if "code" in result and "message" in result:
            raise RuntimeError(
                "ZAP API returned an error"
            )

        return result

    # =================================
    # Application Validation
    # =================================
    def _validate_application(self, application):

        if (
            not isinstance(application, str)
            or not application.strip()
        ):
            raise ValueError(
                "Application name is required"
            )

        application = application.strip()

        if application not in self.allowed_apps:
            raise ValueError(
                "Application is outside the authorized scope"
            )

        return application

    # =================================
    # Validate Spider Scan ID
    # =================================
    def _validate_scan_id(self, scan_id):

        scan_id = str(scan_id).strip()

        if not re.fullmatch(r"\d+", scan_id):
            raise ValueError(
                "Invalid Spider scan ID"
            )

        return scan_id

    # =================================
    # Build Authorized Application URL
    # =================================
    def get_application_url(self, application):

        application = self._validate_application(
            application
        )

        target_url = (
            f"{self.target_base_url}/ords/r/"
            f"{self.target_workspace}/"
            f"{application}/"
        )

        return self._validate_target(target_url)

    # =================================
    # Target URL Validation
    # =================================
    def _validate_target(self, target_url):

        if not isinstance(target_url, str):
            raise ValueError("Invalid target URL")

        parsed = urlparse(target_url)

        base = urlparse(
            self.target_base_url
        )

        try:

            parsed_port = parsed.port
            base_port = base.port

        except ValueError:

            raise ValueError(
                "Invalid target URL port"
            )

        if (
            parsed.scheme != base.scheme
            or parsed.hostname != base.hostname
            or parsed_port != base_port
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError(
                "Target is outside the authorized scope"
            )

        if parsed.query or parsed.fragment:
            raise ValueError(
                "Target URL cannot contain query or fragment"
            )

        if "\\" in parsed.path or "%" in parsed.path:
            raise ValueError(
                "Invalid target URL path"
            )

        path_parts = parsed.path.strip("/").split("/")

        if len(path_parts) < 4:
            raise ValueError(
                "Invalid target application path"
            )

        if (
            path_parts[0] != "ords"
            or path_parts[1] != "r"
            or path_parts[2] != self.target_workspace
            or path_parts[3] not in self.allowed_apps
        ):
            raise ValueError(
                "Target application is not authorized"
            )

        return target_url

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

            alert_port = parsed_alert.port
            target_port = parsed_target.port

        except ValueError:

            return False

        # Validate origin
        if (
            parsed_alert.scheme != parsed_target.scheme
            or parsed_alert.hostname != parsed_target.hostname
            or alert_port != target_port
            or parsed_alert.username is not None
            or parsed_alert.password is not None
        ):
            return False

        # Reject invalid path representations
        if (
            "\\" in parsed_alert.path
            or "%" in parsed_alert.path
        ):
            return False

        # Exact application path boundary
        application_path = parsed_target.path.rstrip("/")
        alert_path = parsed_alert.path.rstrip("/")

        if (
            alert_path != application_path
            and not alert_path.startswith(
                application_path + "/"
            )
        ):
            return False

        return True

    # =================================
    # Mask Sensitive URL Parameters
    # =================================
    def _mask_url(self, url):

        if not isinstance(url, str):
            return ""

        parsed = urlsplit(url)

        sensitive_params = {
            "session",
            "sessionid",
            "p_context",
            "cs",
            "dialogcs",
            "csrf",
            "csrf_token",
            "p_checksum",
            "checksum",
            "ck",
            "p_session",
            "apex_session",
            "sid",
            "token",
            "access_token",
            "auth",
            "authorization"
        }

        query = []

        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            if key.lower() in sensitive_params:
                value = "[MASKED]"

            query.append((key, value))

        sanitized_path = re.sub(
            r"(?i)(/ords/r/[^/?#]+/[^/?#]+/[^/?#]+/)\d{6,}(?=/|$)",
            r"\1[MASKED]",
            parsed.path
        )

        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            sanitized_path,
            urlencode(query),
            ""
        ))

    # =================================
    # ZAP Version
    # =================================
    def get_version(self):

        return self._request(
            "core",
            "view",
            "version"
        )

    # =================================
    # ZAP Connection Status
    # =================================
    def is_connected(self):

        try:

            result = self.get_version()

            return {
                "connected": True,
                "version": result.get("version")
            }

        except Exception:

            return {
                "connected": False,
                "error": "Unable to connect to ZAP"
            }

    # =================================
    # Spider Scan
    # =================================
    def start_spider(self, target_url):

        target_url = self._validate_target(
            target_url
        )

        result = self._request(
            "spider",
            "action",
            "scan",
            {
                "url": target_url,
                "recurse": "true",
                "subtreeOnly": "true"
            }
        )

        return {
            "scan_id": result.get("scan"),
            "status": "started",
            "target": target_url
        }

    # =================================
    # Spider Status
    # =================================
    def get_spider_status(self, scan_id):

        scan_id = self._validate_scan_id(
            scan_id
        )

        result = self._request(
            "spider",
            "view",
            "status",
            {
                "scanId": scan_id
            }
        )

        return {
            "scan_id": scan_id,
            "progress": int(
                result.get("status", 0)
            )
        }

    # =================================
    # Get Existing Spider Results
    # =================================
    def get_spider_results(
        self,
        application,
        scan_id
    ):

        application = self._validate_application(
            application
        )

        scan_id = self._validate_scan_id(
            scan_id
        )

        target_url = self.get_application_url(
            application
        )

        result = self._request(
            "spider",
            "view",
            "results",
            {
                "scanId": scan_id
            }
        )

        urls = result.get("results", [])

        if not isinstance(urls, list):
            raise RuntimeError(
                "Invalid Spider results response"
            )

        discovered_urls = []

        for url in urls:

            if not isinstance(url, str):
                continue

            if not self._is_alert_in_application_scope(
                {"url": url},
                target_url
            ):
                continue

            discovered_urls.append(
                self._mask_url(url)
            )

        discovered_urls = sorted(
            set(discovered_urls)
        )

        return {
            "application": application,
            "scan_id": scan_id,
            "total_discovered_urls": len(discovered_urls),
            "urls": discovered_urls
        }

    # =================================
    # Get URLs From ZAP History
    # =================================
    def get_application_urls(self, application):

        application = self._validate_application(
            application
        )

        target_url = self.get_application_url(
            application
        )

        result = self._request(
            "core",
            "view",
            "urls",
            {
                "baseurl": target_url
            }
        )

        urls = result.get("urls", [])

        if not isinstance(urls, list):
            raise RuntimeError(
                "Invalid ZAP URLs response"
            )

        visited_urls = []

        for url in urls:

            if not isinstance(url, str):
                continue

            if not self._is_alert_in_application_scope(
                {"url": url},
                target_url
            ):
                continue

            visited_urls.append(
                self._mask_url(url)
            )

        visited_urls = sorted(
            set(visited_urls)
        )

        return {
            "application": application,
            "total_visited_urls": len(visited_urls),
            "urls": visited_urls
        }

    # =================================
    # Passive Scan Status
    # =================================
    def get_passive_scan_status(self):

        result = self._request(
            "pscan",
            "view",
            "recordsToScan"
        )

        return {
            "records_remaining": int(
                result.get("recordsToScan", 0)
            )
        }

    # =================================
    # Get All Alerts By Target URL
    # =================================
    def get_alerts(self, target_url):

        target_url = self._validate_target(
            target_url
        )

        all_alerts = []
        start = 0
        reported_total = None

        while True:

            result = self._request(
                "core",
                "view",
                "alerts",
                {
                    "baseurl": target_url,
                    "start": start,
                    "count": self.alert_page_size
                }
            )

            alerts = result.get("alerts", [])

            if not isinstance(alerts, list):
                raise RuntimeError(
                    "Invalid alerts response from ZAP"
                )

            if "totalResults" in result:

                try:

                    reported_total = int(
                        result["totalResults"]
                    )

                except (ValueError, TypeError):

                    raise RuntimeError(
                        "Invalid totalResults from ZAP"
                    )

                if reported_total < 0:
                    raise RuntimeError(
                        "Invalid totalResults from ZAP"
                    )

            if not alerts:
                break

            all_alerts.extend(alerts)

            if (
                reported_total is not None
                and len(all_alerts) >= reported_total
            ):
                break

            start += len(alerts)

            if (
                reported_total is None
                and len(alerts) < self.alert_page_size
            ):
                break

        # Additional application-level filtering
        filtered_alerts = [
            alert
            for alert in all_alerts
            if self._is_alert_in_application_scope(
                alert,
                target_url
            )
        ]

        return {
            "total_alerts": len(filtered_alerts),
            "alerts": filtered_alerts
        }

    # =================================
    # Get Alerts By Application
    # =================================
    def get_application_alerts(self, application):

        application = self._validate_application(
            application
        )

        target_url = self.get_application_url(
            application
        )

        result = self.get_alerts(
            target_url
        )

        return {
            "application": application,
            "target": target_url,
            "total_alerts": result["total_alerts"],
            "alerts": result["alerts"]
        }


# =================================
# Service Initialization
# =================================
zap_service = ZAPService()
