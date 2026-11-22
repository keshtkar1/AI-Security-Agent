
import os
import re
import json
import time

from pathlib import Path
from urllib.parse import (
    urlparse,
    urlsplit,
    urlunsplit,
    parse_qsl,
    urlencode,
    urljoin
)

from dotenv import load_dotenv
from getpass import getpass

from playwright.sync_api import (
    sync_playwright,
    TimeoutError as PlaywrightTimeoutError
)


# ============================================================
# Load Environment Variables
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")


def get_required_env(name):

    value = os.getenv(name)

    if not value or not value.strip():
        raise ValueError(
            f"Environment variable {name} is not configured"
        )

    return value.strip()


def get_optional_env(name, default):

    value = os.getenv(name)

    if not value or not value.strip():
        return default

    return value.strip()


def get_bool_env(name):

    value = get_required_env(name).lower()

    if value not in ("true", "false"):
        raise ValueError(
            f"{name} must be true or false"
        )

    return value == "true"


# ============================================================
# Browser Configuration
# ============================================================

CHROME_PATH = get_required_env("CHROME_PATH")

BROWSER_HEADLESS = get_bool_env(
    "BROWSER_HEADLESS"
)

BROWSER_TIMEOUT = int(
    get_required_env("BROWSER_TIMEOUT")
)


# ============================================================
# Target Configuration
# ============================================================

TARGET_BASE_URL = get_required_env(
    "TARGET_BASE_URL"
).rstrip("/")

TARGET_WORKSPACE = get_required_env(
    "TARGET_WORKSPACE"
)

TARGET_LOGIN_APP = get_required_env(
    "TARGET_LOGIN_APP"
)


# ============================================================
# ZAP Proxy Configuration
# ============================================================

ZAP_BASE_URL = get_required_env(
    "ZAP_BASE_URL"
).rstrip("/")


# ============================================================
# Login Configuration
# ============================================================

OTP_MODAL_TIMEOUT = int(
    get_required_env("OTP_MODAL_TIMEOUT")
)

AUTH_RESULT_WAIT_MS = int(
    get_required_env("AUTH_RESULT_WAIT_MS")
)


# ============================================================
# APEX Selectors
# ============================================================

LOGIN_USERNAME_SELECTOR = get_required_env(
    "LOGIN_USERNAME_SELECTOR"
)

LOGIN_PASSWORD_SELECTOR = get_required_env(
    "LOGIN_PASSWORD_SELECTOR"
)

LOGIN_CAPTCHA_SELECTOR = get_required_env(
    "LOGIN_CAPTCHA_SELECTOR"
)

OTP_REQUEST_BUTTON_SELECTOR = get_required_env(
    "OTP_REQUEST_BUTTON_SELECTOR"
)

OTP_FIELD_SELECTOR = get_required_env(
    "OTP_FIELD_SELECTOR"
)

OTP_SUBMIT_BUTTON_SELECTOR = get_required_env(
    "OTP_SUBMIT_BUTTON_SELECTOR"
)


# ============================================================
# Crawl Configuration
# ============================================================

MAX_CRAWL_PAGES = int(
    get_optional_env("MAX_CRAWL_PAGES", "200")
)

CRAWL_WAIT_MS = int(
    get_optional_env("CRAWL_WAIT_MS", "1000")
)

PAGE_TEXT_MAX_LENGTH = int(
    get_required_env("PAGE_TEXT_MAX_LENGTH")
)

MAX_INTERACTIVE_ELEMENTS_PER_PAGE = int(
    get_optional_env(
        "MAX_INTERACTIVE_ELEMENTS_PER_PAGE",
        "500"
    )
)

MAX_JS_CANDIDATES_PER_PAGE = int(
    get_optional_env(
        "MAX_JS_CANDIDATES_PER_PAGE",
        "300"
    )
)

MAX_NETWORK_RECORDS = int(
    get_optional_env(
        "MAX_NETWORK_RECORDS",
        "5000"
    )
)

MAX_REJECTED_URLS = int(
    get_optional_env(
        "MAX_REJECTED_URLS",
        "2000"
    )
)


# ============================================================
# Applications Configuration
# ============================================================

APPLICATIONS_FILE = BASE_DIR / "applications.json"


# ============================================================
# Sensitive URL Parameters
# ============================================================

SENSITIVE_PARAMS = {
    "session",
    "sessionid",
    "sid",
    "token",
    "access_token",
    "auth",
    "authorization",
    "p_session",
    "apex_session",
    "refresh_token",
    "csrf",
    "csrf_token",
    "p_checksum",
    "checksum",
    "ck",
    "s"
}


# ============================================================
# APEX Session Parameters
# ============================================================

APEX_SESSION_PARAMS = {
    "session",
    "p_session",
    "apex_session",
    "sessionid"
}


# ============================================================
# Authenticated Session State
# ============================================================

# This variable stores the authenticated APEX session
# only in memory. It is never written to reports or logs.

AUTHENTICATED_SESSION_PARAMS = []


def extract_apex_session_params(url):
    """
    Extracts APEX session parameters from a URL.

    Session values must never be printed or saved
    in crawl reports.
    """

    if not isinstance(url, str) or not url:
        return []

    try:

        parsed = urlsplit(url)

        return [
            (key, value)
            for key, value in parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
            if (
                key.lower() in APEX_SESSION_PARAMS
                and value
            )
        ]

    except Exception:

        return []


def get_authenticated_session_params(
    page,
    preferred_url=None
):
    """
    Finds the authenticated APEX session from:
    1. Preferred URL
    2. Main browser page URL
    3. Existing browser frames

    The browser context is not recreated.
    """

    candidates = []

    if preferred_url:
        candidates.append(preferred_url)

    try:
        candidates.append(page.url)
    except Exception:
        pass

    try:

        for frame in page.frames:

            if frame.url:
                candidates.append(frame.url)

    except Exception:
        pass

    for candidate in candidates:

        session_params = extract_apex_session_params(
            candidate
        )

        if session_params:
            return session_params

    return []


def apply_authenticated_session(
    target_url,
    session_params
):
    """
    Adds the authenticated APEX session to a configured URL.

    If the configured URL already contains a session parameter,
    its value is replaced with the authenticated session value.

    All other query parameters are preserved.
    """

    if not session_params:
        return target_url

    parsed = urlsplit(target_url)

    session_names = {
        key.lower()
        for key, _ in session_params
    }

    query_params = [
        (key, value)
        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        )
        if key.lower() not in session_names
    ]

    query_params.extend(session_params)

    return urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        urlencode(query_params),
        parsed.fragment
    ))


def update_authenticated_session(
    page,
    preferred_url=None
):
    """
    Refreshes the in-memory session from the current browser
    URL or one of its frames.

    Existing authenticated session is retained if no new
    session parameter can be found.
    """

    global AUTHENTICATED_SESSION_PARAMS

    detected_params = get_authenticated_session_params(
        page,
        preferred_url
    )

    if detected_params:

        AUTHENTICATED_SESSION_PARAMS = detected_params

        return True

    return bool(AUTHENTICATED_SESSION_PARAMS)


# ============================================================
# Non-page APEX Endpoints
# ============================================================

BLOCKED_PATHS = {
    "/wwv_flow.accept",
    "/apex_authentication.logout",
    "/apex_util.get_blob"
}


STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".otf",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp3",
    ".mp4",
    ".webm",
    ".avi",
    ".mov",
    ".xlsx",
    ".xls",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx"
}


# ============================================================
# Custom Exceptions
# ============================================================

class AuthenticationLostError(Exception):
    pass


class ApplicationNotMatchedError(Exception):
    pass


# ============================================================
# General Helpers
# ============================================================

def safe_text(value, max_length=300):

    if not isinstance(value, str):
        return ""

    value = re.sub(
        r"\s+",
        " ",
        value
    ).strip()

    return value[:max_length]


def sanitize_message(value, max_length=500):

    if not isinstance(value, str):
        return ""

    value = re.sub(
        r"https?://[^\s\"'<>]+",
        lambda match: mask_url(match.group(0)),
        value
    )

    return safe_text(
        value,
        max_length
    )


# ============================================================
# URL Helpers
# ============================================================

def normalize_url(url):

    parsed = urlsplit(url)

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.query,
        ""
    ))


def url_identity_key(url):
    """
    URL comparison key.

    Sensitive parameters are ignored for comparison.
    The original URL is preserved for navigation.
    """

    parsed = urlsplit(url)

    query = []

    for key, value in parse_qsl(
        parsed.query,
        keep_blank_values=True
    ):

        if key.lower() in SENSITIVE_PARAMS:
            continue

        query.append((key, value))

    query.sort()

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        urlencode(query),
        ""
    ))


def mask_url(url):

    if not isinstance(url, str):
        return ""

    try:

        parsed = urlsplit(url)

        query = []

        for key, value in parse_qsl(
            parsed.query,
            keep_blank_values=True
        ):

            if key.lower() in SENSITIVE_PARAMS:
                value = "[MASKED]"

            query.append((key, value))

        return urlunsplit((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode(query),
            ""
        ))

    except Exception:

        return "[INVALID_URL]"


def is_url_in_application_scope(
    candidate_url,
    base_url
):

    try:

        candidate = urlparse(candidate_url)
        base = urlparse(base_url)

        candidate_port = candidate.port
        base_port = base.port

    except ValueError:

        return False

    if (
        candidate.scheme.lower() != base.scheme.lower()
        or candidate.hostname != base.hostname
        or candidate_port != base_port
        or candidate.username is not None
        or candidate.password is not None
    ):
        return False

    if "\\" in candidate.path:
        return False

    base_path = base.path.rstrip("/")
    candidate_path = candidate.path.rstrip("/")

    if (
        candidate_path != base_path
        and not candidate_path.startswith(
            base_path + "/"
        )
    ):
        return False

    return True


def is_blocked_page_url(url):

    try:

        parsed = urlsplit(url)

        path = parsed.path.lower()

        normalized_path = path.rstrip("/")

        if normalized_path in BLOCKED_PATHS:
            return True

        path_segments = [
            segment.lower()
            for segment in path.split("/")
            if segment
        ]

        if "separator" in path_segments:
            return True

        if path.lower().endswith("/f"):
            return True

        suffix = Path(path).suffix.lower()

        if suffix in STATIC_EXTENSIONS:
            return True

        if "/wwv_flow." in path:
            return True

        if "/apex_authentication." in path:
            return True

        if "/apex_util." in path:
            return True

        return False

    except Exception:

        return True


def resolve_candidate_url(
    value,
    current_url
):

    if not isinstance(value, str):
        return None

    value = value.strip()

    if not value:
        return None

    if value.startswith((
        "javascript:",
        "mailto:",
        "tel:",
        "data:",
        "blob:",
        "#"
    )):
        return None

    if value.lower().startswith("f?p="):
        return None

    absolute_url = urljoin(
        current_url,
        value
    )

    try:

        parsed = urlsplit(absolute_url)

        if parsed.scheme.lower() not in (
            "http",
            "https"
        ):
            return None

        if not parsed.hostname:
            return None

        if parsed.path.lower().endswith("/f"):
            return None

        return normalize_url(absolute_url)

    except Exception:

        return None


def should_crawl_candidate(
    candidate_url,
    base_url
):

    if not is_url_in_application_scope(
        candidate_url,
        base_url
    ):
        return False, "outside_application_scope"

    if is_blocked_page_url(candidate_url):
        return False, "blocked_operation_or_resource"

    return True, None


def sanitize_attribute_value(
    name,
    value,
    current_url
):

    if not isinstance(value, str):
        return ""

    name = name.lower()

    if name in (
        "href",
        "action",
        "formaction",
        "data-url",
        "data-href",
        "data-link",
        "data-target"
    ):

        absolute_url = resolve_candidate_url(
            value,
            current_url
        )

        if absolute_url:
            return mask_url(absolute_url)

        return safe_text(value, 500)

    if name == "onclick":

        value = re.sub(
            r"https?://[^\s\"'<>]+",
            lambda match: mask_url(match.group(0)),
            value
        )

        return safe_text(
            value,
            500
        )

    return safe_text(
        value,
        500
    )


# ============================================================
# Resolve Configured Page URL
# ============================================================

def resolve_page_url(
    application,
    page_config
):
    """
    Resolves a configured relative Friendly URL.

    Absolute URLs, external URLs, legacy f?p URLs,
    and operational endpoints are rejected.
    """

    base_url = (
        application["base_url"].rstrip("/") + "/"
    )

    relative_url = page_config.get("url")

    if (
        not isinstance(relative_url, str)
        or not relative_url.strip()
    ):
        raise ValueError(
            "Page URL must be a non-empty relative URL"
        )

    relative_url = relative_url.strip()

    parsed = urlsplit(relative_url)

    if (
        parsed.scheme
        or parsed.netloc
        or relative_url.startswith("//")
        or relative_url.startswith("/")
        or "\\" in relative_url
        or relative_url.lower().startswith("f?p=")
    ):
        raise ValueError(
            f"Page URL must be a relative Friendly URL: "
            f"{page_config.get('id')}"
        )

    resolved_url = urljoin(
        base_url,
        relative_url
    )

    if not is_url_in_application_scope(
        resolved_url,
        base_url
    ):
        raise ValueError(
            f"Resolved page URL is outside application scope: "
            f"{page_config.get('id')}"
        )

    if is_blocked_page_url(resolved_url):
        raise ValueError(
            f"Configured URL is an operation or resource: "
            f"{page_config.get('id')}"
        )

    return normalize_url(resolved_url)


# ============================================================
# Load Applications
# ============================================================

def load_applications():

    if not APPLICATIONS_FILE.is_file():
        raise FileNotFoundError(
            "applications.json was not found"
        )

    with APPLICATIONS_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        config = json.load(file)

    applications = config.get("applications")

    if (
        not isinstance(applications, list)
        or not applications
    ):
        raise ValueError(
            "No applications configured"
        )

    application_map = {}

    target = urlparse(TARGET_BASE_URL)

    for application in applications:

        if not isinstance(application, dict):
            raise ValueError(
                "Invalid application configuration"
            )

        app_id = application.get("id")

        if (
            not isinstance(app_id, str)
            or not app_id.strip()
        ):
            raise ValueError(
                "Invalid application ID"
            )

        if app_id in application_map:
            raise ValueError(
                f"Duplicate application ID: {app_id}"
            )

        # ----------------------------------------------------
        # Crawl Mode
        # ----------------------------------------------------

        crawl_mode = application.get(
            "crawl_mode",
            "automatic"
        )

        if (
            not isinstance(crawl_mode, str)
            or crawl_mode.lower() not in (
                "automatic",
                "manual"
            )
        ):
            raise ValueError(
                f"Invalid crawl_mode for {app_id}"
            )

        application["crawl_mode"] = crawl_mode.lower()

        # ----------------------------------------------------
        # Base URL
        # ----------------------------------------------------

        base_url = application.get("base_url")

        if (
            not isinstance(base_url, str)
            or not base_url.strip()
        ):
            raise ValueError(
                f"Invalid base URL for {app_id}"
            )

        base_url = base_url.strip()

        parsed = urlparse(base_url)

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                f"Invalid base URL for {app_id}"
            )

        if (
            parsed.scheme != target.scheme
            or parsed.hostname != target.hostname
            or parsed.port != target.port
        ):
            raise ValueError(
                f"Application {app_id} is outside TARGET_BASE_URL"
            )

        application["base_url"] = (
            base_url.rstrip("/") + "/"
        )

        # ----------------------------------------------------
        # Authentication
        # ----------------------------------------------------

        authentication = application.get(
            "authentication",
            {}
        )

        if not isinstance(authentication, dict):
            raise ValueError(
                f"Invalid authentication configuration for {app_id}"
            )

        # ----------------------------------------------------
        # Configured Pages
        # ----------------------------------------------------

        pages = application.get("pages")

        if (
            not isinstance(pages, list)
            or not pages
        ):
            raise ValueError(
                f"No pages configured for {app_id}"
            )

        page_ids = set()

        for page_config in pages:

            if not isinstance(page_config, dict):
                raise ValueError(
                    f"Invalid page configuration in {app_id}"
                )

            page_id = page_config.get("id")

            if (
                not isinstance(page_id, str)
                or not page_id.strip()
            ):
                raise ValueError(
                    f"Invalid page ID in {app_id}"
                )

            if page_id in page_ids:
                raise ValueError(
                    f"Duplicate page ID in {app_id}: {page_id}"
                )

            page_ids.add(page_id)

            enabled = page_config.get(
                "enabled",
                True
            )

            if not isinstance(enabled, bool):
                raise ValueError(
                    f"Invalid enabled value for page {page_id}"
                )

            page_config["enabled"] = enabled

            method = page_config.get(
                "method",
                "GET"
            )

            if (
                not isinstance(method, str)
                or method.upper() != "GET"
            ):
                raise ValueError(
                    "Only GET pages are supported"
                )

            page_config["method"] = "GET"

            if enabled:

                resolve_page_url(
                    application,
                    page_config
                )

        application_map[app_id] = application

    return application_map


APPLICATIONS = load_applications()


def get_applications_to_crawl():

    return list(
        APPLICATIONS.values()
    )


# ============================================================
# Login URL
# ============================================================

LOGIN_URL = (
    f"{TARGET_BASE_URL}/ords/r/"
    f"{TARGET_WORKSPACE}/{TARGET_LOGIN_APP}/login"
)


# ============================================================
# Configuration Validation
# ============================================================

def validate_configuration():

    if not os.path.isfile(CHROME_PATH):
        raise FileNotFoundError(
            "Chrome executable was not found"
        )

    if (
        OTP_MODAL_TIMEOUT <= 0
        or BROWSER_TIMEOUT <= 0
    ):
        raise ValueError(
            "Timeout values must be greater than zero"
        )

    if (
        AUTH_RESULT_WAIT_MS < 0
        or PAGE_TEXT_MAX_LENGTH <= 0
    ):
        raise ValueError(
            "Invalid browser configuration"
        )

    if (
        MAX_CRAWL_PAGES <= 0
        or CRAWL_WAIT_MS < 0
        or MAX_INTERACTIVE_ELEMENTS_PER_PAGE <= 0
        or MAX_JS_CANDIDATES_PER_PAGE <= 0
        or MAX_NETWORK_RECORDS <= 0
        or MAX_REJECTED_URLS <= 0
    ):
        raise ValueError(
            "Invalid crawl configuration"
        )

    target = urlparse(TARGET_BASE_URL)
    proxy = urlparse(ZAP_BASE_URL)

    if (
        target.scheme not in ("http", "https")
        or not target.hostname
    ):
        raise ValueError(
            "Invalid TARGET_BASE_URL"
        )

    if (
        proxy.scheme not in ("http", "https")
        or not proxy.hostname
    ):
        raise ValueError(
            "Invalid ZAP_BASE_URL"
        )


# ============================================================
# OTP Frame Detection
# ============================================================

def find_otp_frame(page):

    print("\nWaiting for OTP modal...")

    start_time = time.time()

    while (
        time.time() - start_time
        < OTP_MODAL_TIMEOUT
    ):

        for frame in page.frames:

            try:

                field = frame.locator(
                    OTP_FIELD_SELECTOR
                )

                if (
                    field.count() > 0
                    and field.is_visible()
                ):

                    print(
                        "OTP modal detected."
                    )

                    return frame

            except Exception:
                continue

        time.sleep(0.5)

    raise TimeoutError(
        "OTP field was not found in modal."
    )


# ============================================================
# Authentication Check
# ============================================================

def is_login_url(candidate_url):

    candidate = urlparse(candidate_url)
    login = urlparse(LOGIN_URL)

    return (
        candidate.scheme == login.scheme
        and candidate.hostname == login.hostname
        and candidate.port == login.port
        and candidate.path.rstrip("/")
        == login.path.rstrip("/")
    )


def verify_authentication(page):

    current_url = page.url

    parsed = urlparse(current_url)
    login = urlparse(LOGIN_URL)

    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
    ):
        raise RuntimeError(
            "Browser is not on a valid application URL"
        )

    if (
        parsed.scheme != login.scheme
        or parsed.hostname != login.hostname
        or parsed.port != login.port
    ):
        raise RuntimeError(
            "Browser was redirected outside the login host"
        )

    if is_login_url(current_url):
        raise RuntimeError(
            "Authentication could not be verified. "
            "Browser is still on the login page."
        )

    print(
        "\nBrowser is no longer on the login URL."
    )

    print(
        "Authentication will be checked again during crawling."
    )

    return True


# ============================================================
# URL Candidate Extraction From JavaScript
# ============================================================

def extract_url_candidates_from_text(text):

    if not isinstance(text, str) or not text:
        return set()

    candidates = set()

    patterns = [
        r"""https?://[^\s"'<>\\]+""",

        r"""(?<![A-Za-z0-9])/(?:ords/|[A-Za-z0-9_.~-]+/)[^\s"'<>\\]*""",

        r"""(?<![A-Za-z0-9])(?:[A-Za-z0-9_.~-]+/)+[A-Za-z0-9_.~-]+(?:\?[^\s"'<>\\]*)?"""
    ]

    for pattern in patterns:

        for match in re.findall(
            pattern,
            text,
            flags=re.IGNORECASE
        ):

            candidate = match.strip()

            candidate = candidate.rstrip(
                ".,;:)]}"
            )

            if (
                candidate
                and not candidate.lower().startswith("f?p=")
            ):
                candidates.add(candidate)

    return candidates


# ============================================================
# Inspect APEX Page Elements
# ============================================================

def inspect_page_elements(
    document,
    current_url,
    base_url
):

    result = {
        "links": set(),
        "elements": [],
        "forms": [],
        "javascript_candidates": set(),
        "rejected_candidates": [],
        "page_text": "",
        "page_text_length": 0,
        "inspection_error": None
    }

    try:

        dom_data = document.evaluate("""
            () => {

                const selector = [
                    'a[href]',
                    'area[href]',
                    'form',
                    'button',
                    'input[type="button"]',
                    'input[type="submit"]',
                    'input[type="reset"]',
                    '[onclick]',
                    '[data-url]',
                    '[data-href]',
                    '[data-target]',
                    '[data-link]',
                    '[formaction]',
                    '[role="button"]',
                    '[role="link"]'
                ].join(',');

                const elements = Array.from(
                    document.querySelectorAll(selector)
                );

                const output = elements.map(el => {

                    const attrs = {};

                    for (const attr of el.attributes) {

                        const name = attr.name.toLowerCase();

                        if (
                            name === 'href' ||
                            name === 'action' ||
                            name === 'formaction' ||
                            name === 'onclick' ||
                            name.startsWith('data-')
                        ) {
                            attrs[name] = attr.value;
                        }
                    }

                    return {

                        tag: el.tagName.toLowerCase(),

                        type: el.getAttribute('type') || '',

                        id: el.id || '',

                        name: el.getAttribute('name') || '',

                        role: el.getAttribute('role') || '',

                        text: (
                            el.innerText ||
                            el.getAttribute('aria-label') ||
                            el.getAttribute('title') ||
                            ''
                        ).trim().slice(0, 200),

                        attributes: attrs,

                        disabled: !!el.disabled
                    };
                });

                const forms = Array.from(
                    document.forms
                ).map(form => ({

                    action: form.action || '',

                    method: (
                        form.method || 'GET'
                    ).toUpperCase(),

                    id: form.id || '',

                    name: form.name || ''
                }));

                const scripts = Array.from(
                    document.scripts
                )
                .filter(script => !script.src)
                .map(script => script.textContent || '');

                const bodyText = (
                    document.body?.innerText || ''
                );

                return {

                    elements: output,

                    forms: forms,

                    scripts: scripts,

                    pageText: bodyText,

                    pageTextLength: bodyText.length
                };
            }
        """)

    except Exception as exc:

        result["inspection_error"] = type(exc).__name__

        return result

    elements = dom_data.get(
        "elements",
        []
    )

    forms = dom_data.get(
        "forms",
        []
    )

    scripts = dom_data.get(
        "scripts",
        []
    )

    # --------------------------------------------------------
    # Sanitize elements
    # --------------------------------------------------------

    sanitized_elements = []

    for element in elements[
        :MAX_INTERACTIVE_ELEMENTS_PER_PAGE
    ]:

        sanitized = dict(element)

        attributes = {}

        for name, value in element.get(
            "attributes",
            {}
        ).items():

            attributes[name] = sanitize_attribute_value(
                name,
                value,
                current_url
            )

        sanitized["attributes"] = attributes

        sanitized["text"] = safe_text(
            sanitized.get("text", ""),
            200
        )

        sanitized_elements.append(
            sanitized
        )

    result["elements"] = sanitized_elements

    # --------------------------------------------------------
    # Forms
    # --------------------------------------------------------

    for form in forms:

        sanitized_form = dict(form)

        action = form.get("action", "")

        if action:

            absolute_action = resolve_candidate_url(
                action,
                current_url
            )

            if absolute_action:
                sanitized_form["action"] = mask_url(
                    absolute_action
                )
            else:
                sanitized_form["action"] = ""

        result["forms"].append(
            sanitized_form
        )

    # --------------------------------------------------------
    # Page text
    # --------------------------------------------------------

    page_text = dom_data.get(
        "pageText",
        ""
    )

    result["page_text_length"] = dom_data.get(
        "pageTextLength",
        0
    )

    result["page_text"] = safe_text(
        page_text,
        PAGE_TEXT_MAX_LENGTH
    )

    # --------------------------------------------------------
    # Candidate processing
    # --------------------------------------------------------

    def process_candidate(value, source):

        absolute_url = resolve_candidate_url(
            value,
            current_url
        )

        if not absolute_url:
            return

        allowed, reason = should_crawl_candidate(
            absolute_url,
            base_url
        )

        if not allowed:

            if (
                len(result["rejected_candidates"])
                < MAX_REJECTED_URLS
            ):

                result["rejected_candidates"].append({
                    "source": source,
                    "url": mask_url(absolute_url),
                    "reason": reason
                })

            return

        # Observed only. Never added to a crawl queue.

        result["links"].add(
            absolute_url
        )

    # --------------------------------------------------------
    # HTML attributes
    # --------------------------------------------------------

    for element in elements:

        attributes = element.get(
            "attributes",
            {}
        )

        for attribute_name, attribute_value in attributes.items():

            attribute_name = attribute_name.lower()

            if attribute_name in (
                "href",
                "data-url",
                "data-href",
                "data-link",
                "data-target",
                "formaction",
                "action"
            ):

                process_candidate(
                    attribute_value,
                    attribute_name
                )

            if attribute_name == "onclick":

                candidates = extract_url_candidates_from_text(
                    attribute_value
                )

                for candidate in candidates:

                    result["javascript_candidates"].add(
                        candidate
                    )

                    process_candidate(
                        candidate,
                        "onclick"
                    )

    # --------------------------------------------------------
    # Form actions
    # --------------------------------------------------------

    for form in forms:

        if form.get("method", "GET").upper() != "GET":
            continue

        action = form.get("action")

        if action:

            process_candidate(
                action,
                "form_action"
            )

    # --------------------------------------------------------
    # Inline JavaScript
    # --------------------------------------------------------

    js_candidates = set()

    for script_text in scripts:

        remaining = (
            MAX_JS_CANDIDATES_PER_PAGE
            - len(js_candidates)
        )

        if remaining <= 0:
            break

        found = extract_url_candidates_from_text(
            script_text
        )

        for candidate in found:

            js_candidates.add(candidate)

            if (
                len(js_candidates)
                >= MAX_JS_CANDIDATES_PER_PAGE
            ):
                break

    # --------------------------------------------------------
    # Process JavaScript candidates
    # --------------------------------------------------------

    for candidate in js_candidates:

        result["javascript_candidates"].add(
            candidate
        )

        process_candidate(
            candidate,
            "inline_javascript"
        )

    return result


# ============================================================
# Inspect Main Page And Frames
# ============================================================

def inspect_page_and_frames(
    page,
    current_url,
    base_url,
    preferred_frame_url=None
):

    combined = {
        "links": set(),
        "elements": [],
        "forms": [],
        "javascript_candidates": set(),
        "rejected_candidates": [],
        "page_text": "",
        "page_text_length": 0,
        "frames_inspected": 0,
        "frame_errors": [],
        "inspection_errors": []
    }

    documents = []

    preferred_frame = None

    if preferred_frame_url:

        preferred_key = url_identity_key(
            preferred_frame_url
        )

        for frame in page.frames:

            try:

                if (
                    frame != page.main_frame
                    and frame.url
                    and url_identity_key(frame.url)
                    == preferred_key
                ):

                    preferred_frame = frame
                    break

            except Exception:
                continue

    # --------------------------------------------------------
    # Main document
    # --------------------------------------------------------

    if is_url_in_application_scope(
        current_url,
        base_url
    ):

        documents.append((
            page,
            current_url,
            "main"
        ))

    # --------------------------------------------------------
    # Application frames
    # --------------------------------------------------------

    for frame in page.frames:

        if frame == page.main_frame:
            continue

        frame_url = frame.url

        if not frame_url:
            continue

        if not is_url_in_application_scope(
            frame_url,
            base_url
        ):
            continue

        documents.append((
            frame,
            frame_url,
            "frame"
        ))

    # --------------------------------------------------------
    # Ensure preferred frame is included
    # --------------------------------------------------------

    if preferred_frame is not None:

        preferred_exists = any(
            document == preferred_frame
            for document, _, _ in documents
        )

        if not preferred_exists:

            documents.append((
                preferred_frame,
                preferred_frame.url,
                "frame"
            ))

    # --------------------------------------------------------
    # Inspect documents
    # --------------------------------------------------------

    for document, document_url, document_type in documents:

        try:

            inspection = inspect_page_elements(
                document,
                document_url,
                base_url
            )

            combined["links"].update(
                inspection.get("links", set())
            )

            combined["javascript_candidates"].update(
                inspection.get(
                    "javascript_candidates",
                    set()
                )
            )

            combined["rejected_candidates"].extend(
                inspection.get(
                    "rejected_candidates",
                    []
                )
            )

            combined["elements"].extend(
                inspection.get(
                    "elements",
                    []
                )
            )

            combined["forms"].extend(
                inspection.get(
                    "forms",
                    []
                )
            )

            if document_type == "frame":

                combined["frames_inspected"] += 1

            if (
                document_type == "main"
                and not preferred_frame_url
            ):

                combined["page_text"] = inspection.get(
                    "page_text",
                    ""
                )

                combined["page_text_length"] = inspection.get(
                    "page_text_length",
                    0
                )

            elif (
                document_type == "frame"
                and document == preferred_frame
            ):

                combined["page_text"] = inspection.get(
                    "page_text",
                    ""
                )

                combined["page_text_length"] = inspection.get(
                    "page_text_length",
                    0
                )

        except Exception as exc:

            combined["frame_errors"].append({

                "type": document_type,

                "url": mask_url(document_url),

                "error": type(exc).__name__

            })

    combined["elements"] = combined["elements"][
        :MAX_INTERACTIVE_ELEMENTS_PER_PAGE
    ]

    combined["javascript_candidates"] = set(
        list(combined["javascript_candidates"])[
            :MAX_JS_CANDIDATES_PER_PAGE
        ]
    )

    return combined


# ============================================================
# Unavailable Page Detection
# ============================================================

def is_unavailable_page(
    title,
    page_text,
    response_status=None
):

    if (
        response_status is not None
        and response_status >= 400
    ):
        return True, "http_error"

    combined = (
        safe_text(title, 500)
        + " "
        + safe_text(page_text, 3000)
    ).lower()

    unavailable_phrases = [

        "sorry, this page isn't available",

        "this page isn't available",

        "page not found",

        "404 not found",

        "404 - not found",

        "the requested url was not found",

        "requested page could not be found",

        "requested resource was not found",

        "صفحه مورد نظر یافت نشد",

        "صفحه مورد نظر در دسترس نیست",

        "صفحه پیدا نشد"

    ]

    for phrase in unavailable_phrases:

        if phrase in combined:
            return True, "unavailable_page_content"

    return False, None


# ============================================================
# Network Monitoring
# ============================================================

def attach_network_monitor(
    page,
    base_url
):

    network_records = {}

    def get_request_key(request):

        return (
            request.method,
            url_identity_key(request.url),
            request.resource_type
        )

    def on_request(request):

        try:

            request_url = request.url

            if not is_url_in_application_scope(
                request_url,
                base_url
            ):
                return

            resource_type = request.resource_type

            if resource_type not in (
                "document",
                "xhr",
                "fetch"
            ):
                return

            key = get_request_key(request)

            if key in network_records:
                return

            if len(network_records) >= MAX_NETWORK_RECORDS:
                return

            network_records[key] = {

                "url": mask_url(request_url),

                "method": request.method,

                "resource_type": resource_type,

                "status": None,

                "failed": False

            }

        except Exception:
            pass

    def on_response(response):

        try:

            request = response.request

            request_url = request.url

            if not is_url_in_application_scope(
                request_url,
                base_url
            ):
                return

            resource_type = request.resource_type

            if resource_type not in (
                "document",
                "xhr",
                "fetch"
            ):
                return

            key = get_request_key(request)

            if key not in network_records:

                if len(network_records) >= MAX_NETWORK_RECORDS:
                    return

                network_records[key] = {

                    "url": mask_url(request_url),

                    "method": request.method,

                    "resource_type": resource_type,

                    "status": None,

                    "failed": False

                }

            network_records[key]["status"] = response.status

        except Exception:
            pass

    def on_request_failed(request):

        try:

            request_url = request.url

            if not is_url_in_application_scope(
                request_url,
                base_url
            ):
                return

            resource_type = request.resource_type

            if resource_type not in (
                "document",
                "xhr",
                "fetch"
            ):
                return

            key = get_request_key(request)

            if key in network_records:

                network_records[key]["failed"] = True

        except Exception:
            pass

    page.on("request", on_request)

    page.on("response", on_response)

    page.on("requestfailed", on_request_failed)

    return {

        "records": network_records,

        "request_handler": on_request,

        "response_handler": on_response,

        "failed_handler": on_request_failed

    }


def detach_network_monitor(
    page,
    monitor
):

    try:

        page.remove_listener(
            "request",
            monitor["request_handler"]
        )

        page.remove_listener(
            "response",
            monitor["response_handler"]
        )

        page.remove_listener(
            "requestfailed",
            monitor["failed_handler"]
        )

    except Exception:
        pass


# ============================================================
# Get Document Title
# ============================================================

def get_document_title(
    page,
    preferred_frame_url=None
):

    if preferred_frame_url:

        preferred_key = url_identity_key(
            preferred_frame_url
        )

        for frame in page.frames:

            try:

                if (
                    frame != page.main_frame
                    and frame.url
                    and url_identity_key(frame.url)
                    == preferred_key
                ):

                    return frame.title()

            except Exception:
                continue

    try:

        return page.title()

    except Exception:

        return ""


# ============================================================
# JSON-DRIVEN Crawl Application
# ============================================================

def crawl_application(
    page,
    application,
    start_url=None,
    start_frame=None
):
    """
    JSON-Driven Crawling.

    Only pages defined in applications.json are navigated.

    Links and JavaScript URLs are inspected and reported,
    but they are NEVER added to a crawl queue.

    The authenticated APEX session is preserved when
    navigating to configured pages.

    start_url and start_frame are only used to reuse
    the already-loaded authenticated document when
    the first enabled configured page matches it.
    """

    global AUTHENTICATED_SESSION_PARAMS

    app_id = application["id"]

    app_name = application.get(
        "name",
        app_id
    )

    base_url = application["base_url"]

    all_configured_pages = application["pages"]

    enabled_pages = [
        item
        for item in all_configured_pages
        if item.get("enabled", True)
    ]

    disabled_pages = [
        item
        for item in all_configured_pages
        if not item.get("enabled", True)
    ]

    # --------------------------------------------------------
    # Resolve configured pages
    # --------------------------------------------------------

    configured_items = []

    for page_config in enabled_pages:

        page_url = resolve_page_url(
            application,
            page_config
        )

        configured_items.append({

            "id": page_config["id"],

            "name": page_config.get(
                "name",
                page_config["id"]
            ),

            "description": page_config.get(
                "description",
                ""
            ),

            "url": page_url,

            "key": url_identity_key(page_url)

        })

    # --------------------------------------------------------
    # Deduplicate configured pages
    # --------------------------------------------------------

    unique_items = []

    duplicate_configured_pages = []

    configured_keys = set()

    for item in configured_items:

        if item["key"] in configured_keys:

            duplicate_configured_pages.append({

                "id": item["id"],

                "url": mask_url(item["url"]),

                "reason": "duplicate_configured_url"

            })

            continue

        configured_keys.add(
            item["key"]
        )

        unique_items.append(item)

    configured_items = unique_items

    configured_count = len(configured_items)

    # --------------------------------------------------------
    # Apply MAX_CRAWL_PAGES
    # --------------------------------------------------------

    pages_to_process = configured_items[
        :MAX_CRAWL_PAGES
    ]

    limit_skipped_pages = configured_items[
        MAX_CRAWL_PAGES:
    ]

    # --------------------------------------------------------
    # Result containers
    # --------------------------------------------------------

    attempted_keys = set()

    visited_keys = set()

    unavailable_keys = set()

    attempted_urls = {}

    visited_urls = {}

    unavailable_urls = {}

    page_details = []

    errors = []

    rejected_urls = []

    observed_internal_links = {}

    network_monitor = None

    # --------------------------------------------------------
    # Report helper
    # --------------------------------------------------------

    def add_error(
        page_id,
        page_url,
        exception
    ):

        errors.append({

            "page_id": page_id,

            "url": mask_url(page_url),

            "error": type(exception).__name__,

            "message": sanitize_message(
                str(exception),
                500
            )

        })

    # --------------------------------------------------------
    # Start information
    # --------------------------------------------------------

    print("\n")
    print("=" * 65)
    print("APPLICATION:", app_name)
    print("APPLICATION ID:", app_id)
    print("CRAWL MODE:", application["crawl_mode"])
    print("BASE URL:", mask_url(base_url))
    print("=" * 65)

    print("\n========== JSON-DRIVEN CRAWL ==========")

    print(
        "Configured pages:",
        len(all_configured_pages)
    )

    print(
        "Enabled pages:",
        len(enabled_pages)
    )

    print(
        "Disabled pages:",
        len(disabled_pages)
    )

    print(
        "Unique enabled pages:",
        configured_count
    )

    print(
        "Pages selected for this run:",
        len(pages_to_process)
    )

    print(
        "Pages skipped by MAX_CRAWL_PAGES:",
        len(limit_skipped_pages)
    )

    print(
        "\nCrawling order is taken directly from applications.json."
    )

    print(
        "Discovered links will NOT be crawled."
    )

    # --------------------------------------------------------
    # Detect whether first configured page is already loaded
    # --------------------------------------------------------

    first_page_reuse = False

    preferred_frame_url = None

    if pages_to_process and start_url:

        first_item = pages_to_process[0]

        start_key = url_identity_key(
            start_url
        )

        if start_key == first_item["key"]:

            if (
                start_frame is not None
                and not page.is_closed()
            ):

                try:

                    if (
                        start_frame.url
                        and url_identity_key(start_frame.url)
                        == first_item["key"]
                    ):

                        first_page_reuse = True

                        preferred_frame_url = start_frame.url

                except Exception:
                    pass

            if not first_page_reuse:

                try:

                    if (
                        not page.is_closed()
                        and url_identity_key(page.url)
                        == first_item["key"]
                    ):

                        first_page_reuse = True

                except Exception:
                    pass

            if not first_page_reuse:

                for frame in page.frames:

                    try:

                        if (
                            frame != page.main_frame
                            and frame.url
                            and url_identity_key(frame.url)
                            == first_item["key"]
                        ):

                            first_page_reuse = True

                            preferred_frame_url = frame.url

                            break

                    except Exception:
                        continue

    # --------------------------------------------------------
    # Capture authenticated APEX session
    # --------------------------------------------------------

    # First, try the selected manual URL or current browser URL.
    # If a session has already been captured, do not discard it.

    if not AUTHENTICATED_SESSION_PARAMS:

        AUTHENTICATED_SESSION_PARAMS = (
            get_authenticated_session_params(
                page,
                preferred_url=(
                    start_url
                    if start_url
                    else None
                )
            )
        )

    # If still empty, try the selected frame URL.

    if (
        not AUTHENTICATED_SESSION_PARAMS
        and preferred_frame_url
    ):

        AUTHENTICATED_SESSION_PARAMS = (
            extract_apex_session_params(
                preferred_frame_url
            )
        )

    print(
        "\nAuthenticated APEX session detected:",
        bool(AUTHENTICATED_SESSION_PARAMS)
    )

    # --------------------------------------------------------
    # Network Monitoring
    # --------------------------------------------------------

    network_monitor = attach_network_monitor(
        page,
        base_url
    )

    termination_reason = "configured_pages_completed"

    # --------------------------------------------------------
    # Process configured pages in JSON order
    # --------------------------------------------------------

    try:

        for index, item in enumerate(
            pages_to_process,
            start=1
        ):

            page_id = item["id"]

            page_name = item["name"]

            current_url = item["url"]

            current_key = item["key"]

            print(
                f"\n[{index}/{len(pages_to_process)}] "
                f"Page ID: {page_id}"
            )

            print(
                "Page name:",
                safe_text(page_name, 200)
            )

            print(
                "Opening:",
                mask_url(current_url)
            )

            if current_key in attempted_keys:

                print(
                    "Duplicate configured page skipped."
                )

                continue

            attempted_keys.add(current_key)

            attempted_urls[current_key] = current_url

            try:

                # ------------------------------------------------
                # Reuse already-loaded first page if it matches
                # ------------------------------------------------

                reuse_current_page = (
                    index == 1
                    and first_page_reuse
                )

                if reuse_current_page:

                    response = None

                    actual_url = (
                        preferred_frame_url
                        if preferred_frame_url
                        else page.url
                    )

                    print(
                        "Using the already-loaded authenticated document."
                    )

                    print(
                        "No navigation request will be sent for this page."
                    )

                else:

                    preferred_frame_url = None

                    # --------------------------------------------
                    # Apply authenticated APEX session
                    # --------------------------------------------

                    navigation_url = apply_authenticated_session(
                        current_url,
                        AUTHENTICATED_SESSION_PARAMS
                    )

                    print(
                        "Navigating with authenticated session:",
                        bool(AUTHENTICATED_SESSION_PARAMS)
                    )

                    response = page.goto(
                        navigation_url,
                        wait_until="domcontentloaded",
                        timeout=BROWSER_TIMEOUT
                    )

                    actual_url = page.url

                # ------------------------------------------------
                # HTTP status
                # ------------------------------------------------

                if response is not None:

                    response_status = response.status

                    print(
                        "HTTP Status:",
                        response_status
                    )

                else:

                    response_status = None

                    print(
                        "HTTP Status: Already loaded"
                    )

                # ------------------------------------------------
                # Wait for page stabilization
                # ------------------------------------------------

                try:

                    page.wait_for_load_state(
                        "networkidle",
                        timeout=5000
                    )

                except PlaywrightTimeoutError:
                    pass

                if CRAWL_WAIT_MS:
                    page.wait_for_timeout(
                        CRAWL_WAIT_MS
                    )

                # ------------------------------------------------
                # Detect authentication loss
                # ------------------------------------------------

                if is_login_url(actual_url):

                    raise AuthenticationLostError(
                        "Browser was redirected to the login page. "
                        "The authenticated session may have expired."
                    )

                if not is_url_in_application_scope(
                    actual_url,
                    base_url
                ):

                    raise ApplicationNotMatchedError(
                        "Page redirected outside application scope."
                    )

                actual_url = normalize_url(actual_url)

                actual_key = url_identity_key(
                    actual_url
                )

                # ------------------------------------------------
                # Refresh session if a new session appears
                # ------------------------------------------------

                # The session in the browser URL may change after
                # an APEX redirect. Refresh it for subsequent pages.

                update_authenticated_session(
                    page,
                    preferred_url=actual_url
                )

                # ------------------------------------------------
                # Page title
                # ------------------------------------------------

                title = get_document_title(
                    page,
                    preferred_frame_url
                )

                print(
                    "Page title:",
                    safe_text(title, 200)
                )

                # ------------------------------------------------
                # Inspect page and frames
                # ------------------------------------------------

                inspection = inspect_page_and_frames(
                    page,
                    actual_url,
                    base_url,
                    preferred_frame_url=preferred_frame_url
                )

                links = inspection["links"]

                elements = inspection["elements"]

                forms = inspection["forms"]

                js_candidates = inspection[
                    "javascript_candidates"
                ]

                rejected_candidates = inspection[
                    "rejected_candidates"
                ]

                page_text = inspection.get(
                    "page_text",
                    ""
                )

                # ------------------------------------------------
                # Record observed links for reporting only
                # ------------------------------------------------

                observed_internal_links[page_id] = sorted(
                    mask_url(link)
                    for link in links
                )

                # ------------------------------------------------
                # Detect unavailable page
                # ------------------------------------------------

                unavailable, unavailable_reason = is_unavailable_page(
                    title,
                    page_text,
                    response_status
                )

                if unavailable:

                    unavailable_keys.add(
                        current_key
                    )

                    unavailable_urls[current_key] = current_url

                    print(
                        "Unavailable page detected:",
                        unavailable_reason
                    )

                    page_details.append({

                        "page_id": page_id,

                        "page_name": page_name,

                        "description": item["description"],

                        "configured_url": mask_url(current_url),

                        "actual_url": mask_url(actual_url),

                        "title": safe_text(title, 300),

                        "page_status": "unavailable",

                        "unavailable_reason": unavailable_reason,

                        "internal_links_found": len(links),

                        "interactive_elements_found": len(elements),

                        "forms_found": len(forms),

                        "javascript_candidates_found": len(
                            js_candidates
                        ),

                        "frames_inspected": inspection.get(
                            "frames_inspected",
                            0
                        ),

                        "page_text_length": inspection.get(
                            "page_text_length",
                            0
                        )

                    })

                    continue

                # ------------------------------------------------
                # Valid page
                # ------------------------------------------------

                visited_keys.add(
                    current_key
                )

                visited_urls[current_key] = current_url

                if actual_key != current_key:

                    visited_keys.add(
                        actual_key
                    )

                    visited_urls[actual_key] = actual_url

                # ------------------------------------------------
                # Console diagnostics
                # ------------------------------------------------

                print(
                    "Internal URLs found:",
                    len(links)
                )

                print(
                    "Interactive elements:",
                    len(elements)
                )

                print(
                    "Forms found:",
                    len(forms)
                )

                print(
                    "JavaScript URL candidates:",
                    len(js_candidates)
                )

                print(
                    "Frames inspected:",
                    inspection.get(
                        "frames_inspected",
                        0
                    )
                )

                print(
                    "Rejected URL candidates:",
                    len(rejected_candidates)
                )

                # ------------------------------------------------
                # Sanitize JavaScript candidates
                # ------------------------------------------------

                safe_js_candidates = []

                for candidate in sorted(js_candidates):

                    absolute_candidate = resolve_candidate_url(
                        candidate,
                        actual_url
                    )

                    if absolute_candidate:

                        safe_js_candidates.append(
                            mask_url(absolute_candidate)
                        )

                    else:

                        safe_js_candidates.append(
                            safe_text(candidate, 300)
                        )

                # ------------------------------------------------
                # Save Page Details
                # ------------------------------------------------

                page_details.append({

                    "page_id": page_id,

                    "page_name": page_name,

                    "description": item["description"],

                    "configured_url": mask_url(current_url),

                    "actual_url": mask_url(actual_url),

                    "title": safe_text(
                        title,
                        300
                    ),

                    "page_status": "visited",

                    "internal_links_found": len(links),

                    "interactive_elements_found": len(elements),

                    "forms_found": len(forms),

                    "javascript_candidates_found": len(
                        js_candidates
                    ),

                    "frames_inspected": inspection.get(
                        "frames_inspected",
                        0
                    ),

                    "page_text_length": inspection.get(
                        "page_text_length",
                        0
                    ),

                    "page_text": page_text,

                    "elements": elements,

                    "forms": forms,

                    "javascript_candidates": safe_js_candidates,

                    "rejected_candidates": rejected_candidates,

                    "frame_errors": inspection.get(
                        "frame_errors",
                        []
                    )

                })

                # ------------------------------------------------
                # Rejected candidates
                # ------------------------------------------------

                for rejected_item in rejected_candidates:

                    if len(rejected_urls) >= MAX_REJECTED_URLS:
                        break

                    rejected_urls.append(
                        rejected_item
                    )

                # ------------------------------------------------
                # No link discovery queue
                # ------------------------------------------------

                print(
                    "Page inspection completed."
                )

                print(
                    "Next page will be taken from applications.json."
                )

            except AuthenticationLostError:
                raise

            except Exception as exc:

                add_error(
                    page_id,
                    current_url,
                    exc
                )

                page_details.append({

                    "page_id": page_id,

                    "page_name": page_name,

                    "description": item["description"],

                    "configured_url": mask_url(current_url),

                    "actual_url": None,

                    "title": "",

                    "page_status": "error",

                    "error": type(exc).__name__,

                    "message": sanitize_message(
                        str(exc),
                        500
                    )

                })

                print(
                    "Page crawl failed:",
                    type(exc).__name__
                )

    except AuthenticationLostError as exc:

        termination_reason = "authentication_lost"

        errors.append({

            "error": type(exc).__name__,

            "message": sanitize_message(
                str(exc),
                500
            )

        })

        print(
            "\nAUTHENTICATION LOST:",
            sanitize_message(str(exc))
        )

    finally:

        if network_monitor is not None:

            detach_network_monitor(
                page,
                network_monitor
            )

    # --------------------------------------------------------
    # Determine termination reason
    # --------------------------------------------------------

    if termination_reason != "authentication_lost":

        if limit_skipped_pages:

            termination_reason = "max_pages_reached"

        else:

            termination_reason = "configured_pages_completed"

    # ========================================================
    # Network Summary
    # ========================================================

    network_records = (
        list(network_monitor["records"].values())
        if network_monitor
        else []
    )

    document_requests = [
        item
        for item in network_records
        if item["resource_type"] == "document"
    ]

    xhr_requests = [
        item
        for item in network_records
        if item["resource_type"] == "xhr"
    ]

    fetch_requests = [
        item
        for item in network_records
        if item["resource_type"] == "fetch"
    ]

    failed_requests = [
        item
        for item in network_records
        if item["failed"]
    ]

    # ========================================================
    # Configured Page Status Lists
    # ========================================================

    disabled_page_results = [

        {

            "page_id": item["id"],

            "page_name": item.get(
                "name",
                item["id"]
            ),

            "url": mask_url(
                resolve_page_url(
                    application,
                    item
                )
            ),

            "reason": "disabled_in_configuration"

        }

        for item in disabled_pages

    ]

    limit_skipped_results = [

        {

            "page_id": item["id"],

            "page_name": item["name"],

            "url": mask_url(item["url"]),

            "reason": "max_crawl_pages_reached"

        }

        for item in limit_skipped_pages

    ]

    # ========================================================
    # Crawl Result
    # ========================================================

    result = {

        "application": app_id,

        "application_name": app_name,

        "crawl_mode": application["crawl_mode"],

        "crawl_strategy": "configured_pages_only",

        "crawl_limits": {

            "max_pages": MAX_CRAWL_PAGES

        },

        "termination_reason": termination_reason,

        "total_configured_pages": len(all_configured_pages),

        "total_enabled_pages": len(enabled_pages),

        "total_disabled_pages": len(disabled_pages),

        "total_unique_configured_pages": configured_count,

        "total_attempted_urls": len(attempted_urls),

        "total_visited_pages": len(visited_urls),

        "total_unavailable_pages": len(unavailable_urls),

        "total_error_pages": sum(
            1
            for item in page_details
            if item.get("page_status") == "error"
        ),

        "total_skipped_configured_pages": (
            len(disabled_page_results)
            + len(limit_skipped_results)
            + len(duplicate_configured_pages)
        ),

        "total_duplicate_configured_pages": len(
            duplicate_configured_pages
        ),

        "total_observed_internal_links": sum(
            len(items)
            for items in observed_internal_links.values()
        ),

        "total_discovered_urls": 0,

        "total_pending_urls": len(
            limit_skipped_results
        ),

        "total_rejected_urls": len(rejected_urls),

        "attempted_urls": sorted(
            mask_url(url)
            for url in attempted_urls.values()
        ),

        "visited_urls": sorted(
            mask_url(url)
            for url in visited_urls.values()
        ),

        "unavailable_urls": sorted(
            mask_url(url)
            for url in unavailable_urls.values()
        ),

        "configured_pages": [

            {

                "page_id": item["id"],

                "page_name": item["name"],

                "url": mask_url(item["url"])

            }

            for item in configured_items

        ],

        "disabled_pages": disabled_page_results,

        "limit_skipped_pages": limit_skipped_results,

        "duplicate_configured_pages": duplicate_configured_pages,

        "observed_internal_links": observed_internal_links,

        "discovered_urls": [],

        "pending_urls": limit_skipped_results,

        "rejected_urls": rejected_urls,

        "page_details": page_details,

        "network_summary": {

            "total_requests": len(network_records),

            "document_requests": len(document_requests),

            "xhr_requests": len(xhr_requests),

            "fetch_requests": len(fetch_requests),

            "failed_requests": len(failed_requests)

        },

        "network_requests": network_records,

        "errors": errors

    }

    # ========================================================
    # Console Summary
    # ========================================================

    print(
        "\n========== APPLICATION CRAWL SUMMARY =========="
    )

    print(
        "Configured pages:",
        result["total_configured_pages"]
    )

    print(
        "Enabled pages:",
        result["total_enabled_pages"]
    )

    print(
        "Disabled pages:",
        result["total_disabled_pages"]
    )

    print(
        "Unique configured pages:",
        result["total_unique_configured_pages"]
    )

    print(
        "Attempted URLs:",
        result["total_attempted_urls"]
    )

    print(
        "Visited pages:",
        result["total_visited_pages"]
    )

    print(
        "Unavailable pages:",
        result["total_unavailable_pages"]
    )

    print(
        "Error pages:",
        result["total_error_pages"]
    )

    print(
        "Skipped configured pages:",
        result["total_skipped_configured_pages"]
    )

    print(
        "Duplicate configured pages:",
        result["total_duplicate_configured_pages"]
    )

    print(
        "Observed internal links:",
        result["total_observed_internal_links"]
    )

    print(
        "Discovered URLs crawled:",
        result["total_discovered_urls"]
    )

    print(
        "Pending configured pages:",
        result["total_pending_urls"]
    )

    print(
        "Rejected URL candidates:",
        result["total_rejected_urls"]
    )

    print(
        "Document requests:",
        len(document_requests)
    )

    print(
        "XHR requests:",
        len(xhr_requests)
    )

    print(
        "Fetch requests:",
        len(fetch_requests)
    )

    print(
        "Failed requests:",
        len(failed_requests)
    )

    print(
        "Termination reason:",
        termination_reason
    )

    print(
        "Errors:",
        len(errors)
    )

    return result


# ============================================================
# Match Manual Application
# ============================================================

def find_manual_application(
    current_url,
    pending_applications
):

    matches = []

    for application in pending_applications:

        base_url = application["base_url"]

        if is_url_in_application_scope(
            current_url,
            base_url
        ):

            parsed_base = urlparse(base_url)

            path_length = len(
                parsed_base.path.rstrip("/")
            )

            matches.append((
                path_length,
                application
            ))

    if not matches:
        return None

    matches.sort(
        key=lambda item: item[0],
        reverse=True
    )

    return matches[0][1]


# ============================================================
# Manual Application Selection
# ============================================================

def select_manual_application(
    context,
    pending_applications
):

    print("\n")
    print("=" * 60)
    print("MANUAL APPLICATION SELECTION")
    print("=" * 60)

    print(
        "\nThe authenticated Chrome browser is ready."
    )

    print(
        "Navigate to one of the following applications:"
    )

    for index, application in enumerate(
        pending_applications,
        start=1
    ):

        print(
            f"{index}. "
            f"{application.get('name', application['id'])}"
        )

        print(
            "   Base URL:",
            mask_url(application["base_url"])
        )

    print(
        "\nAfter opening the desired application, "
        "press Enter in this terminal."
    )

    while True:

        input(
            "\nPress Enter after navigating to the application..."
        )

        browser_pages = [

            browser_page

            for browser_page in context.pages

            if not browser_page.is_closed()

        ]

        if not browser_pages:

            raise RuntimeError(
                "No open browser tabs were found."
            )

        print("\n========== BROWSER DIAGNOSTICS ==========")

        for index, browser_page in enumerate(
            browser_pages,
            start=1
        ):

            print(f"\nPage {index}")

            print(
                "URL:",
                mask_url(browser_page.url)
            )

            print(
                "Title:",
                safe_text(
                    browser_page.title(),
                    200
                )
            )

            for frame_index, frame in enumerate(
                browser_page.frames,
                start=1
            ):

                print(
                    f"Frame {frame_index}:",
                    mask_url(frame.url)
                )

        print("\n=========================================")

        # ----------------------------------------------------
        # Find matching application
        # ----------------------------------------------------

        matches = []

        for browser_page in reversed(browser_pages):

            # Main page

            current_url = browser_page.url

            if (
                current_url
                and not is_login_url(current_url)
            ):

                matched_application = find_manual_application(
                    current_url,
                    pending_applications
                )

                if matched_application is not None:

                    parsed_base = urlparse(
                        matched_application["base_url"]
                    )

                    path_length = len(
                        parsed_base.path.rstrip("/")
                    )

                    matches.append((

                        path_length,

                        matched_application,

                        browser_page,

                        current_url,

                        "page",

                        None

                    ))

            # Frames

            for frame in browser_page.frames:

                frame_url = frame.url

                if (
                    not frame_url
                    or is_login_url(frame_url)
                ):
                    continue

                matched_application = find_manual_application(
                    frame_url,
                    pending_applications
                )

                if matched_application is not None:

                    parsed_base = urlparse(
                        matched_application["base_url"]
                    )

                    path_length = len(
                        parsed_base.path.rstrip("/")
                    )

                    matches.append((

                        path_length,

                        matched_application,

                        browser_page,

                        frame_url,

                        "frame",

                        frame

                    ))

        # ----------------------------------------------------
        # No matching application
        # ----------------------------------------------------

        if not matches:

            print(
                "\nNo pending Manual application matches "
                "any open browser tab or frame."
            )

            print(
                "Please navigate to one of the listed applications."
            )

            continue

        # ----------------------------------------------------
        # Select longest matching path
        # ----------------------------------------------------

        matches.sort(
            key=lambda item: item[0],
            reverse=True
        )

        (
            _,
            matched_application,
            matched_page,
            matched_url,
            matched_source,
            matched_frame
        ) = matches[0]

        print(
            "\nMatched application:",
            matched_application.get(
                "name",
                matched_application["id"]
            )
        )

        print(
            "Application ID:",
            matched_application["id"]
        )

        print(
            "Matched URL:",
            mask_url(matched_url)
        )

        print(
            "Match source:",
            matched_source
        )

        print(
            "\nThe matching browser tab will be used for crawling."
        )

        print(
            "All configured pages will be processed from applications.json."
        )

        return (
            matched_application,
            matched_page,
            matched_url,
            matched_frame
        )


# ============================================================
# Save Crawl Results
# ============================================================

def save_crawl_results(result):

    reports_directory = (
        BASE_DIR / "data" / "crawl_results"
    )

    reports_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    app_id = result["application"]

    output_file = (
        reports_directory
        / f"{app_id}_crawl.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            ensure_ascii=False,
            indent=4
        )

    print(
        "\nCrawl results saved:"
    )

    print(output_file)


# ============================================================
# Save Overall Crawl Summary
# ============================================================

def save_overall_summary(results):

    reports_directory = (
        BASE_DIR / "data" / "crawl_results"
    )

    reports_directory.mkdir(
        parents=True,
        exist_ok=True
    )

    summary = {

        "total_applications": len(results),

        "total_configured_pages": sum(
            item.get("total_configured_pages", 0)
            for item in results
        ),

        "total_attempted_urls": sum(
            item.get("total_attempted_urls", 0)
            for item in results
        ),

        "total_visited_pages": sum(
            item.get("total_visited_pages", 0)
            for item in results
        ),

        "total_unavailable_pages": sum(
            item.get("total_unavailable_pages", 0)
            for item in results
        ),

        "total_error_pages": sum(
            item.get("total_error_pages", 0)
            for item in results
        ),

        "total_skipped_configured_pages": sum(
            item.get("total_skipped_configured_pages", 0)
            for item in results
        ),

        "total_observed_internal_links": sum(
            item.get("total_observed_internal_links", 0)
            for item in results
        ),

        "total_errors": sum(
            len(item.get("errors", []))
            for item in results
        ),

        "applications": [

            {

                "application": item["application"],

                "application_name": item["application_name"],

                "crawl_mode": item.get("crawl_mode"),

                "crawl_strategy": item.get(
                    "crawl_strategy"
                ),

                "total_configured_pages": item.get(
                    "total_configured_pages",
                    0
                ),

                "total_enabled_pages": item.get(
                    "total_enabled_pages",
                    0
                ),

                "total_attempted_urls": item.get(
                    "total_attempted_urls",
                    0
                ),

                "total_visited_pages": item.get(
                    "total_visited_pages",
                    0
                ),

                "total_unavailable_pages": item.get(
                    "total_unavailable_pages",
                    0
                ),

                "total_error_pages": item.get(
                    "total_error_pages",
                    0
                ),

                "total_skipped_configured_pages": item.get(
                    "total_skipped_configured_pages",
                    0
                ),

                "termination_reason": item.get(
                    "termination_reason"
                ),

                "total_errors": len(
                    item.get("errors", [])
                )

            }

            for item in results

        ]

    }

    output_file = (
        reports_directory
        / "crawl_summary.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            ensure_ascii=False,
            indent=4
        )

    print(
        "\nOverall summary saved:"
    )

    print(output_file)

    return summary


# ============================================================
# Save Application Failure
# ============================================================

def create_failed_result(
    application,
    exception
):

    return {

        "application": application["id"],

        "application_name": application.get(
            "name",
            application["id"]
        ),

        "crawl_mode": application.get("crawl_mode"),

        "crawl_strategy": "configured_pages_only",

        "termination_reason": "application_failed",

        "total_configured_pages": len(
            application.get("pages", [])
        ),

        "total_enabled_pages": sum(
            1
            for item in application.get("pages", [])
            if item.get("enabled", True)
        ),

        "total_disabled_pages": sum(
            1
            for item in application.get("pages", [])
            if not item.get("enabled", True)
        ),

        "total_unique_configured_pages": 0,

        "total_attempted_urls": 0,

        "total_visited_pages": 0,

        "total_unavailable_pages": 0,

        "total_error_pages": 0,

        "total_skipped_configured_pages": 0,

        "total_duplicate_configured_pages": 0,

        "total_observed_internal_links": 0,

        "total_discovered_urls": 0,

        "total_pending_urls": 0,

        "attempted_urls": [],

        "visited_urls": [],

        "unavailable_urls": [],

        "configured_pages": [],

        "disabled_pages": [],

        "limit_skipped_pages": [],

        "duplicate_configured_pages": [],

        "observed_internal_links": {},

        "discovered_urls": [],

        "pending_urls": [],

        "rejected_urls": [],

        "page_details": [],

        "network_summary": {

            "total_requests": 0,

            "document_requests": 0,

            "xhr_requests": 0,

            "fetch_requests": 0,

            "failed_requests": 0

        },

        "network_requests": [],

        "errors": [

            {

                "error": type(exception).__name__,

                "message": sanitize_message(
                    str(exception),
                    500
                )

            }

        ]

    }


# ============================================================
# Authentication Flow
# ============================================================

def authenticate_user(page):

    global AUTHENTICATED_SESSION_PARAMS

    print(
        "\nOpening SAKHA login page..."
    )

    page.goto(
        LOGIN_URL,
        wait_until="domcontentloaded",
        timeout=BROWSER_TIMEOUT
    )

    # --------------------------------------------------------
    # Username and Password
    # --------------------------------------------------------

    username = input(
        "\nUsername: "
    )

    password = getpass(
        "Password: "
    )

    if not username.strip():
        raise ValueError(
            "Username cannot be empty."
        )

    if not password.strip():
        raise ValueError(
            "Password cannot be empty."
        )

    page.locator(
        LOGIN_USERNAME_SELECTOR
    ).fill(username)

    page.locator(
        LOGIN_PASSWORD_SELECTOR
    ).fill(password)

    print(
        "\nUsername and password entered."
    )

    # --------------------------------------------------------
    # Manual CAPTCHA
    # --------------------------------------------------------

    print(
        "\nPlease enter CAPTCHA manually in Chrome."
    )

    input(
        "After entering CAPTCHA, press Enter here..."
    )

    captcha = page.locator(
        LOGIN_CAPTCHA_SELECTOR
    ).input_value()

    if not captcha.strip():
        raise ValueError(
            "CAPTCHA field is empty."
        )

    # --------------------------------------------------------
    # Request OTP
    # --------------------------------------------------------

    print(
        "\nRequesting OTP..."
    )

    page.locator(
        OTP_REQUEST_BUTTON_SELECTOR
    ).click()

    # --------------------------------------------------------
    # Find OTP Frame
    # --------------------------------------------------------

    otp_frame = find_otp_frame(
        page
    )

    # --------------------------------------------------------
    # Enter OTP
    # --------------------------------------------------------

    otp_code = getpass(
        "OTP Code: "
    )

    if not otp_code.strip():
        raise ValueError(
            "OTP code cannot be empty."
        )

    otp_frame.locator(
        OTP_FIELD_SELECTOR
    ).fill(otp_code)

    # --------------------------------------------------------
    # Submit OTP
    # --------------------------------------------------------

    otp_frame.locator(
        OTP_SUBMIT_BUTTON_SELECTOR
    ).click()

    print(
        "\nOTP submitted. Waiting for authentication..."
    )

    page.wait_for_timeout(
        AUTH_RESULT_WAIT_MS
    )

    # --------------------------------------------------------
    # Verify Authentication
    # --------------------------------------------------------

    print(
        "\n========== LOGIN RESULT =========="
    )

    print(
        "Current URL:",
        mask_url(page.url)
    )

    print(
        "Page title:",
        safe_text(
            page.title(),
            200
        )
    )

    verify_authentication(page)

    # --------------------------------------------------------
    # Capture authenticated APEX session
    # --------------------------------------------------------

    AUTHENTICATED_SESSION_PARAMS = (
        get_authenticated_session_params(page)
    )

    print(
        "Authenticated APEX session detected:",
        bool(AUTHENTICATED_SESSION_PARAMS)
    )

    return True


# ============================================================
# Process Automatic Applications
# ============================================================

def process_automatic_applications(
    page,
    applications,
    all_results
):

    automatic_applications = [

        application

        for application in applications

        if application["crawl_mode"] == "automatic"

    ]

    print("\n")
    print("=" * 60)
    print("AUTOMATIC APPLICATIONS")
    print("=" * 60)

    if not automatic_applications:

        print(
            "No Automatic applications configured."
        )

        return True

    for application in automatic_applications:

        print(
            "\nStarting Automatic application:",
            application["id"]
        )

        try:

            crawl_result = crawl_application(
                page,
                application
            )

            save_crawl_results(
                crawl_result
            )

            all_results.append(
                crawl_result
            )

            if crawl_result.get(
                "termination_reason"
            ) == "authentication_lost":

                print(
                    "\nStopping all crawls because "
                    "authentication was lost."
                )

                return False

        except AuthenticationLostError as exc:

            failed_result = create_failed_result(
                application,
                exc
            )

            save_crawl_results(
                failed_result
            )

            all_results.append(
                failed_result
            )

            return False

        except Exception as exc:

            print(
                "\nApplication crawl failed:",
                application["id"],
                type(exc).__name__
            )

            failed_result = create_failed_result(
                application,
                exc
            )

            save_crawl_results(
                failed_result
            )

            all_results.append(
                failed_result
            )

    return True


# ============================================================
# Process Manual Applications
# ============================================================

def process_manual_applications(
    context,
    applications,
    all_results
):

    pending_applications = [

        application

        for application in applications

        if application["crawl_mode"] == "manual"

    ]

    print("\n")
    print("=" * 60)
    print("MANUAL APPLICATIONS")
    print("=" * 60)

    if not pending_applications:

        print(
            "No Manual applications configured."
        )

        return True

    while pending_applications:

        # ----------------------------------------------------
        # Select application and tab
        # ----------------------------------------------------

        (
            application,
            selected_page,
            selected_url,
            selected_frame
        ) = select_manual_application(
            context,
            pending_applications
        )

        print(
            "\nStarting Manual application:",
            application["id"]
        )

        try:

            # ------------------------------------------------
            # Validate selected URL
            # ------------------------------------------------

            if not selected_url:

                raise RuntimeError(
                    "Selected browser page has no application URL."
                )

            if is_login_url(selected_url):

                raise AuthenticationLostError(
                    "Selected browser page is the login page."
                )

            if not is_url_in_application_scope(
                selected_url,
                application["base_url"]
            ):

                raise ApplicationNotMatchedError(
                    "Selected browser URL is outside application scope."
                )

            print(
                "\nManual application selected successfully."
            )

            print(
                "Selected browser URL:",
                mask_url(selected_url)
            )

            if selected_frame is not None:

                print(
                    "Selected document: iframe"
                )

            else:

                print(
                    "Selected document: main page"
                )

            # ------------------------------------------------
            # Capture session from selected URL/frame
            # ------------------------------------------------

            # If a session is present in the selected application
            # URL, use it for this crawl.

            selected_session_params = (
                extract_apex_session_params(
                    selected_url
                )
            )

            if selected_session_params:

                global AUTHENTICATED_SESSION_PARAMS

                AUTHENTICATED_SESSION_PARAMS = (
                    selected_session_params
                )

            else:

                update_authenticated_session(
                    selected_page,
                    preferred_url=selected_url
                )

            print(
                "Authenticated APEX session available:",
                bool(AUTHENTICATED_SESSION_PARAMS)
            )

            print(
                "\nThe crawler will now process the configured pages "
                "in applications.json order."
            )

            # ------------------------------------------------
            # JSON-Driven Crawl
            # ------------------------------------------------

            crawl_result = crawl_application(
                selected_page,
                application,
                start_url=selected_url,
                start_frame=selected_frame
            )

            save_crawl_results(
                crawl_result
            )

            all_results.append(
                crawl_result
            )

            # ------------------------------------------------
            # Remove processed application
            # ------------------------------------------------

            pending_applications = [

                item

                for item in pending_applications

                if item["id"] != application["id"]

            ]

            # ------------------------------------------------
            # Check authentication
            # ------------------------------------------------

            if crawl_result.get(
                "termination_reason"
            ) == "authentication_lost":

                print(
                    "\nStopping all crawls because "
                    "authentication was lost."
                )

                return False

        except AuthenticationLostError as exc:

            failed_result = create_failed_result(
                application,
                exc
            )

            save_crawl_results(
                failed_result
            )

            all_results.append(
                failed_result
            )

            return False

        except Exception as exc:

            print(
                "\nApplication crawl failed:",
                application["id"],
                type(exc).__name__
            )

            failed_result = create_failed_result(
                application,
                exc
            )

            save_crawl_results(
                failed_result
            )

            all_results.append(
                failed_result
            )

            pending_applications = [

                item

                for item in pending_applications

                if item["id"] != application["id"]

            ]

    return True


# ============================================================
# Main
# ============================================================

def main(application_ids=None, wait_for_exit=True):

    global AUTHENTICATED_SESSION_PARAMS

    AUTHENTICATED_SESSION_PARAMS = []

    validate_configuration()

    applications = get_applications_to_crawl()

    if application_ids is not None:

        if not isinstance(application_ids, (list, tuple, set)):
            raise ValueError("application_ids must be a list")

        requested_ids = {
            item.strip()
            for item in application_ids
            if isinstance(item, str) and item.strip()
        }

        available_ids = {
            item["id"]
            for item in applications
        }

        unknown_ids = requested_ids - available_ids

        if unknown_ids:
            raise ValueError(
                "Applications are not configured in applications.json: "
                + ", ".join(sorted(unknown_ids))
            )

        applications = [
            item
            for item in applications
            if item["id"] in requested_ids
        ]

        if not applications:
            raise ValueError("No applications selected for crawling")

    print("\n========== APPLICATIONS ==========")

    for index, application in enumerate(
        applications,
        start=1
    ):

        enabled_count = sum(
            1
            for item in application["pages"]
            if item.get("enabled", True)
        )

        print(
            f"{index}. "
            f"{application.get('name', application['id'])} "
            f"({application['id']}) "
            f"[{application['crawl_mode'].upper()}]"
        )

        print(
            "   Configured pages:",
            len(application["pages"])
        )

        print(
            "   Enabled pages:",
            enabled_count
        )

    print(
        "\nTotal applications:",
        len(applications)
    )

    automatic_count = sum(
        1
        for application in applications
        if application["crawl_mode"] == "automatic"
    )

    manual_count = sum(
        1
        for application in applications
        if application["crawl_mode"] == "manual"
    )

    print(
        "Automatic applications:",
        automatic_count
    )

    print(
        "Manual applications:",
        manual_count
    )

    with sync_playwright() as p:

        browser = p.chromium.launch(

            executable_path=CHROME_PATH,

            headless=BROWSER_HEADLESS,

            proxy={
                "server": ZAP_BASE_URL
            }

        )

        # One browser context for the entire session.
        # Cookies and authentication state are preserved.

        context = browser.new_context()

        page = context.new_page()

        page.set_default_timeout(
            BROWSER_TIMEOUT
        )

        try:

            # ------------------------------------------------
            # Step 1: Authentication
            # ------------------------------------------------

            authenticate_user(page)

            all_results = []

            # ------------------------------------------------
            # Step 2: Automatic Applications
            # ------------------------------------------------

            automatic_completed = process_automatic_applications(
                page,
                applications,
                all_results
            )

            # ------------------------------------------------
            # Step 3: Manual Applications
            # ------------------------------------------------

            if automatic_completed:

                process_manual_applications(
                    context,
                    applications,
                    all_results
                )

            # ------------------------------------------------
            # Step 4: Overall Summary
            # ------------------------------------------------

            summary = save_overall_summary(
                all_results
            )

            # ------------------------------------------------
            # Step 5: Final Summary
            # ------------------------------------------------

            print(
                "\n========== FINAL CRAWL SUMMARY =========="
            )

            print(
                "Completed applications:",
                summary["total_applications"]
            )

            print(
                "Total configured pages:",
                summary["total_configured_pages"]
            )

            print(
                "Total attempted URLs:",
                summary["total_attempted_urls"]
            )

            print(
                "Total visited pages:",
                summary["total_visited_pages"]
            )

            print(
                "Total unavailable pages:",
                summary["total_unavailable_pages"]
            )

            print(
                "Total error pages:",
                summary["total_error_pages"]
            )

            print(
                "Total skipped configured pages:",
                summary["total_skipped_configured_pages"]
            )

            print(
                "Total observed internal links:",
                summary["total_observed_internal_links"]
            )

            print(
                "\nCrawling strategy: Configured Pages Only"
            )

            print(
                "Only configured pages were navigated."
            )

            print(
                "Discovered links were not crawled."
            )

            print(
                "\nZAP continues receiving browser traffic "
                "through its configured proxy."
            )

            if wait_for_exit:
                input(
                    "\nPress Enter to close browser..."
                )

            return summary

        finally:

            context.close()

            browser.close()


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    main()
