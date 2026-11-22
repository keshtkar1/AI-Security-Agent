"""
Evidence-based coverage reporting for the actual browser_auth.py crawl result.

This service reports what the crawler observed. It does not equate DOM/network
observation with security testing or vulnerability validation.
"""

from collections import Counter
from typing import Any, Dict, Iterable, List, Mapping, Optional


class SecurityCoverageService:
    VERSION = "1.1"

    @staticmethod
    def _items(value: Any) -> List[dict]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @staticmethod
    def _strings(value: Any) -> List[str]:
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, str)]

    @staticmethod
    def _count(value: Any) -> int:
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0

    @staticmethod
    def _percentage(numerator: int, denominator: int) -> Optional[float]:
        if denominator <= 0:
            return None
        return round((numerator / denominator) * 100, 2)

    @staticmethod
    def _unique_records(records: Iterable[dict], keys: tuple) -> List[dict]:
        unique = {}
        for record in records:
            identity = tuple(record.get(key) for key in keys)
            unique.setdefault(identity, record)
        return list(unique.values())

    @staticmethod
    def _counter_dict(counter: Counter) -> Dict[str, int]:
        return dict(sorted(counter.items()))

    def build_report(self, crawl_result: Mapping[str, Any]) -> Dict[str, Any]:
        """Build a coverage report from one crawl_application() result."""
        result = dict(crawl_result or {})

        # These collection names and counters are emitted by browser_auth.py.
        page_details = self._items(result.get("page_details"))
        configured_pages = self._items(result.get("configured_pages"))
        disabled_pages = self._items(result.get("disabled_pages"))
        limit_skipped_pages = self._items(result.get("limit_skipped_pages"))
        duplicate_pages = self._items(result.get("duplicate_configured_pages"))

        denominator = self._count(result.get("total_unique_configured_pages"))
        if "total_unique_configured_pages" not in result:
            denominator = len(configured_pages)

        attempted_urls = self._strings(result.get("attempted_urls"))
        visited_urls = self._strings(result.get("visited_urls"))
        unavailable_urls = self._strings(result.get("unavailable_urls"))

        # page_details contains one status record for each page actually
        # processed. Its page_status values are visited/unavailable/error.
        page_status_counts = Counter(
            str(item.get("page_status", "unknown")).lower()
            for item in page_details
        )
        visited = page_status_counts.get("visited", 0)
        unavailable = page_status_counts.get("unavailable", 0)
        page_errors = page_status_counts.get("error", 0)

        attempted = self._count(result.get("total_attempted_urls"))
        if "total_attempted_urls" not in result:
            attempted = len(attempted_urls)
        if attempted == 0 and page_details:
            attempted = sum(
                1 for item in page_details
                if item.get("page_status") in {"visited", "unavailable", "error"}
            )

        # Any configured unique page not attempted remains pending, including
        # pages left behind after authentication loss or a crawl limit.
        pending = max(denominator - attempted, 0)

        page_coverage = {
            "denominator": denominator,
            "attempted": attempted,
            "visited": visited,
            "unavailable": unavailable,
            "error": page_errors,
            "pending_or_not_attempted": pending,
            "coverage_percent": self._percentage(visited, denominator),
            "attempt_percent": self._percentage(attempted, denominator),
            "disabled_out_of_scope": len(disabled_pages),
            "skipped_by_crawl_limit": len(limit_skipped_pages),
            "duplicate_configurations": len(duplicate_pages),
            "configured_pages": configured_pages,
            "disabled_pages": disabled_pages,
            "limit_skipped_pages": limit_skipped_pages,
            "duplicate_pages": duplicate_pages,
            "page_details": page_details,
            "crawler_counters": {
                "total_configured_pages": self._count(result.get("total_configured_pages")),
                "total_enabled_pages": self._count(result.get("total_enabled_pages")),
                "total_unique_configured_pages": denominator,
                "total_attempted_urls": attempted,
                "total_visited_pages_reported_by_crawler": self._count(result.get("total_visited_pages")),
                "total_unavailable_pages_reported_by_crawler": self._count(result.get("total_unavailable_pages")),
                "total_error_pages_reported_by_crawler": self._count(result.get("total_error_pages")),
                "total_skipped_configured_pages": self._count(result.get("total_skipped_configured_pages")),
                "total_pending_urls": self._count(result.get("total_pending_urls")),
            },
            "limitations": [
                "Page coverage is based on unique enabled configured pages, not every route in the application.",
                "Observed internal links are not automatically added to the crawl queue.",
                "The crawler's visited URL counter can include a redirected actual URL; page status counts use page_details to avoid treating a redirect as an additional configured page.",
            ],
        }

        # browser_auth.py stores each page's interactive elements using these
        # fields: tag, type, id, name, role, text, attributes, disabled.
        element_records = []
        form_records = []
        javascript_candidates = set()
        observed_links = result.get("observed_internal_links")
        if isinstance(observed_links, dict):
            link_count = sum(
                len(value) for value in observed_links.values()
                if isinstance(value, (list, tuple, set))
            )
        else:
            link_count = self._count(result.get("total_observed_internal_links"))

        frames_inspected = 0
        frame_error_count = 0
        for page in page_details:
            element_records.extend(self._items(page.get("elements")))
            form_records.extend(self._items(page.get("forms")))
            javascript_candidates.update(
                self._strings(page.get("javascript_candidates"))
            )
            frames_inspected += self._count(page.get("frames_inspected"))
            frame_error_count += len(self._items(page.get("frame_errors")))

        # The crawler caps elements per page. Report both raw observations and
        # unique signatures; never label either number as tested controls.
        unique_elements = self._unique_records(
            element_records, ("tag", "type", "id", "name", "role", "text")
        )
        unique_forms = self._unique_records(
            form_records, ("action", "method", "id", "name")
        )

        element_tags = Counter(
            str(item.get("tag") or "unknown").lower()
            for item in element_records
        )
        element_types = Counter(
            str(item.get("type") or "unspecified").lower()
            for item in element_records
        )
        form_methods = Counter(
            str(item.get("method") or "GET").upper()
            for item in form_records
        )

        component_coverage = {
            "evidence_status": "observed_on_visited_pages",
            "visited_pages_used": visited,
            "interactive_element_occurrences_observed": len(element_records),
            "unique_interactive_element_signatures_observed": len(unique_elements),
            "elements_by_tag": self._counter_dict(element_tags),
            "elements_by_type": self._counter_dict(element_types),
            "form_occurrences_observed": len(form_records),
            "unique_form_signatures_observed": len(unique_forms),
            "forms_by_method": self._counter_dict(form_methods),
            "forms": form_records,
            "internal_links_observed": link_count,
            "javascript_url_candidates_observed": len(javascript_candidates),
            "frames_inspected": frames_inspected,
            "frame_inspection_errors": frame_error_count,
            "form_input_fields": {
                "status": "not_collected_by_current_crawler",
                "count": None,
            },
            "limitations": [
                "Interactive elements are collected using a fixed DOM selector and a per-page cap; this is not an exhaustive inventory of every control.",
                "Form metadata is collected, but individual form input fields are not enumerated.",
                "Observed links and JavaScript candidates are recorded but are not crawled automatically.",
                "Component counts describe DOM observations, not security tests performed on those components.",
            ],
        }

        # Actual browser_auth.py emits network_requests as a list of records
        # with url, method, resource_type, status and failed. The list is
        # already deduplicated by the crawler using method + URL identity +
        # resource type. Do not deduplicate again using masked URLs: distinct
        # sessionized URLs may become identical after masking.
        network_records = self._items(result.get("network_requests"))
        network_summary = result.get("network_summary")
        if not isinstance(network_summary, dict):
            network_summary = {}

        if network_records:
            resource_counts = Counter(
                str(item.get("resource_type") or "unknown").lower()
                for item in network_records
            )
            method_counts = Counter(
                str(item.get("method") or "UNKNOWN").upper()
                for item in network_records
            )
            status_counts = Counter()
            failed_count = 0
            for item in network_records:
                status = item.get("status")
                failed = item.get("failed") is True
                if failed:
                    failed_count += 1
                    status_counts["request_failed"] += 1
                elif isinstance(status, int) and not isinstance(status, bool):
                    status_counts[f"{status // 100}xx"] += 1
                else:
                    status_counts["no_response_status"] += 1
            network_total = len(network_records)
            network_evidence = "request_records"
        else:
            # Failed-application results and older crawl summaries may contain
            # only network_summary aggregates, without individual records.
            resource_counts = Counter({
                "document": self._count(network_summary.get("document_requests")),
                "xhr": self._count(network_summary.get("xhr_requests")),
                "fetch": self._count(network_summary.get("fetch_requests")),
            })
            resource_counts += Counter()
            method_counts = Counter()
            status_counts = Counter()
            failed_count = self._count(network_summary.get("failed_requests"))
            network_total = self._count(
                network_summary.get("total_requests")
            )
            network_evidence = (
                "aggregate_summary_only" if network_summary else "not_available"
            )

        network_coverage = {
            "evidence_status": network_evidence,
            "unique_requests_observed": network_total,
            "requests_by_resource_type": self._counter_dict(resource_counts),
            "requests_by_method": self._counter_dict(method_counts),
            "requests_by_status_class": self._counter_dict(status_counts),
            "failed_requests": failed_count,
            "requests": network_records,
            "limitations": [
                "The crawler records only in-scope Document, XHR, and Fetch requests.",
                "Request records are deduplicated by the crawler using method, URL identity, and resource type.",
                "Request observation is not endpoint security-test coverage.",
                "The crawl result does not provide a denominator for all possible application endpoints.",
            ],
        }

        return {
            "coverage_version": self.VERSION,
            "application": result.get("application"),
            "application_name": result.get("application_name"),
            "crawl_mode": result.get("crawl_mode"),
            "crawl_strategy": result.get("crawl_strategy"),
            "termination_reason": result.get("termination_reason"),
            "measurement": {
                "source": "browser_auth.py crawl_application result",
                "generated_from_observed_data": True,
                "security_testing_claim": False,
            },
            "summary": {
                "page_coverage_percent": page_coverage["coverage_percent"],
                "page_attempt_percent": page_coverage["attempt_percent"],
                "enabled_unique_pages": denominator,
                "attempted_pages": attempted,
                "visited_pages": visited,
                "unavailable_pages": unavailable,
                "error_pages": page_errors,
                "pending_or_not_attempted_pages": pending,
                "interactive_elements_observed": len(element_records),
                "unique_interactive_element_signatures_observed": len(unique_elements),
                "forms_observed": len(form_records),
                "unique_form_signatures_observed": len(unique_forms),
                "network_requests_observed": network_total,
                "failed_network_requests": failed_count,
            },
            "page_coverage": page_coverage,
            "component_coverage": component_coverage,
            "network_coverage": network_coverage,
        }

    def build_overall_report(
        self, crawl_results: Iterable[Mapping[str, Any]]
    ) -> Dict[str, Any]:
        """Aggregate application reports using weighted totals, not averages."""
        reports = [
            self.build_report(item)
            for item in crawl_results
            if isinstance(item, Mapping)
        ]

        page_denominator = sum(
            item["page_coverage"]["denominator"] for item in reports
        )
        page_attempted = sum(
            item["page_coverage"]["attempted"] for item in reports
        )
        page_visited = sum(
            item["page_coverage"]["visited"] for item in reports
        )

        return {
            "coverage_version": self.VERSION,
            "application_count": len(reports),
            "summary": {
                "enabled_unique_pages": page_denominator,
                "attempted_pages": page_attempted,
                "visited_pages": page_visited,
                "page_coverage_percent": self._percentage(
                    page_visited, page_denominator
                ),
                "page_attempt_percent": self._percentage(
                    page_attempted, page_denominator
                ),
                "interactive_elements_observed": sum(
                    item["summary"]["interactive_elements_observed"]
                    for item in reports
                ),
                "forms_observed": sum(
                    item["summary"]["forms_observed"]
                    for item in reports
                ),
                "network_requests_observed": sum(
                    item["summary"]["network_requests_observed"]
                    for item in reports
                ),
                "failed_network_requests": sum(
                    item["summary"]["failed_network_requests"]
                    for item in reports
                ),
            },
            "applications": reports,
            "measurement": {
                "source": "browser_auth.py crawl_application results",
                "generated_from_observed_data": True,
                "security_testing_claim": False,
            },
        }