"""SQL Injection Scanner Plugin.

Tests for SQL injection by injecting payloads into URL parameters and
checking for database error messages in the response.
"""

from __future__ import annotations

import re
import secrets
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.payloads import SQLI_ERROR_PATTERNS, SQLI_ERROR_PAYLOADS
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "sqli_error",
    name="SQL Injection (Error-Based)",
    category="injection",
    owasp_category="A03:2021-Injection",
    asvs_ids=["V5.3.4", "V5.3.5"],
    cwe_ids=[89],
    description="Tests for error-based SQL injection by detecting database error messages.",
)
class SQLInjectionPlugin(BaseScanPlugin):

    # Compiled regex patterns for performance
    _error_patterns = [re.compile(p, re.IGNORECASE) for p in SQLI_ERROR_PATTERNS]

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                # Try common parameter names
                params = {p: ["1"] for p in ("id", "page", "cat", "item", "user", "search")}

            for param_name in params:
                # First get a baseline response
                baseline_url = self._inject_param(url, param_name, "1")
                baseline = await self.http.get(baseline_url)
                if baseline is None:
                    continue

                # Check if baseline already has SQL errors (false positive indicator)
                if self._has_sql_error(baseline.text):
                    continue

                for payload in SQLI_ERROR_PAYLOADS:
                    test_url = self._inject_param(url, param_name, payload)
                    resp = await self.http.get(test_url)
                    if resp is None:
                        continue

                    error_match = self._has_sql_error(resp.text)
                    if error_match:
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title=f"SQL Injection in '{param_name}' parameter",
                            description=(
                                f"The parameter '{param_name}' appears vulnerable to SQL injection. "
                                f"Database error messages were detected in the response when "
                                f"injecting SQL metacharacters."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=f"SQL error pattern matched: {error_match}",
                            cwe_id=89,
                            cvss_score=9.8,
                            remediation=(
                                "Use parameterized queries or prepared statements instead of "
                                "string concatenation. Implement input validation and use an ORM. "
                                "Never embed user input directly into SQL queries."
                            ),
                            request_dump=resp.dump_request(),
                            response_dump=resp.dump_response(),
                        ))
                        # One confirmed per parameter
                        break

                    # Time-based detection: check if response time is significantly longer
                    if "WAITFOR" in payload or "SLEEP" in payload:
                        if resp.elapsed_ms > 4500:  # 5 second delay minus margin
                            findings.append(ScanFinding(
                                plugin_id=self.meta.plugin_id,
                                title=f"Time-Based SQL Injection in '{param_name}' parameter",
                                description=(
                                    f"The parameter '{param_name}' may be vulnerable to time-based "
                                    f"SQL injection. The response time was {resp.elapsed_ms:.0f}ms "
                                    f"when a time-delay payload was injected."
                                ),
                                severity=Severity.CRITICAL,
                                confidence=Confidence.TENTATIVE,
                                url=url,
                                method="GET",
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Response time: {resp.elapsed_ms:.0f}ms (expected ~5000ms delay)",
                                cwe_id=89,
                                cvss_score=9.8,
                                remediation=(
                                    "Use parameterized queries or prepared statements. "
                                    "Implement input validation and use an ORM."
                                ),
                                request_dump=resp.dump_request(),
                                response_dump=resp.dump_response(max_body=500),
                            ))
                            break

        return findings

    def _has_sql_error(self, body: str) -> str | None:
        """Check response body for SQL error patterns. Returns the matched pattern or None."""
        body_lower = body.lower()
        for pattern in self._error_patterns:
            match = pattern.search(body_lower)
            if match:
                return match.group()
        return None

    @staticmethod
    def _inject_param(url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
