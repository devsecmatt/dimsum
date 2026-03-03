"""Reflected XSS Scanner Plugin.

Tests for reflected cross-site scripting by injecting payloads into URL
parameters and checking if they appear in the response.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.payloads import XSS_BASIC_PAYLOADS, XSS_CANARY_PREFIX
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "reflected_xss",
    name="Reflected XSS Scanner",
    category="injection",
    owasp_category="A03:2021-Injection",
    asvs_ids=["V5.3.3", "V5.3.4"],
    cwe_ids=[79],
    description="Tests for reflected cross-site scripting (XSS) vulnerabilities.",
)
class ReflectedXSSPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                # No query parameters — try reflected canary in common param names
                params = {p: [""] for p in ("q", "search", "query", "id", "page", "name", "input")}

            for param_name in params:
                # Phase 1: Canary test — check if the parameter value is reflected
                canary = f"{XSS_CANARY_PREFIX}{secrets.token_hex(4)}"
                test_url = self._inject_param(url, param_name, canary)
                resp = await self.http.get(test_url)
                if resp is None or canary not in resp.text:
                    continue  # Not reflected — skip payload testing

                self.log("Parameter '%s' reflects input on %s", param_name, url)

                # Phase 2: Try actual XSS payloads
                for payload in XSS_BASIC_PAYLOADS:
                    test_url = self._inject_param(url, param_name, payload)
                    resp = await self.http.get(test_url)
                    if resp is None:
                        continue

                    # Check if the payload appears unescaped in the response
                    if self._is_payload_reflected(payload, resp.text):
                        confidence = self._determine_confidence(payload, resp.text)
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title=f"Reflected XSS in '{param_name}' parameter",
                            description=(
                                f"The parameter '{param_name}' reflects user input without proper "
                                f"sanitization, allowing cross-site scripting (XSS) attacks."
                            ),
                            severity=Severity.HIGH,
                            confidence=confidence,
                            url=url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=self._extract_evidence(payload, resp.text),
                            cwe_id=79,
                            cvss_score=6.1,
                            remediation=(
                                "Encode all user-supplied input before including it in HTML output. "
                                "Use context-aware output encoding (HTML entity encoding for HTML body, "
                                "JavaScript encoding for script blocks, URL encoding for URLs). "
                                "Implement a Content-Security-Policy header to reduce XSS impact."
                            ),
                            request_dump=resp.dump_request(),
                            response_dump=resp.dump_response(),
                        ))
                        # One confirmed XSS per parameter is enough
                        break

        return findings

    @staticmethod
    def _inject_param(url: str, param_name: str, value: str) -> str:
        """Replace or add a parameter value in a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def _is_payload_reflected(payload: str, body: str) -> bool:
        """Check if an XSS payload appears unescaped in the response body."""
        # Check for exact match (unescaped)
        if payload in body:
            return True

        # Check for key dangerous parts of the payload
        dangerous_parts = [
            "<script>", "</script>",
            "onerror=", "onload=",
            "<svg ", "<img ",
            "javascript:",
        ]
        for part in dangerous_parts:
            if part in payload.lower() and part in body.lower():
                return True

        return False

    @staticmethod
    def _determine_confidence(payload: str, body: str) -> Confidence:
        """Determine confidence level based on how the payload is reflected."""
        if payload in body:
            return Confidence.CONFIRMED
        return Confidence.FIRM

    @staticmethod
    def _extract_evidence(payload: str, body: str, context_chars: int = 100) -> str:
        """Extract the portion of the response body around the reflected payload."""
        lower_body = body.lower()
        lower_payload = payload.lower()
        idx = lower_body.find(lower_payload)
        if idx == -1:
            # Try finding a key part of the payload
            for part in ("<script>", "onerror=", "onload=", "<svg", "<img"):
                if part in lower_payload:
                    idx = lower_body.find(part)
                    if idx != -1:
                        break
        if idx == -1:
            return f"Payload reflected: {payload}"

        start = max(0, idx - context_chars)
        end = min(len(body), idx + len(payload) + context_chars)
        return f"...{body[start:end]}..."
