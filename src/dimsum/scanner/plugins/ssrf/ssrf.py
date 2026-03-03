"""SSRF (Server-Side Request Forgery) Scanner Plugin.

Tests for SSRF by injecting internal/cloud metadata URLs into parameters
that are likely used for URL fetching or redirects.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity

# Parameters commonly used for URL-fetching functionality
SSRF_PARAM_NAMES = (
    "url", "link", "redirect", "redirect_url", "next", "return",
    "return_url", "callback", "dest", "destination", "target",
    "uri", "path", "go", "feed", "host", "site", "html",
    "proxy", "domain", "source", "src", "img", "image",
)

# Indicators that an internal resource was reached
SSRF_INDICATORS = [
    "ami-id",              # AWS EC2 metadata
    "instance-id",         # AWS/GCP metadata
    "availability-zone",   # AWS metadata
    "computeMetadata",     # GCP metadata
    "root:x:0:",           # /etc/passwd
    "localhost",           # Loopback indicators
]


@PluginRegistry.register(
    "ssrf",
    name="Server-Side Request Forgery (SSRF)",
    category="ssrf",
    owasp_category="A10:2021-SSRF",
    asvs_ids=["V12.6.1"],
    cwe_ids=[918],
    description="Tests for SSRF vulnerabilities by injecting internal URLs into parameters.",
)
class SSRFPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        generator = self.get_payload_generator()

        for url in self.get_target_urls():
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            # Identify SSRF-likely parameters
            target_params = [p for p in params if p.lower() in SSRF_PARAM_NAMES]
            if not target_params:
                # Try all params if none match known names
                target_params = list(params.keys())
            if not target_params:
                continue

            for param_name in target_params:
                for ssrf_url in generator.get_ssrf_payloads(param_name, url):
                    test_url = self._inject_param(url, param_name, ssrf_url)
                    resp = await self.http.get(test_url)
                    if resp is None:
                        continue

                    indicator = self._has_ssrf_indicator(resp.text)
                    if indicator:
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title=f"SSRF in '{param_name}' parameter",
                            description=(
                                f"The parameter '{param_name}' may be vulnerable to Server-Side "
                                f"Request Forgery. The server appears to have fetched an internal "
                                f"resource when an internal URL was provided."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.FIRM,
                            url=url,
                            method="GET",
                            parameter=param_name,
                            payload=ssrf_url,
                            evidence=f"SSRF indicator in response: {indicator}",
                            cwe_id=918,
                            cvss_score=7.5,
                            remediation=(
                                "Validate and sanitize all user-supplied URLs. Use an allowlist "
                                "of permitted domains. Block requests to internal IP ranges "
                                "(127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
                                "192.168.0.0/16). Disable HTTP redirects or validate redirect targets."
                            ),
                            request_dump=resp.dump_request(),
                            response_dump=resp.dump_response(),
                        ))
                        break  # One finding per parameter

        return findings

    @staticmethod
    def _has_ssrf_indicator(body: str) -> str | None:
        body_lower = body.lower()
        for indicator in SSRF_INDICATORS:
            if indicator.lower() in body_lower:
                return indicator
        return None

    @staticmethod
    def _inject_param(url: str, param_name: str, value: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_query))
