"""Security Headers Scanner Plugin.

Checks for missing or misconfigured security headers on target URLs.
"""

from __future__ import annotations

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.payloads import DANGEROUS_HEADERS, EXPECTED_SECURITY_HEADERS
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "security_headers",
    name="Security Headers Check",
    category="misconfig",
    owasp_category="A05:2021-Security Misconfiguration",
    asvs_ids=["V14.4.1", "V14.4.2", "V14.4.3"],
    cwe_ids=[693, 1021, 523, 200],
    description="Checks for missing or misconfigured HTTP security headers.",
)
class SecurityHeadersPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            resp = await self.http.get(url)
            if resp is None:
                continue

            # Check for missing security headers
            for header_name, info in EXPECTED_SECURITY_HEADERS.items():
                value = resp.header(header_name)
                if not value:
                    findings.append(ScanFinding(
                        plugin_id=self.meta.plugin_id,
                        title=f"Missing {header_name} Header",
                        description=info["description"],
                        severity=Severity(info["severity"]),
                        confidence=Confidence.CONFIRMED,
                        url=resp.url,
                        method="GET",
                        evidence=f"Response headers do not contain {header_name}",
                        cwe_id=info["cwe_id"],
                        remediation=info["remediation"],
                        request_dump=resp.dump_request(),
                        response_dump=resp.dump_response(max_body=500),
                    ))

                # Check for HSTS-specific issues
                if header_name == "Strict-Transport-Security" and value:
                    self._check_hsts(value, resp, findings)

            # Check for dangerous information disclosure headers
            for header_name, info in DANGEROUS_HEADERS.items():
                value = resp.header(header_name)
                if value:
                    findings.append(ScanFinding(
                        plugin_id=self.meta.plugin_id,
                        title=f"Information Disclosure: {header_name}",
                        description=f"{info['description']} Value: {value}",
                        severity=Severity(info["severity"]),
                        confidence=Confidence.CONFIRMED,
                        url=resp.url,
                        method="GET",
                        evidence=f"{header_name}: {value}",
                        cwe_id=info["cwe_id"],
                        remediation=info["remediation"],
                        request_dump=resp.dump_request(),
                        response_dump=resp.dump_response(max_body=500),
                    ))

            # Check for insecure cookie flags
            self._check_cookies(resp, findings)

        return findings

    def _check_hsts(self, value: str, resp, findings: list[ScanFinding]) -> None:
        """Check HSTS header for weak configuration."""
        value_lower = value.lower()

        # Check max-age is at least 6 months (15768000 seconds)
        try:
            for part in value_lower.split(";"):
                part = part.strip()
                if part.startswith("max-age="):
                    max_age = int(part.split("=")[1])
                    if max_age < 15768000:
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title="Weak HSTS max-age",
                            description=f"HSTS max-age is {max_age} seconds, which is less than the recommended 6 months (15768000).",
                            severity=Severity.LOW,
                            confidence=Confidence.CONFIRMED,
                            url=resp.url,
                            method="GET",
                            evidence=f"Strict-Transport-Security: {value}",
                            cwe_id=523,
                            remediation="Set Strict-Transport-Security max-age to at least 15768000 (6 months).",
                        ))
        except (ValueError, IndexError):
            pass

    def _check_cookies(self, resp, findings: list[ScanFinding]) -> None:
        """Check Set-Cookie headers for missing security flags."""
        for key, value in resp.headers.items():
            if key.lower() != "set-cookie":
                continue

            cookie_lower = value.lower()
            cookie_name = value.split("=")[0].strip()

            if "secure" not in cookie_lower:
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=f"Cookie Missing Secure Flag: {cookie_name}",
                    description="Cookie is set without the Secure flag, allowing transmission over unencrypted HTTP.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    url=resp.url,
                    method="GET",
                    evidence=f"Set-Cookie: {value[:200]}",
                    cwe_id=614,
                    remediation="Add the Secure flag to all cookies.",
                ))

            if "httponly" not in cookie_lower:
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=f"Cookie Missing HttpOnly Flag: {cookie_name}",
                    description="Cookie is set without the HttpOnly flag, making it accessible to JavaScript.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    url=resp.url,
                    method="GET",
                    evidence=f"Set-Cookie: {value[:200]}",
                    cwe_id=1004,
                    remediation="Add the HttpOnly flag to cookies that don't need JavaScript access.",
                ))

            if "samesite" not in cookie_lower:
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=f"Cookie Missing SameSite Attribute: {cookie_name}",
                    description="Cookie is set without the SameSite attribute, potentially vulnerable to CSRF.",
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    url=resp.url,
                    method="GET",
                    evidence=f"Set-Cookie: {value[:200]}",
                    cwe_id=1275,
                    remediation="Add SameSite=Strict or SameSite=Lax to cookies.",
                ))
