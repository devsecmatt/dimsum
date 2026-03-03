"""Command Injection Scanner Plugin.

Tests for OS command injection by injecting shell metacharacters
into URL parameters and checking for command execution indicators.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.payloads import CMDI_INDICATORS
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "command_injection",
    name="OS Command Injection",
    category="injection",
    owasp_category="A03:2021-Injection",
    asvs_ids=["V5.3.8"],
    cwe_ids=[78],
    description="Tests for OS command injection vulnerabilities.",
)
class CommandInjectionPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        generator = self.get_payload_generator()

        for url in self.get_target_urls():
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)

            if not params:
                default_params = ["cmd", "exec", "command", "file", "path", "dir", "host", "ip"]
                default_params.extend(generator.get_discovered_params())
                params = {p: ["test"] for p in set(default_params)}

            for param_name in params:
                # Get baseline
                baseline_url = self._inject_param(url, param_name, "harmless_test_value")
                baseline = await self.http.get(baseline_url)
                if baseline is None:
                    continue

                # Check baseline doesn't already contain indicators
                if self._has_cmd_output(baseline.text):
                    continue

                for payload in generator.get_cmdi_payloads(param_name, url):
                    test_url = self._inject_param(url, param_name, payload)
                    resp = await self.http.get(test_url)
                    if resp is None:
                        continue

                    indicator = self._has_cmd_output(resp.text)
                    if indicator:
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title=f"OS Command Injection in '{param_name}' parameter",
                            description=(
                                f"The parameter '{param_name}' appears vulnerable to OS command injection. "
                                f"Command execution output was detected in the response."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Command execution indicator found: {indicator}",
                            cwe_id=78,
                            cvss_score=9.8,
                            remediation=(
                                "Never pass user input directly to system commands. Use language-specific "
                                "APIs instead of shell commands. If shell commands are necessary, use "
                                "allowlists for input validation and proper escaping."
                            ),
                            request_dump=resp.dump_request(),
                            response_dump=resp.dump_response(),
                        ))
                        break

        # Phase 2: Fuzz parameters discovered by source analysis
        findings.extend(await self._fuzz_extracted_params())

        return findings

    async def _fuzz_extracted_params(self) -> list[ScanFinding]:
        """Test parameters extracted from source code analysis."""
        findings: list[ScanFinding] = []
        extracted = self.get_extracted_params_by_source("query", "body", "path")
        if not extracted:
            return findings

        for url in self.get_target_urls():
            for ep in extracted:
                param_name = ep["name"]
                param_source = ep.get("source", "query")

                # Baseline check
                if param_source == "body":
                    baseline = await self.http.post(url, data={param_name: "harmless_test_value"})
                else:
                    baseline = await self.http.get(self._inject_param(url, param_name, "harmless_test_value"))

                if baseline is None or self._has_cmd_output(baseline.text):
                    continue

                method = "POST" if param_source == "body" else "GET"

                for payload in CMDI_PAYLOADS:
                    if param_source == "body":
                        resp = await self.http.post(url, data={param_name: payload})
                    else:
                        resp = await self.http.get(self._inject_param(url, param_name, payload))

                    if resp is None:
                        continue

                    indicator = self._has_cmd_output(resp.text)
                    if indicator:
                        findings.append(ScanFinding(
                            plugin_id=self.meta.plugin_id,
                            title=f"OS Command Injection in '{param_name}' parameter (source analysis)",
                            description=(
                                f"The parameter '{param_name}' (found via source analysis) appears "
                                f"vulnerable to OS command injection."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.FIRM,
                            url=url,
                            method=method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Command execution indicator found: {indicator}",
                            cwe_id=78,
                            cvss_score=9.8,
                            remediation=(
                                "Never pass user input directly to system commands. Use "
                                "language-specific APIs instead of shell commands."
                            ),
                            source_file=ep.get("file", ""),
                            source_line=ep.get("line"),
                        ))
                        break
        return findings

    @staticmethod
    def _has_cmd_output(body: str) -> str | None:
        body_lower = body.lower()
        for indicator in CMDI_INDICATORS:
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
