from __future__ import annotations

import abc
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dimsum.scanner.context import ScanContext
    from dimsum.scanner.http_client import AsyncHTTPClient
    from dimsum.scanner.registry import PluginMeta
    from dimsum.scanner.result import ScanFinding


class BaseScanPlugin(abc.ABC):
    """Abstract base class for all scan plugins.

    Subclasses must implement `run()` which performs the actual scanning
    and returns a list of ScanFinding objects.
    """

    meta: PluginMeta  # Populated by @PluginRegistry.register()

    def __init__(self, context: ScanContext, http_client: AsyncHTTPClient):
        self.context = context
        self.http = http_client

    @abc.abstractmethod
    async def run(self) -> list[ScanFinding]:
        """Execute the plugin's scanning logic.

        Returns a list of findings discovered during the scan.
        """
        ...

    def get_target_urls(self) -> list[str]:
        """Get all URLs to scan from context (explicit targets + discovered endpoints)."""
        urls = list(self.context.target_urls)
        urls.extend(self.context.discovered_endpoints)
        return urls

    def get_extracted_params_by_source(self, *sources: str) -> list[dict]:
        """Get extracted parameters filtered by source type (query, body, header, path, cookie).

        Returns a deduplicated list of parameter dicts from source analysis.
        """
        seen: set[str] = set()
        result: list[dict] = []
        for ep in self.context.extracted_parameters:
            name = ep.get("name", "")
            source = ep.get("source", "query")
            if not name:
                continue
            if sources and source not in sources:
                continue
            key = f"{name}:{source}"
            if key not in seen:
                seen.add(key)
                result.append(ep)
        return result

    def get_payload_generator(self):
        """Create a PayloadGenerator with context from source analysis."""
        from dimsum.scanner.payload_generator import PayloadGenerator
        return PayloadGenerator(
            extracted_parameters=self.context.extracted_parameters,
            risk_indicators=self.context.risk_indicators,
        )

    def log(self, msg: str, *args) -> None:
        """Log a message scoped to this plugin."""
        import logging
        logger = logging.getLogger(f"dimsum.scanner.{self.meta.plugin_id}")
        logger.info(msg, *args)
