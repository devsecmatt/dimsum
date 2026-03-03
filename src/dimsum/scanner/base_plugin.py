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

    def log(self, msg: str, *args) -> None:
        """Log a message scoped to this plugin."""
        import logging
        logger = logging.getLogger(f"dimsum.scanner.{self.meta.plugin_id}")
        logger.info(msg, *args)
