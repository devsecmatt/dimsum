from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    """Shared state passed to every plugin during a scan.

    Collects target information, discovered endpoints, configuration,
    and provides a place for plugins to share data.
    """

    scan_id: uuid.UUID

    # Target information
    target_urls: list[str] = field(default_factory=list)
    target_domains: list[str] = field(default_factory=list)
    target_ips: list[str] = field(default_factory=list)

    # Endpoints discovered by enumeration plugins
    discovered_endpoints: list[str] = field(default_factory=list)

    # Data extracted from source code analysis
    extracted_parameters: list[dict[str, Any]] = field(default_factory=list)
    extracted_routes: list[dict[str, Any]] = field(default_factory=list)

    # Risk indicators from source analysis
    risk_indicators: list[dict[str, Any]] = field(default_factory=list)

    # Configuration
    max_concurrency: int = 10
    request_delay_ms: int = 100
    timeout_seconds: int = 30
    max_depth: int = 3
    custom_headers: dict[str, str] = field(default_factory=dict)
    auth_config: dict[str, Any] | None = None
    asvs_level: int = 1

    # Scan type control
    scan_type: str = "full"
    enabled_plugin_ids: list[str] = field(default_factory=list)

    # Shared data between plugins (e.g., crawled page data)
    shared_data: dict[str, Any] = field(default_factory=dict)

    # Progress tracking
    total_checks: int = 0
    completed_checks: int = 0

    @property
    def all_urls(self) -> list[str]:
        """All URLs: explicit targets + discovered endpoints."""
        return list(set(self.target_urls + self.discovered_endpoints))

    def add_discovered_endpoint(self, url: str) -> None:
        if url not in self.discovered_endpoints:
            self.discovered_endpoints.append(url)

    def update_progress(self, completed: int, total: int) -> None:
        self.completed_checks = completed
        self.total_checks = total

    @property
    def progress_percent(self) -> int:
        if self.total_checks == 0:
            return 0
        return min(100, int((self.completed_checks / self.total_checks) * 100))
