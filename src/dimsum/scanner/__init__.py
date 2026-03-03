"""Dimsum Scanner Engine.

The scanning engine uses a plugin-based architecture:
- PluginRegistry: discovers and manages scan plugins
- ScanEngine: orchestrates plugin execution
- BaseScanPlugin: abstract base class for plugins
- ScanContext: shared state per scan
- AsyncHTTPClient: rate-limited async HTTP client
"""

from dimsum.scanner.context import ScanContext
from dimsum.scanner.engine import ScanEngine
from dimsum.scanner.registry import PluginRegistry

__all__ = ["ScanContext", "ScanEngine", "PluginRegistry"]
