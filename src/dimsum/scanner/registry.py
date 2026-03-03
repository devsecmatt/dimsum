from __future__ import annotations

import importlib
import logging
import pkgutil
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dimsum.scanner.base_plugin import BaseScanPlugin

logger = logging.getLogger(__name__)


class PluginMeta:
    """Metadata attached to a registered plugin class."""

    def __init__(
        self,
        plugin_id: str,
        name: str,
        category: str,
        owasp_category: str | None = None,
        asvs_ids: list[str] | None = None,
        cwe_ids: list[int] | None = None,
        description: str = "",
        is_enumeration: bool = False,
    ):
        self.plugin_id = plugin_id
        self.name = name
        self.category = category
        self.owasp_category = owasp_category
        self.asvs_ids = asvs_ids or []
        self.cwe_ids = cwe_ids or []
        self.description = description
        self.is_enumeration = is_enumeration


class PluginRegistry:
    """Singleton registry for scan plugins.

    Plugins self-register using the @PluginRegistry.register() decorator.
    """

    _plugins: dict[str, type[BaseScanPlugin]] = {}

    @classmethod
    def register(
        cls,
        plugin_id: str,
        *,
        name: str,
        category: str,
        owasp_category: str | None = None,
        asvs_ids: list[str] | None = None,
        cwe_ids: list[int] | None = None,
        description: str = "",
        is_enumeration: bool = False,
    ):
        """Decorator that registers a plugin class."""

        def decorator(plugin_cls: type[BaseScanPlugin]) -> type[BaseScanPlugin]:
            plugin_cls.meta = PluginMeta(
                plugin_id=plugin_id,
                name=name,
                category=category,
                owasp_category=owasp_category,
                asvs_ids=asvs_ids,
                cwe_ids=cwe_ids,
                description=description,
                is_enumeration=is_enumeration,
            )
            cls._plugins[plugin_id] = plugin_cls
            logger.debug("Registered plugin: %s (%s)", plugin_id, name)
            return plugin_cls

        return decorator

    @classmethod
    def get(cls, plugin_id: str) -> type[BaseScanPlugin] | None:
        return cls._plugins.get(plugin_id)

    @classmethod
    def get_all(cls) -> dict[str, type[BaseScanPlugin]]:
        return dict(cls._plugins)

    @classmethod
    def get_by_category(cls, category: str) -> list[type[BaseScanPlugin]]:
        return [p for p in cls._plugins.values() if p.meta.category == category]

    @classmethod
    def get_enumeration_plugins(cls) -> list[type[BaseScanPlugin]]:
        return [p for p in cls._plugins.values() if p.meta.is_enumeration]

    @classmethod
    def get_security_plugins(cls) -> list[type[BaseScanPlugin]]:
        return [p for p in cls._plugins.values() if not p.meta.is_enumeration]

    @classmethod
    def list_info(cls) -> list[dict[str, Any]]:
        """Return metadata for all registered plugins."""
        return [
            {
                "plugin_id": p.meta.plugin_id,
                "name": p.meta.name,
                "category": p.meta.category,
                "owasp_category": p.meta.owasp_category,
                "is_enumeration": p.meta.is_enumeration,
                "description": p.meta.description,
            }
            for p in cls._plugins.values()
        ]

    @classmethod
    def discover_plugins(cls) -> None:
        """Walk the plugins package and import all modules to trigger registration."""
        import dimsum.scanner.plugins as plugins_pkg

        for importer, modname, ispkg in pkgutil.walk_packages(
            plugins_pkg.__path__, prefix=plugins_pkg.__name__ + "."
        ):
            try:
                importlib.import_module(modname)
            except Exception:
                logger.exception("Failed to import plugin module: %s", modname)

    @classmethod
    def clear(cls) -> None:
        """Clear all registered plugins (useful for testing)."""
        cls._plugins.clear()
