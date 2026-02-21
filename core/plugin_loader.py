"""
core/plugin_loader.py — Dynamic module discovery and loading for the
AI Red Team Framework.

Scans configured directories for Python modules that expose a standard
interface, registers them in a :class:`ModuleRegistry`, and provides
runtime lookup by name or category.

Standard module interface
~~~~~~~~~~~~~~~~~~~~~~~~~

Every loadable module must expose **two** callables at module level:

* ``execute(context: ExecutionContext) -> ExecutionResult``
* ``metadata() -> dict``  (or a ``ModuleMetadata``-compatible dict)

Modules that lack either callable are skipped with a warning.

Usage::

    from core.plugin_loader import registry, load_all_plugins

    load_all_plugins()                       # scan default dirs
    recon_mods = registry.list_by_category("recon")
    mod = registry.get_by_name("recon")
    result = mod.execute(ctx)
"""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

@dataclass
class ModuleMetadata:
    """Describes a loaded plugin module."""

    name: str
    version: str = "0.1.0"
    author: str = ""
    category: str = ""                   # e.g. "recon", "exploit", "post_exploit"
    dependencies: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    description: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleMetadata":
        return cls(
            name=data.get("name", "unknown"),
            version=data.get("version", "0.1.0"),
            author=data.get("author", ""),
            category=data.get("category", ""),
            dependencies=data.get("dependencies", []),
            mitre_techniques=data.get("mitre_techniques", []),
            description=data.get("description", ""),
        )


@dataclass
class ExecutionContext:
    """Container passed into every plugin's ``execute()`` call."""

    phase: str
    target_info: dict[str, Any] = field(default_factory=dict)
    previous_results: dict[str, Any] = field(default_factory=dict)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Standardised return value from a plugin's ``execute()`` call."""

    success: bool = False
    output: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 2. Plugin wrapper
# ---------------------------------------------------------------------------

class PluginModule:
    """Thin wrapper around a loaded Python module that guarantees the
    standard interface.
    """

    def __init__(
        self,
        raw_module: ModuleType,
        meta: ModuleMetadata,
        execute_fn: Callable[..., Any],
    ) -> None:
        self._module = raw_module
        self.metadata = meta
        self._execute_fn = execute_fn

    @property
    def name(self) -> str:
        return self.metadata.name

    def execute(self, context: ExecutionContext) -> ExecutionResult:
        """Run the plugin and normalise the return value."""
        try:
            raw = self._execute_fn(context)
            if isinstance(raw, ExecutionResult):
                return raw
            # Legacy modules return plain dicts / lists — wrap them.
            return ExecutionResult(success=True, output={"data": raw})
        except Exception as exc:
            logger.exception("Plugin %s raised an error", self.name)
            return ExecutionResult(success=False, errors=[str(exc)])


# ---------------------------------------------------------------------------
# 3. Module Registry
# ---------------------------------------------------------------------------

class ModuleRegistry:
    """Central catalogue of all loaded plugin modules."""

    def __init__(self) -> None:
        self._modules: dict[str, PluginModule] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, module_name: str, plugin: PluginModule) -> None:
        """Register *plugin* under *module_name*."""
        self._modules[module_name] = plugin
        logger.info("Registered plugin: %s (category=%s)", module_name, plugin.metadata.category)

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_by_name(self, module_name: str) -> Optional[PluginModule]:
        """Return the plugin registered under *module_name*, or ``None``."""
        return self._modules.get(module_name)

    def list_by_category(self, category: str) -> list[PluginModule]:
        """Return all plugins whose metadata category matches *category*."""
        return [p for p in self._modules.values() if p.metadata.category == category]

    def list_all(self) -> list[PluginModule]:
        """Return every registered plugin."""
        return list(self._modules.values())

    @property
    def names(self) -> list[str]:
        """Return the sorted names of all registered plugins."""
        return sorted(self._modules.keys())


# Module-level singleton
registry = ModuleRegistry()


# ---------------------------------------------------------------------------
# 4. Loader helpers
# ---------------------------------------------------------------------------

# Category inferred from the containing directory name
_DIR_CATEGORY_MAP: dict[str, str] = {
    "modules": "",        # inferred per-file below
    "recon": "recon",
    "exploit": "exploit",
    "post_exploit": "post_exploit",
    "mitre": "mitre",
}

# Modules that the old engine imported — map file stem → canonical name
# and category so the engine can look them up by their legacy phase name.
_LEGACY_MODULE_MAP: dict[str, tuple[str, str]] = {
    "recon": ("recon", "recon"),
    "scanner": ("scanner", "recon"),
    "ai_decision": ("ai_decision", "analysis"),
    "exploit": ("exploit", "exploit"),
    "privesc": ("privesc", "post_exploit"),
    "persistence": ("persistence", "post_exploit"),
    "reporter": ("reporter", "reporting"),
}


def _infer_category(stem: str) -> str:
    """Return the category string for a module file stem."""
    if stem in _LEGACY_MODULE_MAP:
        return _LEGACY_MODULE_MAP[stem][1]
    return ""


def _build_metadata(raw_module: ModuleType, stem: str) -> ModuleMetadata:
    """Extract or synthesise a ``ModuleMetadata`` from *raw_module*."""
    if hasattr(raw_module, "metadata") and callable(raw_module.metadata):
        try:
            return ModuleMetadata.from_dict(raw_module.metadata())
        except Exception:
            pass

    # Synthesise from module attributes
    return ModuleMetadata(
        name=stem,
        category=_infer_category(stem),
        description=(raw_module.__doc__ or "").strip().split("\n")[0],
    )


def _get_execute_fn(raw_module: ModuleType) -> Optional[Callable[..., Any]]:
    """Return the ``execute`` callable from *raw_module*, or ``None``.

    Falls back to the legacy ``run()`` function, wrapping it in an
    adapter that unpacks an :class:`ExecutionContext`.
    """
    if hasattr(raw_module, "execute") and callable(raw_module.execute):
        return raw_module.execute

    # Legacy adapter: ``run(target, **kwargs)``
    if hasattr(raw_module, "run") and callable(raw_module.run):
        legacy_run = raw_module.run

        def _adapter(context: ExecutionContext) -> Any:
            target = context.target_info.get("target", "")
            return legacy_run(target, **context.config)

        return _adapter

    return None


def _load_module_from_path(filepath: Path, package: str = "") -> Optional[ModuleType]:
    """Import a single Python file and return the module object."""
    module_name = f"{package}.{filepath.stem}" if package else filepath.stem
    try:
        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec is None or spec.loader is None:
            return None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = mod
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod
    except Exception as exc:
        logger.warning("Failed to import %s: %s", filepath, exc)
        return None


# ---------------------------------------------------------------------------
# 5. Public loader API
# ---------------------------------------------------------------------------

# Set of module names that should not be loaded (populated from config).
_disabled_modules: set[str] = set()


def disable_module(name: str) -> None:
    """Prevent *name* from being loaded by :func:`load_all_plugins`."""
    _disabled_modules.add(name)


def enable_module(name: str) -> None:
    """Re-allow *name* for loading."""
    _disabled_modules.discard(name)


def load_plugin(filepath: Path, package: str = "") -> Optional[PluginModule]:
    """Load a single plugin from *filepath* and register it.

    Returns the :class:`PluginModule` on success, ``None`` on failure.
    """
    stem = filepath.stem
    if stem.startswith("_"):
        return None  # skip __init__, __pycache__ helpers, etc.

    if stem in _disabled_modules:
        logger.info("Skipping disabled module: %s", stem)
        return None

    raw = _load_module_from_path(filepath, package)
    if raw is None:
        return None

    execute_fn = _get_execute_fn(raw)
    if execute_fn is None:
        logger.debug("Module %s has no execute/run — skipping", stem)
        return None

    meta = _build_metadata(raw, stem)
    plugin = PluginModule(raw, meta, execute_fn)
    registry.register(meta.name, plugin)
    return plugin


def load_plugins_from_directory(directory: Path, package: str = "") -> list[PluginModule]:
    """Discover and load all ``*.py`` plugins inside *directory*."""
    loaded: list[PluginModule] = []
    if not directory.is_dir():
        logger.debug("Plugin directory does not exist: %s", directory)
        return loaded

    for filepath in sorted(directory.glob("*.py")):
        plugin = load_plugin(filepath, package)
        if plugin is not None:
            loaded.append(plugin)

    return loaded


def load_all_plugins(
    base_dir: Optional[Path] = None,
    extra_dirs: Optional[list[Path]] = None,
) -> list[PluginModule]:
    """Scan the default module directories and load every valid plugin.

    Searches ``modules/`` by default, plus any paths in *extra_dirs*.
    """
    if base_dir is None:
        from config.settings import BASE_DIR
        base_dir = BASE_DIR

    search_dirs: list[tuple[Path, str]] = [
        (base_dir / "modules", "modules"),
    ]

    for name in ("recon", "exploit", "post_exploit", "mitre"):
        candidate = base_dir / name
        if candidate.is_dir():
            search_dirs.append((candidate, name))

    if extra_dirs:
        for d in extra_dirs:
            search_dirs.append((d, d.name))

    all_loaded: list[PluginModule] = []
    for directory, package in search_dirs:
        all_loaded.extend(load_plugins_from_directory(directory, package))

    logger.info("Loaded %d plugin(s): %s", len(all_loaded), registry.names)
    return all_loaded
