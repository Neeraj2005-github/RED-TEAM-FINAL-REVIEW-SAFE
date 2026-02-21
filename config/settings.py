"""
config/settings.py — Unified configuration for the AI Red Team Framework.

Configuration priority (highest wins):
  1. CLI arguments   (passed as *cli_overrides* dict)
  2. Environment variables  (REDTEAM_<SECTION>_<KEY>)
  3. YAML config file (config/config.yaml)
  4. Hard-coded defaults below

Legacy module-level constants (BASE_DIR, GROQ_API_KEY, …) are still
exported so existing code keeps working.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# ── Legacy constants (backward compat) ────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

BASE_DIR = Path(__file__).parent.parent

DB_PATH = BASE_DIR / "db" / "state.json"
REPORTS_DIR = BASE_DIR / "reports"
GRAPHS_DIR = BASE_DIR / "graphs"
WORDLISTS_DIR = BASE_DIR / "wordlists"

SCAN_TIMEOUT = 120
EXPLOIT_TIMEOUT = 5
WORDLIST_PATH = WORDLISTS_DIR / "passwords_common.txt"


# ── Section accessor ──────────────────────────────────────────────────

class _Section:
    """Dot-access wrapper around a dict section of the config."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def __getattr__(self, key: str) -> Any:
        try:
            val = self._data[key]
        except KeyError:
            raise AttributeError(f"Config key not found: {key}")
        if isinstance(val, dict):
            return _Section(val)
        return val

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def __repr__(self) -> str:
        return f"_Section({self._data!r})"

    def to_dict(self) -> dict[str, Any]:
        return dict(self._data)


# ── ConfigManager ─────────────────────────────────────────────────────

class ConfigManager:
    """Load YAML → apply env-var overrides → apply CLI overrides.

    Usage::

        cfg = ConfigManager("config/config.yaml")
        cfg.general.target          # "192.168.1.1"
        cfg.timeout.scan_timeout    # 600
        cfg.get_api_key("groq_llm") # env GROQ_API_KEY
    """

    DEFAULT_PATH = BASE_DIR / "config" / "config.yaml"
    ENV_PREFIX = "REDTEAM"

    def __init__(
        self,
        config_path: str | Path | None = None,
        cli_overrides: dict[str, Any] | None = None,
    ) -> None:
        self._path = Path(config_path) if config_path else self.DEFAULT_PATH
        self._raw: dict[str, Any] = {}
        self._load_yaml()
        self._apply_env_overrides()
        if cli_overrides:
            self._apply_cli_overrides(cli_overrides)
        self._update_legacy_constants()

    # ── YAML loading ──────────────────────────────────────────────────

    def _load_yaml(self) -> None:
        if self._path.is_file():
            with open(self._path, "r", encoding="utf-8") as fh:
                self._raw = yaml.safe_load(fh) or {}
            logger.debug("Loaded config from %s", self._path)
        else:
            logger.warning("Config file not found: %s — using defaults", self._path)
            self._raw = {}

    # ── Env-var overrides (REDTEAM_SECTION_KEY) ───────────────────────

    def _apply_env_overrides(self) -> None:
        prefix = f"{self.ENV_PREFIX}_"
        for key, value in os.environ.items():
            if not key.startswith(prefix):
                continue
            parts = key[len(prefix):].lower().split("_", 1)
            if len(parts) != 2:
                continue
            section, field = parts
            if section not in self._raw:
                self._raw[section] = {}
            self._raw[section][field] = self._coerce(value)

    # ── CLI overrides (flat dict: "section.key" → value) ──────────────

    def _apply_cli_overrides(self, overrides: dict[str, Any]) -> None:
        for dotted_key, value in overrides.items():
            parts = dotted_key.split(".", 1)
            if len(parts) == 2:
                section, field = parts
                if section not in self._raw:
                    self._raw[section] = {}
                self._raw[section][field] = value
            else:
                # Top-level key
                self._raw[dotted_key] = value

    # ── Keep legacy module-level constants in sync ────────────────────

    def _update_legacy_constants(self) -> None:
        global SCAN_TIMEOUT, EXPLOIT_TIMEOUT, GROQ_API_KEY, SHODAN_API_KEY

        SCAN_TIMEOUT = self.get("timeout.scan_timeout", 120)
        EXPLOIT_TIMEOUT = self.get("timeout.exploit_timeout", 5)
        GROQ_API_KEY = self.get_api_key("groq_llm") or GROQ_API_KEY
        SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

    # ── Type coercion for env values ──────────────────────────────────

    @staticmethod
    def _coerce(value: str) -> Any:
        """Convert string env values to appropriate Python types."""
        low = value.lower()
        if low in ("true", "yes", "1"):
            return True
        if low in ("false", "no", "0"):
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        if value.startswith("[") and value.endswith("]"):
            return [v.strip().strip("'\"") for v in value[1:-1].split(",") if v.strip()]
        return value

    # ── Dot-access via section properties ─────────────────────────────

    def __getattr__(self, key: str) -> Any:
        if key.startswith("_"):
            raise AttributeError(key)
        data = self._raw.get(key)
        if data is None:
            raise AttributeError(f"Config section not found: {key}")
        if isinstance(data, dict):
            return _Section(data)
        return data

    # ── Generic getters ───────────────────────────────────────────────

    def get(self, dotted_key: str, default: Any = None) -> Any:
        """Retrieve a value by dot-path (e.g. ``timeout.scan_timeout``)."""
        parts = dotted_key.split(".")
        node: Any = self._raw
        for p in parts:
            if isinstance(node, dict):
                node = node.get(p)
            else:
                return default
            if node is None:
                return default
        return node

    def get_api_key(self, section: str) -> str:
        """Return the API key for *section*, preferring env vars."""
        env_map = {
            "groq_llm": "GROQ_API_KEY",
            "shodan": "SHODAN_API_KEY",
        }
        env_name = env_map.get(section, f"{section.upper()}_API_KEY")
        return os.getenv(env_name, "")

    def get_wordlist(self, name: str) -> Path:
        """Resolve a wordlist name to its filesystem path."""
        mapping = {
            "subdomains": self.get("recon.subdomain_wordlist", "wordlists/subdomains_small.txt"),
            "passwords": self.get("exploitation.password_wordlist", "wordlists/passwords_common.txt"),
        }
        rel = mapping.get(name, f"wordlists/{name}.txt")
        return BASE_DIR / rel

    # ── Validation ────────────────────────────────────────────────────

    def validate_configuration(self) -> list[str]:
        """Return a list of ERROR / WARNING strings."""
        issues: list[str] = []

        target = self.get("general.target", "")
        if not target:
            issues.append("ERROR: general.target is not set")

        if not self.get_api_key("groq_llm"):
            issues.append("WARNING: GROQ_API_KEY not set — LLM features disabled")

        timeout_scan = self.get("timeout.scan_timeout", 0)
        if timeout_scan < 30:
            issues.append(f"WARNING: scan_timeout={timeout_scan}s is very low")

        if not self.get("security.dry_run", True):
            if not self.get("security.safe_mode", True):
                issues.append("WARNING: Both dry_run and safe_mode are OFF — live fire mode")

        return issues

    # ── Pretty summary ────────────────────────────────────────────────

    def print_config_summary(self) -> None:
        """Print a Rich-formatted configuration summary."""
        from rich.console import Console
        from rich.table import Table as RichTable

        c = Console()
        table = RichTable(title="Configuration Summary", show_lines=True)
        table.add_column("Section", style="cyan")
        table.add_column("Key", style="white")
        table.add_column("Value", style="yellow")

        for section_name, section_data in sorted(self._raw.items()):
            if isinstance(section_data, dict):
                for k, v in sorted(section_data.items()):
                    display = str(v)
                    if "key" in k.lower() or "token" in k.lower() or "password" in k.lower():
                        display = "****" if v else "(empty)"
                    table.add_row(section_name, k, display)
            else:
                table.add_row("(root)", section_name, str(section_data))
        c.print(table)

    # ── Serialisation ─────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a deep copy of the raw config dict."""
        import copy
        return copy.deepcopy(self._raw)


# ── Module-level convenience ──────────────────────────────────────────

_config_instance: Optional[ConfigManager] = None


def load_config(
    config_path: str | Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> ConfigManager:
    """Load (or reload) the global ConfigManager singleton."""
    global _config_instance
    _config_instance = ConfigManager(config_path, cli_overrides)
    return _config_instance


def get_config() -> ConfigManager:
    """Return the current ConfigManager, loading defaults if needed."""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance
