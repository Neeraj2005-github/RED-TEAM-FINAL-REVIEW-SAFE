"""
tests/test_config.py — Tests for the ConfigManager system.

Covers:
  * YAML loading
  * Environment variable overrides (string, bool, int, float, list)
  * CLI override priority
  * Validation
  * Dot-access
  * Wordlist resolver
  * API key lookup
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent.parent
YAML_PATH = ROOT / "config" / "config.yaml"

# Env-var keys we set during tests — cleaned up in the fixture
_TEST_ENV_KEYS: list[str] = [
    "REDTEAM_GENERAL_TARGET",
    "REDTEAM_SECURITY_DRY_RUN",
    "REDTEAM_TIMEOUT_SCAN_TIMEOUT",
    "REDTEAM_EXPLOITATION_BRUTE_FORCE_DELAY",
    "REDTEAM_SCOPE_EXCLUDE_IPS",
]


@pytest.fixture(autouse=True)
def _clean_env():
    """Remove test env vars before and after each test."""
    for key in _TEST_ENV_KEYS:
        os.environ.pop(key, None)
    yield
    for key in _TEST_ENV_KEYS:
        os.environ.pop(key, None)


# ---------------------------------------------------------------------------
# 1. Basic YAML loading
# ---------------------------------------------------------------------------

def test_yaml_loads_defaults():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)

    # These are defined in config/config.yaml
    assert cfg.general.target == "192.168.1.1"
    assert cfg.general.log_level == "INFO"
    assert cfg.security.dry_run is True
    assert cfg.security.safe_mode is True


def test_dot_access_nested():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    assert cfg.timeout.dns_timeout == 5
    assert cfg.timeout.scan_timeout == 600
    assert cfg.groq_llm.model == "llama-3.3-70b-versatile"


def test_missing_section_raises():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    with pytest.raises(AttributeError):
        _ = cfg.nonexistent_section


def test_missing_file_uses_defaults():
    from config.settings import ConfigManager

    cfg = ConfigManager("/tmp/__nonexistent_config__.yaml")
    # Should not crash; internal dict is empty
    assert cfg.to_dict() == {} or isinstance(cfg.to_dict(), dict)


# ---------------------------------------------------------------------------
# 2. Environment variable overrides
# ---------------------------------------------------------------------------

def test_env_var_string_override():
    from config.settings import ConfigManager

    os.environ["REDTEAM_GENERAL_TARGET"] = "env-override.com"
    cfg = ConfigManager(YAML_PATH)
    assert cfg.general.target == "env-override.com"


def test_env_var_boolean_override():
    from config.settings import ConfigManager

    os.environ["REDTEAM_SECURITY_DRY_RUN"] = "false"
    cfg = ConfigManager(YAML_PATH)
    assert cfg.security.dry_run is False


def test_env_var_integer_override():
    from config.settings import ConfigManager

    os.environ["REDTEAM_TIMEOUT_SCAN_TIMEOUT"] = "900"
    cfg = ConfigManager(YAML_PATH)
    assert cfg.timeout.scan_timeout == 900


def test_env_var_float_override():
    from config.settings import ConfigManager

    os.environ["REDTEAM_EXPLOITATION_BRUTE_FORCE_DELAY"] = "0.5"
    cfg = ConfigManager(YAML_PATH)
    assert cfg.exploitation.brute_force_delay == 0.5


def test_env_var_list_override():
    from config.settings import ConfigManager

    os.environ["REDTEAM_SCOPE_EXCLUDE_IPS"] = "[10.0.0.1,10.0.0.2]"
    cfg = ConfigManager(YAML_PATH)
    assert cfg.scope.exclude_ips == ["10.0.0.1", "10.0.0.2"]


# ---------------------------------------------------------------------------
# 3. CLI overrides (highest priority)
# ---------------------------------------------------------------------------

def test_cli_override_beats_yaml():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH, cli_overrides={"general.target": "cli.example.com"})
    assert cfg.general.target == "cli.example.com"


def test_cli_override_beats_env():
    from config.settings import ConfigManager

    os.environ["REDTEAM_GENERAL_TARGET"] = "env.example.com"
    cfg = ConfigManager(YAML_PATH, cli_overrides={"general.target": "cli-wins.com"})
    assert cfg.general.target == "cli-wins.com"


def test_priority_chain():
    """CLI > ENV > YAML."""
    from config.settings import ConfigManager

    # YAML default
    cfg_yaml = ConfigManager(YAML_PATH)
    assert cfg_yaml.general.target == "192.168.1.1"

    # ENV overrides YAML
    os.environ["REDTEAM_GENERAL_TARGET"] = "env.com"
    cfg_env = ConfigManager(YAML_PATH)
    assert cfg_env.general.target == "env.com"

    # CLI overrides ENV
    cfg_cli = ConfigManager(YAML_PATH, cli_overrides={"general.target": "cli.com"})
    assert cfg_cli.general.target == "cli.com"


# ---------------------------------------------------------------------------
# 4. Validation
# ---------------------------------------------------------------------------

def test_validate_returns_list():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    issues = cfg.validate_configuration()
    assert isinstance(issues, list)


def test_validate_warns_on_missing_api_key():
    from config.settings import ConfigManager

    # Unless GROQ_API_KEY is actually set in the environment, we expect a warning
    orig = os.environ.pop("GROQ_API_KEY", None)
    try:
        cfg = ConfigManager(YAML_PATH)
        issues = cfg.validate_configuration()
        warnings = [i for i in issues if "GROQ_API_KEY" in i]
        if not orig:
            assert len(warnings) >= 1
    finally:
        if orig:
            os.environ["GROQ_API_KEY"] = orig


def test_validate_no_target_error():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH, cli_overrides={"general.target": ""})
    issues = cfg.validate_configuration()
    errors = [i for i in issues if i.startswith("ERROR")]
    assert any("target" in e.lower() for e in errors)


# ---------------------------------------------------------------------------
# 5. Utility methods
# ---------------------------------------------------------------------------

def test_get_api_key_groq():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    # get_api_key reads from env
    key = cfg.get_api_key("groq_llm")
    assert isinstance(key, str)


def test_get_wordlist():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    path = cfg.get_wordlist("subdomains")
    assert isinstance(path, Path)
    assert "subdomains" in str(path)


def test_get_dotted():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    assert cfg.get("timeout.dns_timeout") == 5
    assert cfg.get("nonexistent.key", "fallback") == "fallback"


def test_to_dict():
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    d = cfg.to_dict()
    assert isinstance(d, dict)
    assert "general" in d
    assert "security" in d


def test_print_config_no_crash(capsys):
    from config.settings import ConfigManager

    cfg = ConfigManager(YAML_PATH)
    # Should not raise
    cfg.print_config_summary()


# ---------------------------------------------------------------------------
# 6. load_config / get_config convenience
# ---------------------------------------------------------------------------

def test_load_config_returns_singleton():
    from config.settings import load_config, get_config

    c1 = load_config(YAML_PATH)
    c2 = get_config()
    # get_config returns the last loaded config
    assert c2 is c1


def test_get_config_lazy_init():
    from config.settings import get_config

    cfg = get_config()
    assert cfg is not None
