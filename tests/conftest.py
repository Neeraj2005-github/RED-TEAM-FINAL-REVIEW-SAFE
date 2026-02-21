"""Shared fixtures for the AI Red Team Framework test suite."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def mock_state(tmp_path):
    """Patch the module-level ``state`` singleton so tests never touch the
    real ``db/state.json`` file.  Provides a fresh in-memory dict per test.
    """
    state_file: Path = tmp_path / "state.json"
    state_file.write_text("{}")

    fake = MagicMock()
    _store: dict = {}

    def _get(key, default=None):
        return _store.get(key, default)

    def _set(key, value):
        _store[key] = value

    def _append(key, item):
        _store.setdefault(key, []).append(item)

    def _reset():
        _store.clear()

    fake.get = MagicMock(side_effect=_get)
    fake.set = MagicMock(side_effect=_set)
    fake.append = MagicMock(side_effect=_append)
    fake.reset = MagicMock(side_effect=_reset)
    fake._store = _store

    with patch("core.state_manager.state", fake):
        yield fake


@pytest.fixture()
def sample_scan_results():
    """Realistic scan-results dict used by multiple test modules."""
    return {
        "22": {
            "service": "ssh",
            "version": "OpenSSH 8.9",
            "banner": "SSH-2.0-OpenSSH_8.9",
            "os_guess": "Linux 5.x",
            "cves": [],
        },
        "80": {
            "service": "http",
            "version": "Apache 2.4.54",
            "banner": "",
            "os_guess": "Linux 5.x",
            "cves": [
                {"cve_id": "CVE-2023-12345", "description": "test", "cvss_score": 7.5}
            ],
        },
    }
