"""Unit tests for modules/scanner.py."""

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test 1 — masscan fallback to default port list
# ---------------------------------------------------------------------------

@patch("modules.scanner.subprocess.run")
def test_masscan_fallback(mock_run, mock_state):
    """When masscan is unavailable, masscan_discovery must return the
    default port list.
    """
    mock_run.side_effect = FileNotFoundError("masscan not installed")

    from modules.scanner import masscan_discovery, DEFAULT_PORTS
    result = masscan_discovery("192.168.1.1")

    assert result == DEFAULT_PORTS


# ---------------------------------------------------------------------------
# Test 2 — nvd_cve_lookup returns [] on HTTP error
# ---------------------------------------------------------------------------

@patch("modules.scanner.requests.get")
@patch("modules.scanner.time.sleep", return_value=None)
def test_nvd_lookup_empty_on_error(mock_sleep, mock_get, mock_state):
    """nvd_cve_lookup should return an empty list when the NVD API times out."""
    import requests as _req
    mock_get.side_effect = _req.exceptions.Timeout("NVD timeout")

    from modules.scanner import nvd_cve_lookup
    result = nvd_cve_lookup("ssh", "8.9")

    assert result == []


# ---------------------------------------------------------------------------
# Test 3 — nmap_scan returns a structured dict
# ---------------------------------------------------------------------------

@patch("modules.scanner.nmap.PortScanner")
def test_nmap_returns_structured_dict(mock_scanner_cls, mock_state):
    """nmap_scan should return a dict keyed by port with expected fields."""
    # Build a mock that behaves like python-nmap's PortScanner
    nm = MagicMock()
    mock_scanner_cls.return_value = nm

    nm.all_hosts.return_value = ["192.168.1.1"]

    # Simulate host data
    host = MagicMock()
    host.all_protocols.return_value = ["tcp"]
    host.__getitem__ = lambda self, k: {
        "tcp": {
            22: {
                "state": "open",
                "name": "ssh",
                "version": "OpenSSH 8.9",
                "script": {"banner": "SSH-2.0-OpenSSH_8.9"},
            }
        },
        "osmatch": [{"name": "Linux 5.x"}],
    }[k]

    nm.__getitem__ = lambda self, k: host

    from modules.scanner import nmap_scan
    result = nmap_scan("192.168.1.1", [22])

    assert isinstance(result, dict)
    assert 22 in result
    assert result[22]["service"] == "ssh"
    assert result[22]["version"] == "OpenSSH 8.9"
