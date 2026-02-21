"""Unit tests for modules/recon.py."""

from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Test 1 — dns_lookup returns a well-formed dict
# ---------------------------------------------------------------------------

@patch("modules.recon.dns.resolver.resolve")
def test_dns_lookup_returns_dict(mock_resolve, mock_state):
    """dns_lookup should return a dict with A, MX, NS, TXT keys."""

    # Each call to resolve() returns a list-like of records
    def fake_resolve(target, rtype):
        mapping = {
            "A":   [MagicMock(__str__=lambda s: "1.2.3.4")],
            "MX":  [MagicMock(__str__=lambda s: "10 mail.example.com.")],
            "NS":  [MagicMock(__str__=lambda s: "ns1.example.com.")],
            "TXT": [MagicMock(__str__=lambda s: "v=spf1 include:example.com ~all")],
        }
        return mapping.get(rtype, [])

    mock_resolve.side_effect = fake_resolve

    from modules.recon import dns_lookup
    result = dns_lookup("example.com")

    assert isinstance(result, dict)
    for key in ("A", "MX", "NS", "TXT"):
        assert key in result
    assert "1.2.3.4" in result["A"]


# ---------------------------------------------------------------------------
# Test 2 — whois_lookup handles exceptions gracefully
# ---------------------------------------------------------------------------

@patch("modules.recon.whois.whois")
def test_whois_lookup_handles_error(mock_whois, mock_state):
    """whois_lookup must return {} when the underlying library raises."""
    mock_whois.side_effect = Exception("WHOIS server unreachable")

    from modules.recon import whois_lookup
    result = whois_lookup("example.com")

    assert result == {}


# ---------------------------------------------------------------------------
# Test 3 — subfinder_enum returns [] when binary is missing
# ---------------------------------------------------------------------------

@patch("modules.recon.subprocess.run")
def test_subfinder_not_found(mock_run, mock_state):
    """subfinder_enum should return an empty list on FileNotFoundError."""
    mock_run.side_effect = FileNotFoundError("subfinder not found")

    from modules.recon import subfinder_enum
    result = subfinder_enum("example.com")

    assert result == []
