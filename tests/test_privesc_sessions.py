"""Tests for the session-type-agnostic privilege escalation module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from core.state_manager import StateManager


@pytest.fixture(autouse=True)
def fresh_state(tmp_path):
    """Provide a clean StateManager for every test."""
    state_file = tmp_path / "state.json"
    with patch("core.state_manager.state", StateManager(str(state_file))):
        yield


def _make_state(tmp_path):
    state_file = tmp_path / "state.json"
    return StateManager(str(state_file))


# ── StateManager session_type tests ────────────────────────────────────────


class TestSessionType:
    def test_ftp_session_type(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 21, "anonymous", "", "ftp_anon")
        assert sm.get_session()["session_type"] == "ftp"
        assert sm.get_session_type() == "ftp"

    def test_ssh_session_type(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 22, "root", "toor", "ssh_brute")
        assert sm.get_session()["session_type"] == "ssh"
        assert sm.get_session_type() == "ssh"

    def test_smb_session_type(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 445, "", "", "smb_enum")
        assert sm.get_session_type() == "smb"

    def test_http_session_type(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 80, "admin", "admin", "http_default_creds")
        assert sm.get_session_type() == "web_shell"

    def test_unknown_technique_passthrough(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 9999, "u", "p", "custom_exploit")
        assert sm.get_session_type() == "custom_exploit"


class TestHasActiveSession:
    def test_no_session(self, tmp_path):
        sm = _make_state(tmp_path)
        assert not sm.has_active_session()

    def test_ftp_anon_empty_username(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 21, "", "", "ftp_anon")
        # FTP anonymous with empty username must still count
        assert sm.has_active_session()

    def test_ssh_session(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 22, "root", "toor", "ssh_brute")
        assert sm.has_active_session()

    def test_alias_matches_has_session(self, tmp_path):
        sm = _make_state(tmp_path)
        sm.set_session("10.0.0.5", 22, "root", "toor", "ssh_brute")
        assert sm.has_session() == sm.has_active_session()


# ── Privesc dispatch tests ─────────────────────────────────────────────────


class TestPrivescDispatch:
    """Test that run_privesc dispatches correctly based on session type."""

    @patch("modules.privesc.state")
    def test_no_session_skips(self, mock_state):
        mock_state.has_active_session.return_value = False
        mock_state.target_ip = "10.0.0.5"

        from modules.privesc import run_privesc
        result = run_privesc()

        assert "No active session available" in result["message"]
        assert result["session_type"] is None
        mock_state.set.assert_called()

    @patch("modules.privesc._try_ssh_client")
    @patch("modules.privesc.state")
    def test_ftp_session_runs_simulated(self, mock_state, mock_ssh):
        mock_state.has_active_session.return_value = True
        mock_state.get_session.return_value = {
            "host": "10.0.0.5",
            "port": 21,
            "username": "anonymous",
            "password": "",
            "technique": "ftp_anon",
            "session_type": "ftp",
        }
        mock_state.get_session_type.return_value = "ftp"
        mock_state.target_ip = "10.0.0.5"

        from modules.privesc import run_privesc
        result = run_privesc()

        assert result["simulated"] is True
        assert result["session_type"] == "ftp"
        assert result["target_ip"] == "10.0.0.5"
        assert len(result["escalation_vectors"]) > 0
        # SSH client should never be called for FTP sessions
        mock_ssh.assert_not_called()

    @patch("modules.privesc._try_ssh_client")
    @patch("modules.privesc.state")
    def test_smb_session_runs_simulated(self, mock_state, mock_ssh):
        mock_state.has_active_session.return_value = True
        mock_state.get_session.return_value = {
            "host": "10.0.0.5",
            "port": 445,
            "username": "",
            "password": "",
            "technique": "smb_enum",
            "session_type": "smb",
        }
        mock_state.get_session_type.return_value = "smb"
        mock_state.target_ip = "10.0.0.5"

        from modules.privesc import run_privesc
        result = run_privesc()

        assert result["simulated"] is True
        assert result["session_type"] == "smb"
        mock_ssh.assert_not_called()

    @patch("modules.privesc.check_writable_configs", return_value=[])
    @patch("modules.privesc.check_cron_jobs", return_value=[])
    @patch("modules.privesc.check_sudo_misconfig", return_value=[])
    @patch("modules.privesc.check_suid_binaries", return_value=[])
    @patch("modules.privesc._try_ssh_client")
    @patch("modules.privesc.state")
    def test_ssh_session_runs_real(self, mock_state, mock_ssh,
                                   mock_suid, mock_sudo, mock_cron, mock_cfg):
        mock_client = MagicMock()
        mock_ssh.return_value = mock_client

        mock_state.has_active_session.return_value = True
        mock_state.get_session.return_value = {
            "host": "10.0.0.5",
            "port": 22,
            "username": "root",
            "password": "toor",
            "technique": "ssh_brute",
            "session_type": "ssh",
        }
        mock_state.get_session_type.return_value = "ssh"
        mock_state.target_ip = "10.0.0.5"

        from modules.privesc import run_privesc
        result = run_privesc()

        assert result["simulated"] is False
        assert result["session_type"] == "ssh"
        assert result["target_ip"] == "10.0.0.5"
        mock_suid.assert_called_once_with(mock_client)
        mock_client.close.assert_called_once()
