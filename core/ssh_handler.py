"""
core/ssh_handler.py — Centralised SSH session management.

Replaces the duplicated ``_get_ssh_session()`` pattern found in
``modules/privesc.py``, ``post_exploit/priv_escalation.py``,
``post_exploit/persistence.py``, ``post_exploit/lateral_movement.py``,
and ``post_exploit/credential_harvest.py``.

Features
--------
* Pre-flight check: verifies port 22 (or configured port) is open before
  attempting an SSH connection.
* Retry logic with configurable attempts and back-off.
* Proper Paramiko settings: ``AutoAddPolicy``, timeouts, ``banner_timeout``.
* Uses ``state.get_session()`` — never hardcodes IPs.
* Context-manager support for automatic cleanup.

Usage::

    from core.ssh_handler import get_ssh_client, ssh_exec

    client = get_ssh_client()          # reads creds from state
    if client:
        output = ssh_exec(client, "id")
        client.close()

    # or as a context manager:
    with ssh_session() as client:
        if client:
            print(ssh_exec(client, "whoami"))
"""

from __future__ import annotations

import contextlib
import logging
import socket
import time
from typing import Any, Generator, Optional

import paramiko

from core.state_manager import state

# Silence noisy paramiko transport-thread tracebacks
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration defaults (can be overridden via config.yaml → state)
# ---------------------------------------------------------------------------
_SSH_TIMEOUT: int = 10          # connection timeout (seconds)
_SSH_BANNER_TIMEOUT: int = 15   # banner read timeout
_SSH_RETRIES: int = 3           # max connection attempts
_SSH_BACKOFF: float = 2.0       # seconds multiplied by attempt number


# ---------------------------------------------------------------------------
# 1. Port pre-flight
# ---------------------------------------------------------------------------

def is_port_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    """Return ``True`` if *host*:*port* accepts a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


# ---------------------------------------------------------------------------
# 2. Core SSH client factory
# ---------------------------------------------------------------------------

def get_ssh_client(
    *,
    host: str | None = None,
    port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    retries: int = _SSH_RETRIES,
    timeout: int = _SSH_TIMEOUT,
    banner_timeout: int = _SSH_BANNER_TIMEOUT,
) -> Optional[paramiko.SSHClient]:
    """Open an SSH connection with retries and pre-flight port check.

    When *host*/*username*/*password* are ``None`` the function reads
    them from ``state.get_session()``.  Returns ``None`` when the
    connection cannot be established.
    """
    # --- resolve credentials ---
    if host is None or username is None:
        session = state.get_session()
        if not session:
            logger.warning("[SSH] No session in state — cannot connect")
            return None
        host = host or session.get("host", "")
        # Only use the session port for SSH if the session was established
        # via an SSH-based technique.  Non-SSH sessions (e.g. FTP on port 21)
        # must not override the SSH default of 22.
        session_technique = session.get("technique", "")
        session_port = int(session.get("port", 22))
        if port is None:
            port = session_port if session_technique.startswith("ssh") else 22
        username = username or session.get("username", "")
        password = password if password is not None else session.get("password", "")

    if not host or not username:
        logger.warning("[SSH] Missing host (%s) or username (%s)", host, username)
        return None

    port = port or 22

    # --- pre-flight: is the port open? ---
    if not is_port_reachable(host, port, timeout=3.0):
        logger.warning("[SSH] Port %d not reachable on %s — aborting", port, host)
        return None

    # --- connect with retries ---
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                banner_timeout=banner_timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            logger.info("[SSH] Connected to %s@%s:%d (attempt %d)",
                        username, host, port, attempt)
            return client

        except paramiko.AuthenticationException:
            logger.error("[SSH] Authentication failed for %s@%s:%d",
                         username, host, port)
            return None  # no point retrying — wrong creds

        except (
            paramiko.SSHException,
            socket.timeout,
            socket.error,
            EOFError,
            OSError,
        ) as exc:
            last_exc = exc
            wait = _SSH_BACKOFF * attempt
            logger.warning(
                "[SSH] Attempt %d/%d failed (%s) — retrying in %.1fs",
                attempt, retries, exc, wait,
            )
            time.sleep(wait)

    logger.error("[SSH] All %d attempts failed for %s:%d: %s",
                 retries, host, port, last_exc)
    return None


# ---------------------------------------------------------------------------
# 3. Remote command execution
# ---------------------------------------------------------------------------

def ssh_exec(
    client: paramiko.SSHClient,
    cmd: str,
    timeout: int = 30,
) -> str:
    """Run *cmd* on the remote host and return stdout as a string."""
    try:
        _in, out, _err = client.exec_command(cmd, timeout=timeout)
        return out.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("[SSH] exec_command(%s) failed: %s", cmd, exc)
        return ""


# ---------------------------------------------------------------------------
# 4. Context-manager wrapper
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def ssh_session(**kwargs: Any) -> Generator[Optional[paramiko.SSHClient], None, None]:
    """Context manager that yields a connected SSH client or ``None``.

    Usage::

        with ssh_session() as client:
            if client:
                print(ssh_exec(client, "id"))
    """
    client = get_ssh_client(**kwargs)
    try:
        yield client
    finally:
        if client:
            try:
                client.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# 5. Quick credential-test helper
# ---------------------------------------------------------------------------

def test_ssh_creds(
    host: str,
    port: int,
    username: str,
    password: str,
    timeout: int = 8,
) -> bool:
    """Return ``True`` when *username*:*password* opens an SSH session.

    Used by brute-force modules to test a single credential pair.
    """
    client = get_ssh_client(
        host=host,
        port=port,
        username=username,
        password=password,
        retries=1,
        timeout=timeout,
        banner_timeout=timeout,
    )
    if client:
        client.close()
        return True
    return False
