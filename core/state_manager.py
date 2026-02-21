"""
core/state_manager.py — Centralised pipeline state for every module.

All phases read/write through the singleton ``state`` object so no
local variables or hardcoded IPs leak between modules.

Key fields
----------
target            — str   : IP / domain / CIDR under test
open_ports        — dict  : {port_int: service_name, …}
discovered_services — dict: {port_int: {name, version, banner, …}, …}
valid_credentials — list  : [{username, password, source, service}, …]
active_session    — dict | None : {host, port, username, password, technique}
scan_results      — dict  : legacy nested structure for reporting
recon             — dict  : DNS / WHOIS / subdomain data
ai_decisions      — list  : ranked exploitation plans from the LLM
exploit_results   — list  : per-technique outcome records
privesc_results   — dict  : SUID / sudo / cron / config findings
credentials       — list  : credentials harvested post-exploit
persistence_simulated — list: simulated persistence techniques
session_info      — dict  : **alias** → kept for backward compat with
                             modules that read ``state.get("session_info")``
"""

import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_STATE: dict[str, Any] = {
    # ---- Target ----
    "target": None,

    # ---- Recon / Scanning ----
    "recon": {},
    "scan_results": {},
    "open_ports": {},
    "discovered_services": {},

    # ---- Exploitation ----
    "ai_decisions": [],
    "exploit_results": [],

    # ---- Credentials & Sessions ----
    "valid_credentials": [],
    "active_session": None,
    "session_info": {},          # backward-compat alias

    # ---- Post-Exploit ----
    "privesc_results": {},
    "credentials": [],
    "persistence_simulated": [],
}


class StateManager:
    """Thread-safe JSON state store shared by every pipeline module.

    Usage::

        from core.state_manager import state
        state.set("target", "10.0.0.5")
        target = state.get("target")
    """

    def __init__(self, path: str = "db/state.json") -> None:
        self._path: Path = Path(path)
        self._lock: threading.Lock = threading.Lock()
        self._state: dict[str, Any] = {}
        self._load()

    # ── persistence ─────────────────────────────────────────────────

    def _load(self) -> None:
        """Load state from disk, or create file with defaults if missing."""
        with self._lock:
            try:
                with open(self._path, "r") as f:
                    self._state = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._state = json.loads(json.dumps(DEFAULT_STATE))
                self._write()

    def _write(self) -> None:
        """Write current state to disk (caller must hold the lock)."""
        with open(self._path, "w") as f:
            json.dump(self._state, f, indent=2)

    # ── basic CRUD ──────────────────────────────────────────────────

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        """Return the value for *key*, or *default* if the key is absent."""
        with self._lock:
            return self._state.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set *key* to *value* and immediately persist to disk."""
        with self._lock:
            self._state[key] = value
            self._write()

    def append(self, key: str, item: Any) -> None:
        """Append *item* to the list at *key*, creating the list if needed."""
        with self._lock:
            if key not in self._state or not isinstance(self._state[key], list):
                self._state[key] = []
            self._state[key].append(item)
            self._write()

    def save(self) -> None:
        """Persist the current in-memory state to disk."""
        with self._lock:
            self._write()

    def reset(self) -> None:
        """Restore defaults and save."""
        with self._lock:
            self._state = json.loads(json.dumps(DEFAULT_STATE))
            self._write()

    # ── target helpers ──────────────────────────────────────────────

    @property
    def target_ip(self) -> str:
        """Return the current target (never ``None``; defaults to ``""``).

        All modules should use ``state.target_ip`` instead of
        hardcoding ``127.0.0.1`` or ``localhost``.
        """
        return self.get("target", "") or ""

    @target_ip.setter
    def target_ip(self, value: str) -> None:
        self.set("target", value)

    # ── session helpers ─────────────────────────────────────────────

    # Maps exploit technique names to canonical session types.
    _SESSION_TYPE_MAP: dict[str, str] = {
        "ssh_brute": "ssh",
        "ssh_brute_force": "ssh",
        "ftp_anon": "ftp",
        "ftp_anonymous": "ftp",
        "smb_enum": "smb",
        "smb_null_session": "smb",
        "http_default_creds": "web_shell",
        "http_creds": "web_shell",
        "cve_check": "exploit",
    }

    @staticmethod
    def _resolve_session_type(technique: str) -> str:
        """Derive a canonical session_type from the exploit *technique*."""
        return StateManager._SESSION_TYPE_MAP.get(technique, technique or "unknown")

    def set_session(
        self,
        host: str,
        port: int,
        username: str,
        password: str,
        technique: str,
    ) -> None:
        """Store a successfully opened session.

        Populates both ``active_session`` (new) and ``session_info``
        (legacy) so every module sees it regardless of which key they read.
        The ``session_type`` field is auto-derived from *technique*.
        """
        session_type = self._resolve_session_type(technique)
        info = {
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "technique": technique,
            "session_type": session_type,
            "target_ip": host,
            "is_active": True,
        }
        with self._lock:
            self._state["active_session"] = info
            self._state["session_info"] = info
            self._write()
        logger.info("[STATE] Session stored: %s@%s:%s via %s (type=%s)",
                    username, host, port, technique, session_type)

    def get_session(self) -> Optional[dict[str, Any]]:
        """Return the active session dict, or ``None``.

        If the session was stored by older code that omitted
        ``session_type`` / ``target_ip`` / ``is_active``, those fields
        are **injected** before the dict is returned so that every
        consumer always sees a complete session object.
        """
        s = self.get("active_session") or self.get("session_info") or None
        if s is None:
            return None
        # Enrich legacy sessions with missing fields
        changed = False
        if "session_type" not in s or not s["session_type"]:
            s["session_type"] = self._resolve_session_type(s.get("technique", ""))
            changed = True
        if "target_ip" not in s:
            s["target_ip"] = s.get("host", self.target_ip)
            changed = True
        if "is_active" not in s:
            s["is_active"] = True
            changed = True
        if changed:
            # Persist the enriched session so it is correct on next load
            with self._lock:
                self._state["active_session"] = s
                self._state["session_info"] = s
                self._write()
        return s

    def has_session(self) -> bool:
        """True when a usable session exists."""
        s = self.get_session()
        return bool(s and s.get("host"))

    # Alias requested by the user — identical semantics.
    has_active_session = has_session

    def get_session_type(self) -> str:
        """Return the canonical session type (``ssh``, ``ftp``, ``smb``, …).

        Returns ``""`` when there is no active session.
        """
        s = self.get_session()
        if not s:
            return ""
        # Prefer explicit field; fall back to technique-based derivation.
        return s.get("session_type") or self._resolve_session_type(
            s.get("technique", "")
        )

    # ── credential helpers ──────────────────────────────────────────

    def add_credential(
        self,
        username: str,
        password: str,
        service: str = "",
        source: str = "",
    ) -> None:
        """Append a credential to ``valid_credentials``."""
        cred = {
            "username": username,
            "password": password,
            "service": service,
            "source": source,
        }
        self.append("valid_credentials", cred)
        logger.info("[STATE] Credential added: %s (service=%s, source=%s)",
                    username, service, source)

    def get_credentials(self) -> list[dict[str, Any]]:
        """Return all discovered credentials."""
        return self.get("valid_credentials", [])

    # ── port / service helpers ──────────────────────────────────────

    def set_open_ports(self, ports: dict[int, str]) -> None:
        """Store ``{port: service_name, …}``."""
        self.set("open_ports", ports)

    def get_open_ports(self) -> dict[int, str]:
        return self.get("open_ports", {})

    def is_port_open(self, port: int) -> bool:
        ports = self.get_open_ports()
        return port in ports or str(port) in ports

    def set_services(self, services: dict[int, dict[str, Any]]) -> None:
        """Store ``{port: {name, version, banner, …}, …}``."""
        self.set("discovered_services", services)

    def get_services(self) -> dict[int, dict[str, Any]]:
        return self.get("discovered_services", {})

    # ── snapshot ────────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        """Return a deep copy of the full internal state (for reporting)."""
        with self._lock:
            return json.loads(json.dumps(self._state))


# Module-level singleton
state: StateManager = StateManager()
