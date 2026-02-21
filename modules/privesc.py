"""
modules/privesc.py — Privilege-escalation checks for the AI Red Team Framework.

MITRE ATT&CK:
  T1548.001  Abuse Elevation Control: Setuid / Setgid
  T1574.009  Hijack Execution Flow
  T1053.003  Scheduled Task/Job: Cron
  T1547.001  Boot or Logon Autostart Execution: Registry Run Keys

Session-type agnostic:  Runs real enumeration over SSH when an SSH
session is available, and falls back to **simulated** privilege-
escalation checks for non-interactive sessions (FTP, SMB, web shell).
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Optional

import paramiko
from rich.console import Console
from rich.panel import Panel
from rich.table import Table as RichTable

from core.ssh_handler import get_ssh_client, ssh_exec
from core.state_manager import state

# Silence noisy paramiko transport-thread tracebacks (SSH banner errors, etc.)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)
logger = logging.getLogger(__name__)

console = Console()

# Session types that support interactive command execution over SSH
_SSH_SESSION_TYPES: set[str] = {"ssh"}

# GTFOBins-exploitable SUID binaries
GTFOBINS_LIST: list[str] = [
    "python", "perl", "bash", "sh", "find", "nmap", "vim", "more",
    "less", "awk", "man", "cp", "mv", "python3", "ruby", "lua",
    "wget", "curl",
]


# ---------------------------------------------------------------------------
# 1. Session helpers — generic (not SSH-only)
# ---------------------------------------------------------------------------

def _get_active_session() -> Optional[dict[str, Any]]:
    """Return the current active session dict, or ``None``.

    Works for **any** session type — SSH, FTP, SMB, web shell, etc.
    """
    if not state.has_active_session():
        return None
    return state.get_session()


def _try_ssh_client(session: dict[str, Any]) -> Optional[paramiko.SSHClient]:
    """Attempt to open an SSH connection for an SSH-type session.

    Returns ``None`` for non-SSH sessions or when the connection fails.
    """
    session_type = state.get_session_type()
    if session_type not in _SSH_SESSION_TYPES:
        return None

    client = get_ssh_client()  # reads creds from state, retries, checks port
    if client is None:
        logger.warning("[PRIVESC] SSH connection failed for session %s@%s:%s",
                       session.get("username"), session.get("host"),
                       session.get("port"))
    return client


# ---------------------------------------------------------------------------
# 2. Execute Remote Command
# ---------------------------------------------------------------------------

def exec_command(client: paramiko.SSHClient, cmd: str) -> str:
    """Run *cmd* on the remote host and return its stdout as a string."""
    return ssh_exec(client, cmd, timeout=30)


# ---------------------------------------------------------------------------
# 3. SUID Binary Check
# ---------------------------------------------------------------------------

def check_suid_binaries(client: paramiko.SSHClient) -> list[dict[str, Any]]:
    """Find SUID binaries and flag those that appear in the GTFOBins list."""
    output: str = exec_command(client, "find / -perm -4000 -type f 2>/dev/null")
    results: list[dict[str, Any]] = []

    for line in output.strip().splitlines():
        path: str = line.strip()
        if not path:
            continue

        binary_name: str = path.rsplit("/", 1)[-1].lower()
        is_exploitable: bool = any(g in binary_name for g in GTFOBINS_LIST)
        technique: str = ""
        if is_exploitable:
            technique = f"GTFOBins exploit via {binary_name}"

        results.append(
            {
                "path": path,
                "is_exploitable": is_exploitable,
                "gtfobins_technique": technique,
            }
        )

    return results


# ---------------------------------------------------------------------------
# 4. Sudo Misconfiguration Check
# ---------------------------------------------------------------------------

def check_sudo_misconfig(client: paramiko.SSHClient) -> list[dict[str, Any]]:
    """Parse ``sudo -l`` output for NOPASSWD and (ALL) entries."""
    output: str = exec_command(client, "sudo -l 2>/dev/null")
    results: list[dict[str, Any]] = []

    for line in output.strip().splitlines():
        stripped: str = line.strip()
        if not stripped:
            continue

        nopasswd: bool = "NOPASSWD" in stripped.upper()
        all_users: bool = "(ALL)" in stripped.upper() or "(ALL : ALL)" in stripped.upper()

        if nopasswd or all_users:
            results.append(
                {
                    "command": stripped,
                    "nopasswd": nopasswd,
                    "all_users": all_users,
                }
            )

    return results


# ---------------------------------------------------------------------------
# 5. Cron Job Check
# ---------------------------------------------------------------------------

def check_cron_jobs(client: paramiko.SSHClient) -> list[dict[str, Any]]:
    """Enumerate cron entries and flag world-writable scripts."""
    crontab_output: str = exec_command(client, "cat /etc/crontab 2>/dev/null")
    cron_d_output: str = exec_command(client, "ls -la /etc/cron.d/ 2>/dev/null")
    spool_output: str = exec_command(client, "find /var/spool/cron -type f 2>/dev/null")

    results: list[dict[str, Any]] = []

    # Parse /etc/crontab for script paths
    for line in crontab_output.strip().splitlines():
        stripped: str = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        parts: list[str] = stripped.split()
        if len(parts) >= 7:
            script_path: str = parts[6]
        elif len(parts) >= 6:
            script_path = parts[5]
        else:
            continue

        # Check writability
        writable_check: str = exec_command(
            client, f"test -w {script_path} && echo WRITABLE"
        ).strip()
        is_writable: bool = writable_check == "WRITABLE"

        results.append(
            {
                "cron_entry": stripped,
                "script_path": script_path,
                "is_writable": is_writable,
            }
        )

    # Enumerate /etc/cron.d entries
    for line in cron_d_output.strip().splitlines():
        stripped = line.strip()
        if stripped.startswith("total") or not stripped:
            continue
        results.append(
            {
                "cron_entry": f"/etc/cron.d — {stripped}",
                "script_path": "",
                "is_writable": False,
            }
        )

    # Spool files
    for line in spool_output.strip().splitlines():
        path = line.strip()
        if path:
            results.append(
                {
                    "cron_entry": f"spool: {path}",
                    "script_path": path,
                    "is_writable": False,
                }
            )

    return results


# ---------------------------------------------------------------------------
# 6. Writable Config Files Check
# ---------------------------------------------------------------------------

def check_writable_configs(client: paramiko.SSHClient) -> list[dict[str, Any]]:
    """Find world-writable files under /etc and inspect critical paths."""
    writable_output: str = exec_command(client, "find /etc -writable -type f 2>/dev/null")
    critical_output: str = exec_command(
        client, "ls -la /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null"
    )

    results: list[dict[str, Any]] = []

    for line in writable_output.strip().splitlines():
        path: str = line.strip()
        if path:
            results.append({"path": path, "permissions": "writable"})

    for line in critical_output.strip().splitlines():
        stripped: str = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) >= 9:
            results.append({"path": parts[-1], "permissions": parts[0]})

    return results


# ---------------------------------------------------------------------------
# 7. Simulated Privesc for Non-SSH Sessions
# ---------------------------------------------------------------------------

_SIMULATED_PRIVESC: dict[str, list[dict[str, Any]]] = {
    "ftp": [
        {
            "vector": "FTP directory traversal",
            "mitre_id": "T1083",
            "description": "Anonymous FTP access may expose sensitive files "
                           "(e.g. /etc/passwd, backup archives) that contain "
                           "credentials usable for privilege escalation.",
            "likelihood": "MEDIUM",
        },
        {
            "vector": "Writable FTP upload directory",
            "mitre_id": "T1105",
            "description": "If the FTP root is web-accessible and writable, an "
                           "attacker can upload a web shell to gain interactive "
                           "command execution.",
            "likelihood": "HIGH",
        },
    ],
    "smb": [
        {
            "vector": "SMB share credential harvesting",
            "mitre_id": "T1552.001",
            "description": "Readable SMB shares may contain configuration "
                           "files, scripts, or database backups with embedded "
                           "credentials.",
            "likelihood": "MEDIUM",
        },
        {
            "vector": "SMB relay / NTLM relay",
            "mitre_id": "T1557.001",
            "description": "Null or guest SMB sessions can be leveraged for "
                           "NTLM relay attacks to escalate privileges on "
                           "domain-joined hosts.",
            "likelihood": "HIGH",
        },
    ],
    "web_shell": [
        {
            "vector": "Web application command injection",
            "mitre_id": "T1059.004",
            "description": "Authenticated web panels often expose command "
                           "injection or file-upload vectors that yield a "
                           "reverse shell.",
            "likelihood": "HIGH",
        },
        {
            "vector": "Web-to-SSH pivot via leaked credentials",
            "mitre_id": "T1552.001",
            "description": "Admin dashboards frequently store or display "
                           "database credentials that can be reused for SSH.",
            "likelihood": "MEDIUM",
        },
    ],
}


def _simulated_privesc(session: dict[str, Any]) -> dict[str, Any]:
    """Return simulated privilege-escalation findings for non-SSH sessions.

    The simulations are parameterised by *session_type* so FTP, SMB,
    and web-shell sessions each produce contextually relevant vectors.
    """
    session_type: str = session.get("session_type", "unknown")
    target_ip: str = session.get("host", state.target_ip)
    technique: str = session.get("technique", "unknown")

    vectors = _SIMULATED_PRIVESC.get(session_type, [
        {
            "vector": "Generic session-based escalation",
            "mitre_id": "T1078",
            "description": f"A {session_type} session was established.  Manual "
                           "analysis is required to determine escalation paths.",
            "likelihood": "LOW",
        },
    ])

    logger.info(
        "[PRIVESC] Simulated privesc — session_type=%s  target_ip=%s  "
        "technique=%s  vectors=%d",
        session_type, target_ip, technique, len(vectors),
    )

    return {
        "session_type": session_type,
        "target_ip": target_ip,
        "technique": technique,
        "simulated": True,
        "message": (
            f"Privilege escalation simulated for {session_type} session "
            f"({technique}) on {target_ip}.  Real enumeration requires an "
            f"interactive shell."
        ),
        "escalation_vectors": vectors,
        "suid_binaries": [],
        "sudo_misconfig": [],
        "cron_jobs": [],
        "writable_configs": [],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# 8. Run Full Privilege-Escalation Phase
# ---------------------------------------------------------------------------

def run_privesc() -> dict[str, Any]:
    """Execute privilege-escalation checks using whatever active session exists.

    Session dispatch logic:
      • **SSH session** → real remote enumeration (SUID, sudo, cron, …)
      • **FTP / SMB / web_shell / other** → simulated escalation vectors
      • **No session at all** → log + skip

    Logs ``session_type``, ``target_ip``, and escalation result regardless
    of which path is taken.
    """
    console.rule("[bold cyan]Phase 5 — Privilege Escalation[/bold cyan]")

    # Clear stale privesc results from any prior run
    state.set("privesc_results", {})

    # ── 1. Check for *any* active session ──────────────────────────
    session = _get_active_session()

    if session is None:
        console.print(
            "[yellow]⚠  No active session available — skipping privilege escalation.[/yellow]"
        )
        logger.warning("[PRIVESC] No active session available — skipping")
        empty: dict[str, Any] = {
            "message": "No active session available. Privilege escalation skipped.",
            "session_type": None,
            "target_ip": state.target_ip,
            "suid_binaries": [],
            "sudo_misconfig": [],
            "cron_jobs": [],
            "writable_configs": [],
        }
        state.set("privesc_results", empty)
        return empty

    session_type: str = state.get_session_type()
    target_ip: str = session.get("host", state.target_ip)
    technique: str = session.get("technique", "unknown")

    console.print(
        f"[cyan]  Session: [bold]{session_type}[/bold]  "
        f"target_ip={target_ip}  technique={technique}[/cyan]"
    )
    logger.info(
        "[PRIVESC] Starting — session_type=%s  target_ip=%s  technique=%s",
        session_type, target_ip, technique,
    )

    # ── 2. Dispatch based on session type ──────────────────────────
    if session_type in _SSH_SESSION_TYPES:
        client: Optional[paramiko.SSHClient] = _try_ssh_client(session)
        if client is None:
            console.print(
                "[yellow]⚠  SSH connection failed — falling back to "
                "simulated escalation.[/yellow]"
            )
            results = _simulated_privesc(session)
            state.set("privesc_results", results)
            _log_result(results)
            return results

        # ── Real SSH-based enumeration ─────────────────────────────
        try:
            suid: list[dict[str, Any]] = check_suid_binaries(client)
            sudo: list[dict[str, Any]] = check_sudo_misconfig(client)
            cron: list[dict[str, Any]] = check_cron_jobs(client)
            configs: list[dict[str, Any]] = check_writable_configs(client)
        finally:
            client.close()

        results = {
            "session_type": session_type,
            "target_ip": target_ip,
            "technique": technique,
            "simulated": False,
            "suid_binaries": suid,
            "sudo_misconfig": sudo,
            "cron_jobs": cron,
            "writable_configs": configs,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    else:
        # Non-SSH session — simulated escalation
        console.print(
            Panel(
                f"[bold bright_yellow]⚠  SIMULATED PRIVILEGE ESCALATION ⚠[/bold bright_yellow]\n"
                f"[yellow]Session type '{session_type}' does not support interactive "
                f"shell access.\nEscalation vectors are inferred, not executed.[/yellow]",
                title="[bold white]Simulated PrivEsc[/bold white]",
                border_style="bright_yellow",
            )
        )
        results = _simulated_privesc(session)

    # ── 3. Summary output + persist ────────────────────────────────
    _print_summary(results)
    state.set("privesc_results", results)
    _log_result(results)
    console.print("[green]✔  Privilege escalation results saved.[/green]")
    return results


# ---------------------------------------------------------------------------
# 9. Output helpers
# ---------------------------------------------------------------------------

def _log_result(results: dict[str, Any]) -> None:
    """Log session_type, target_ip, and escalation outcome."""
    s_type = results.get("session_type", "unknown")
    t_ip = results.get("target_ip", "unknown")
    simulated = results.get("simulated", True)
    label = "simulated" if simulated else "real"

    n_suid = len(results.get("suid_binaries", []))
    n_sudo = len(results.get("sudo_misconfig", []))
    n_cron = len(results.get("cron_jobs", []))
    n_cfg = len(results.get("writable_configs", []))
    n_vec = len(results.get("escalation_vectors", []))

    logger.info(
        "[PRIVESC] Result (%s) — session_type=%s  target_ip=%s  "
        "suid=%d  sudo=%d  cron=%d  configs=%d  vectors=%d",
        label, s_type, t_ip, n_suid, n_sudo, n_cron, n_cfg, n_vec,
    )


def _print_summary(results: dict[str, Any]) -> None:
    """Display a rich summary panel and risk table."""
    suid = results.get("suid_binaries", [])
    sudo = results.get("sudo_misconfig", [])
    cron = results.get("cron_jobs", [])
    configs = results.get("writable_configs", [])
    vectors = results.get("escalation_vectors", [])
    is_simulated = results.get("simulated", False)

    exploitable_suid: int = sum(1 for s in suid if s.get("is_exploitable"))

    lines: list[str] = [
        f"[bold]Session type:[/bold]        {results.get('session_type', 'N/A')}",
        f"[bold]Target IP:[/bold]           {results.get('target_ip', 'N/A')}",
    ]
    if is_simulated and vectors:
        lines.append(f"[bold]Escalation vectors:[/bold]  {len(vectors)}")
    else:
        lines.extend([
            f"[bold]SUID binaries:[/bold]      {len(suid)}  "
            f"([red]{exploitable_suid} exploitable[/red])",
            f"[bold]Sudo misconfigs:[/bold]    {len(sudo)}",
            f"[bold]Cron jobs:[/bold]          {len(cron)}",
            f"[bold]Writable configs:[/bold]   {len(configs)}",
        ])

    console.print(
        Panel(
            "\n".join(lines),
            title="[bold white]Privilege Escalation Findings[/bold white]",
            border_style="cyan",
        )
    )

    # ── Risk table ──
    table = RichTable(title="PrivEsc Summary", show_lines=True)

    if is_simulated and vectors:
        table.add_column("Vector", style="cyan")
        table.add_column("MITRE ID", style="magenta")
        table.add_column("Likelihood", justify="center")
        table.add_column("Description", style="dim")
        for v in vectors:
            lh = v.get("likelihood", "?")
            colour = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(lh, "white")
            table.add_row(
                v.get("vector", ""),
                v.get("mitre_id", ""),
                f"[{colour}]{lh}[/{colour}]",
                v.get("description", "")[:80],
            )
    else:
        table.add_column("Finding Type", style="cyan")
        table.add_column("Count", style="white", justify="right")
        table.add_column("Risk Level", justify="center")

        def _risk(count: int, exploitable: int = 0) -> str:
            if exploitable > 0:
                return "[bold red]CRITICAL[/bold red]"
            if count > 5:
                return "[red]HIGH[/red]"
            if count > 0:
                return "[yellow]MEDIUM[/yellow]"
            return "[green]LOW[/green]"

        table.add_row("SUID Binaries", str(len(suid)), _risk(len(suid), exploitable_suid))
        table.add_row("Sudo Misconfigs", str(len(sudo)), _risk(len(sudo)))
        table.add_row("Cron Jobs", str(len(cron)), _risk(len(cron)))
        table.add_row("Writable Configs", str(len(configs)), _risk(len(configs)))

    console.print(table)


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> dict[str, Any]:
    """Entry-point called by the pipeline orchestrator."""
    return run_privesc()


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_privesc()
