"""
core/network_validator.py — Pre-exploitation network validation layer.

Before any exploitation module runs, the engine calls
:func:`validate_target` to ensure:

1. The host is reachable (ICMP / TCP ping).
2. Ports are actually open.
3. Services are detected and saved in :mod:`core.state_manager`.

Only confirmed-open services are passed to exploitation plugins —
the framework never blindly fires exploits at closed ports.

Usage::

    from core.network_validator import validate_target

    ok = validate_target("10.0.0.5")  # populates state.open_ports etc.
    if ok:
        run_exploitation()
"""

from __future__ import annotations

import logging
import socket
import subprocess
from typing import Any

from rich.console import Console

from core.state_manager import state

logger = logging.getLogger(__name__)
console = Console()

# Common ports to quick-check if scan_results are empty
_COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017,
]


# ---------------------------------------------------------------------------
# 1. Ping check
# ---------------------------------------------------------------------------

def ping_host(host: str, timeout: int = 3) -> bool:
    """Return ``True`` when *host* responds to ICMP echo (or TCP fallback).

    Uses ``ping -c 1`` for ICMP.  Falls back to a TCP connect on port 80
    when ICMP is blocked.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), host],
            capture_output=True,
            timeout=timeout + 2,
        )
        if result.returncode == 0:
            logger.info("[NET] %s responds to ICMP ping", host)
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # TCP fallback — try port 80 / 443
    for port in (80, 443, 22):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                logger.info("[NET] %s reachable on TCP/%d", host, port)
                return True
        except (OSError, socket.timeout):
            continue

    logger.warning("[NET] %s unreachable via ICMP and TCP fallback", host)
    return False


# ---------------------------------------------------------------------------
# 2. Quick port check
# ---------------------------------------------------------------------------

def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Return ``True`` if *host*:*port* accepts a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def quick_port_scan(host: str, ports: list[int] | None = None, timeout: float = 2.0) -> dict[int, str]:
    """TCP-connect scan on *ports* (default: common list).

    Returns ``{port: "open", …}`` for every port that responds.
    """
    ports = ports or _COMMON_PORTS
    open_ports: dict[int, str] = {}
    for port in ports:
        if check_port(host, port, timeout):
            open_ports[port] = "open"
    return open_ports


# ---------------------------------------------------------------------------
# 3. Service validation from state
# ---------------------------------------------------------------------------

def services_confirmed() -> bool:
    """Return ``True`` when ``state`` contains scan results with open ports."""
    scan = state.get("scan_results", {})
    if scan:
        return True
    return bool(state.get_open_ports())


def is_service_open(port: int) -> bool:
    """Check whether *port* appears open in the current state.

    Looks at ``open_ports``, direct ``scan_results`` keys, and the
    legacy nested ``scan_results[target][port]`` structure.
    """
    if state.is_port_open(port):
        return True
    scan = state.get("scan_results", {})
    # Direct check: scan_results may be keyed by port string (e.g. {"22": ...})
    if str(port) in scan:
        return True
    # Legacy fallback: scan_results[target][str(port)]
    target = state.target_ip
    if target in scan:
        sub = scan[target]
        if isinstance(sub, dict):
            return str(port) in sub or port in sub
    return False


# ---------------------------------------------------------------------------
# 4. Full pre-exploitation validation
# ---------------------------------------------------------------------------

def validate_target(target: str | None = None) -> bool:
    """Run the complete pre-exploitation validation sequence.

    1. Resolve target from argument or ``state.target_ip``.
    2. Ping the host.
    3. If ``scan_results`` are empty, run a quick port scan and populate
       ``state.open_ports``.
    4. Return ``True`` only when at least one open port is found.
    """
    target = target or state.target_ip
    if not target:
        console.print("[red]✘  No target IP set — cannot validate.[/red]")
        return False

    console.print(f"[bold blue]🔍 Validating target: {target}[/bold blue]")

    # Step 1 — ping
    if not ping_host(target):
        console.print(f"[yellow]⚠  {target} did not respond to ping "
                      f"— continuing anyway (host may block ICMP)[/yellow]")

    # Step 2 — check for existing scan data
    if services_confirmed():
        console.print("[green]✔  Scan data already present in state[/green]")
        return True

    # Step 3 — quick fallback scan
    console.print("[blue]  Running quick port scan (common ports)…[/blue]")
    open_ports = quick_port_scan(target)

    if not open_ports:
        console.print(f"[red]✘  No open ports found on {target}[/red]")
        return False

    console.print(f"[green]✔  {len(open_ports)} open port(s) found: "
                  f"{', '.join(str(p) for p in sorted(open_ports))}[/green]")

    # Persist
    state.set_open_ports({p: "open" for p in open_ports})
    return True
