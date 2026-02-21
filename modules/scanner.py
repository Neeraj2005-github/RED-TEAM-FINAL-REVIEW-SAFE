"""
modules/scanner.py — Network scanning phase for the AI Red Team Framework.

MITRE ATT&CK:
  T1046  Network Service Discovery
  T1082  System Information Discovery
  T1016  System Network Configuration Discovery

Performs masscan port discovery, nmap service/version detection, and
NVD CVE lookups for each discovered service.
"""

import json
import os
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

import nmap
import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table as RichTable

from config.settings import SCAN_TIMEOUT, get_config
from core.state_manager import state

console = Console()

# Default ports to fall back on when masscan is unavailable
DEFAULT_PORTS: list[int] = [21, 22, 23, 25, 80, 443, 445, 3306, 8080, 8443]


def _scan_settings() -> dict[str, Any]:
    """Read scanning section from config (fall back to safe defaults)."""
    try:
        cfg = get_config()
        s = cfg.to_dict().get("scanning", {})
    except Exception:
        s = {}
    return {
        "port_range": s.get("port_range", "1-1024"),
        "scan_type": s.get("scan_type", "SYN"),
        "rate_limit": int(s.get("rate_limit", 1000)),
        "service_detection": bool(s.get("service_detection", True)),
        "os_detection": bool(s.get("os_detection", True)),
    }


def _nmap_quick_discovery(target: str) -> list[int]:
    """Run a quick nmap TCP-connect scan as a non-root fallback."""
    settings = _scan_settings()
    port_range = settings["port_range"]
    xml_path: str = "/tmp/nmap_quick.xml"
    try:
        subprocess.run(
            ["nmap", "-sT", "-p", port_range, "--open", "-T5", "-oX", xml_path, target],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports: set[int] = set()
        for port_elem in root.findall(".//port"):
            state_elem = port_elem.find("state")
            if state_elem is not None and state_elem.get("state") == "open":
                port_id = port_elem.get("portid")
                if port_id is not None:
                    ports.add(int(port_id))
        if ports:
            return sorted(ports)
    except Exception as exc:
        console.print(f"[yellow]⚠  nmap quick scan failed: {exc}[/yellow]")
    return []


# ---------------------------------------------------------------------------
# 1. Masscan Discovery
# ---------------------------------------------------------------------------

def masscan_discovery(target: str) -> list[int]:
    """Run masscan against *target* to discover all open TCP ports.

    Requires root.  Falls back to nmap TCP-connect scan when not running
    as root, and to a sensible default list if both tools fail.
    """
    # masscan needs raw sockets → root required
    if os.geteuid() != 0:
        console.print(
            "[yellow]⚠  masscan requires root — using nmap alternative.[/yellow]"
        )
        ports = _nmap_quick_discovery(target)
        return ports if ports else DEFAULT_PORTS

    xml_path: str = "/tmp/masscan_out.xml"

    try:
        subprocess.run(
            [
                "masscan",
                target,
                "-p0-65535",
                "--rate=1000",
                "-oX",
                xml_path,
            ],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT,
        )

        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports: set[int] = set()
        for host in root.findall(".//host"):
            for port_elem in host.findall(".//port"):
                port_id = port_elem.get("portid")
                if port_id is not None:
                    ports.add(int(port_id))

        if ports:
            return sorted(ports)

        console.print("[yellow]⚠  masscan found 0 open ports — trying nmap.[/yellow]")
        nmap_ports = _nmap_quick_discovery(target)
        return nmap_ports if nmap_ports else DEFAULT_PORTS

    except FileNotFoundError:
        console.print("[yellow]⚠  masscan not found — trying nmap.[/yellow]")
        nmap_ports = _nmap_quick_discovery(target)
        return nmap_ports if nmap_ports else DEFAULT_PORTS
    except subprocess.TimeoutExpired:
        console.print("[yellow]⚠  masscan timed out — using default port list.[/yellow]")
        return DEFAULT_PORTS
    except Exception as exc:
        console.print(f"[yellow]⚠  masscan error: {exc} — using default port list.[/yellow]")
        return DEFAULT_PORTS


# ---------------------------------------------------------------------------
# 2. Nmap Scan
# ---------------------------------------------------------------------------

def nmap_scan(target: str, ports: list[int]) -> dict[int, dict[str, Any]]:
    """Run an nmap service/version scan on the given *ports*.

    Returns a dict keyed by port number with service details, OS guess,
    and banner for every open port discovered.
    """
    ports_str: str = ",".join(str(p) for p in ports)
    nm = nmap.PortScanner()

    settings = _scan_settings()
    nmap_args = "-T5 --script=banner"
    if settings["service_detection"]:
        nmap_args += " -sV"
    # -O (OS detection) requires root — skip it for non-root users
    # otherwise nmap quits entirely and returns no results at all
    if settings["os_detection"] and os.geteuid() == 0:
        nmap_args += " -O"
    # Non-root: explicitly request TCP connect scan (avoid SYN scan issues)
    if os.geteuid() != 0:
        nmap_args += " -sT"

    try:
        nm.scan(
            hosts=target,
            ports=ports_str,
            arguments=nmap_args,
        )
    except nmap.PortScannerError as exc:
        console.print(f"[red]✘  nmap scan error: {exc}[/red]")
        return {}
    except Exception as exc:
        console.print(f"[red]✘  nmap unexpected error: {exc}[/red]")
        return {}

    results: dict[int, dict[str, Any]] = {}

    for host in nm.all_hosts():
        # Best-effort OS guess
        os_guess: str = ""
        if "osmatch" in nm[host] and nm[host]["osmatch"]:
            os_guess = nm[host]["osmatch"][0].get("name", "")

        for proto in nm[host].all_protocols():
            port_list: list[int] = sorted(nm[host][proto].keys())
            for port in port_list:
                info: dict[str, Any] = nm[host][proto][port]
                if info.get("state") != "open":
                    continue

                banner: str = ""
                if "script" in info and "banner" in info["script"]:
                    banner = info["script"]["banner"]

                results[port] = {
                    "state": info.get("state", ""),
                    "service": info.get("name", ""),
                    "version": info.get("version", ""),
                    "os_guess": os_guess,
                    "banner": banner,
                }

    return results


# ---------------------------------------------------------------------------
# 3. NVD CVE Lookup
# ---------------------------------------------------------------------------

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def nvd_cve_lookup(service: str, version: str) -> list[dict[str, Any]]:
    """Query the NVD REST API for CVEs matching *service* and *version*.

    Returns up to 5 results, each with cve_id, description, and
    cvss_score.  Includes a 1-second sleep to respect rate limits.
    """
    if not service:
        return []

    time.sleep(1)

    keyword: str = f"{service} {version}".strip()
    params: dict[str, Any] = {
        "keywordSearch": keyword,
        "resultsPerPage": 5,
    }

    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()
    except (requests.RequestException, ValueError) as exc:
        console.print(f"[dim]  NVD lookup failed for {keyword}: {exc}[/dim]")
        return []

    cves: list[dict[str, Any]] = []
    for vuln in data.get("vulnerabilities", []):
        cve_item: dict[str, Any] = vuln.get("cve", {})
        cve_id: str = cve_item.get("id", "")

        # Description
        descriptions = cve_item.get("descriptions", [])
        description: str = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # CVSS score — try v3.1 first, then v3.0, then v2
        cvss_score: float = 0.0
        metrics: dict[str, Any] = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                break

        cves.append(
            {
                "cve_id": cve_id,
                "description": description[:300],
                "cvss_score": cvss_score,
            }
        )

    return cves


# ---------------------------------------------------------------------------
# 4. Run full scanner phase
# ---------------------------------------------------------------------------

def run_scanner(target: str) -> dict[str, Any]:
    """Execute the complete scanning pipeline with rich progress output.

    Steps:
      1. masscan port discovery
      2. nmap service / version detection
      3. NVD CVE lookups for every identified service

    Results are saved to state and to ``db/scan_results.json``.
    """
    console.rule("[bold cyan]Phase 2 — Scanning[/bold cyan]")
    console.print(f"[cyan]  Target: {target}[/cyan]")

    final_results: dict[str, Any] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        console=console,
    ) as progress:

        # Step 1 — masscan
        task_mass = progress.add_task("Running masscan discovery…", total=1)
        open_ports: list[int] = masscan_discovery(target)
        progress.update(task_mass, advance=1, description="[green]✔ masscan discovery[/green]")

        # Step 2 — nmap
        task_nmap = progress.add_task("Running nmap service scan…", total=1)
        nmap_results: dict[int, dict[str, Any]] = nmap_scan(target, open_ports)
        progress.update(task_nmap, advance=1, description="[green]✔ nmap service scan[/green]")

        # Step 3 — CVE lookups
        services_to_check: list[tuple[int, str, str]] = []
        for port, info in nmap_results.items():
            svc = info.get("service", "")
            ver = info.get("version", "")
            if svc:
                services_to_check.append((port, svc, ver))

        task_cve = progress.add_task(
            "Querying NVD for CVEs…",
            total=max(len(services_to_check), 1),
        )

        for port, svc, ver in services_to_check:
            cves: list[dict[str, Any]] = nvd_cve_lookup(svc, ver)
            entry = nmap_results[port]
            final_results[str(port)] = {
                "service": entry.get("service", ""),
                "version": entry.get("version", ""),
                "banner": entry.get("banner", ""),
                "os_guess": entry.get("os_guess", ""),
                "cves": cves,
            }
            progress.advance(task_cve)

        # Include ports with no service name (no CVE lookup performed)
        for port, info in nmap_results.items():
            if str(port) not in final_results:
                final_results[str(port)] = {
                    "service": info.get("service", ""),
                    "version": info.get("version", ""),
                    "banner": info.get("banner", ""),
                    "os_guess": info.get("os_guess", ""),
                    "cves": [],
                }

        progress.update(task_cve, description="[green]✔ CVE lookups[/green]")

    # ---- Summary table ----
    table = RichTable(title="Scan Results", show_lines=True)
    table.add_column("Port", style="cyan", no_wrap=True, justify="right")
    table.add_column("Service", style="white")
    table.add_column("Version", style="white")
    table.add_column("CVEs Found", style="red", justify="right")

    for port in sorted(final_results.keys(), key=lambda p: int(p)):
        info = final_results[port]
        table.add_row(
            port,
            info.get("service", ""),
            info.get("version", ""),
            str(len(info.get("cves", []))),
        )

    console.print(table)

    # ---- Persist to state ----
    state.set("scan_results", final_results)

    # ---- Populate open_ports so is_service_open() works in exploit phase ----
    open_ports_dict: dict[int, str] = {}
    for port_key in final_results:
        port_int = int(port_key)
        svc = final_results[port_key].get("service", "open")
        open_ports_dict[port_int] = svc or "open"
    # Also include ports from masscan/nmap that had no service name
    for p in open_ports:
        if p not in open_ports_dict:
            open_ports_dict[p] = "open"
    state.set_open_ports(open_ports_dict)
    state.set_services(nmap_results)

    # ---- Persist to db/scan_results.json ----
    output_path: Path = Path("db") / "scan_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(final_results, f, indent=2, default=str)

    console.print("[green]✔  Scan results saved.[/green]")
    return final_results


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> dict[str, Any]:
    """Entry-point called by the pipeline orchestrator."""
    return run_scanner(target)


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        console.print("[red]Usage: python -m modules.scanner <target>[/red]")
        sys.exit(1)
    run_scanner(sys.argv[1])
