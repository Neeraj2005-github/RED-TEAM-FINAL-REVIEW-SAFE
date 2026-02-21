"""
modules/recon.py — Reconnaissance phase for the AI Red Team Framework.

Performs DNS lookups, WHOIS queries, subdomain enumeration (subfinder),
and Shodan host lookups.  All results are persisted to the central state
file and to db/recon_results.json.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import dns.resolver
import shodan
import whois
from rich import print as rprint
from rich.console import Console
from rich.table import Table as RichTable

from config.settings import SHODAN_API_KEY
from core.state_manager import state

console = Console()


# ---------------------------------------------------------------------------
# 1. DNS Lookup
# ---------------------------------------------------------------------------

def dns_lookup(target: str) -> dict[str, list[str]]:
    """Resolve A, MX, NS, and TXT records for *target*.

    Each record type is queried independently; failures are silently
    skipped so one broken record type never crashes the whole lookup.
    """
    results: dict[str, list[str]] = {}
    record_types: list[str] = ["A", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            results[rtype] = [str(rdata) for rdata in answers]
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.resolver.LifetimeTimeout,
            Exception,
        ):
            results[rtype] = []

    return results


# ---------------------------------------------------------------------------
# 2. WHOIS Lookup
# ---------------------------------------------------------------------------

def _serialize_value(value: Any) -> Any:
    """Convert datetime objects (or lists thereof) to ISO-format strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return [_serialize_value(v) for v in value]
    return value


def whois_lookup(target: str) -> dict[str, Any]:
    """Query WHOIS for *target* and return a normalised dict.

    Keys returned: registrar, creation_date, expiration_date, emails, org.
    Datetime values are converted to ISO 8601 strings.
    """
    try:
        w = whois.whois(target)
        return {
            "registrar": _serialize_value(w.registrar),
            "creation_date": _serialize_value(w.creation_date),
            "expiration_date": _serialize_value(w.expiration_date),
            "emails": _serialize_value(w.emails),
            "org": _serialize_value(w.get("org")),
        }
    except Exception as exc:
        rprint(f"[yellow]⚠  WHOIS lookup failed: {exc}[/yellow]")
        return {}


# ---------------------------------------------------------------------------
# 3. Subfinder Enumeration
# ---------------------------------------------------------------------------

def subfinder_enum(target: str) -> list[str]:
    """Run the *subfinder* binary to enumerate subdomains of *target*.

    Returns a list of discovered subdomains, or an empty list if the
    binary is not installed.
    """
    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        subdomains: list[str] = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]
        return subdomains
    except FileNotFoundError:
        rprint(
            "[yellow]⚠  subfinder not found on PATH — "
            "skipping subdomain enumeration.[/yellow]"
        )
        return []
    except subprocess.TimeoutExpired:
        rprint("[yellow]⚠  subfinder timed out after 60 s.[/yellow]")
        return []
    except Exception as exc:
        rprint(f"[yellow]⚠  subfinder error: {exc}[/yellow]")
        return []


# ---------------------------------------------------------------------------
# 4. Shodan Lookup
# ---------------------------------------------------------------------------

def shodan_lookup(target: str) -> dict[str, Any]:
    """Query the Shodan API for *target* (must be an IP address).

    Returns a dict with open_ports, banners, vulns, org, and country.
    If no API key is configured the function returns an empty dict.
    """
    if not SHODAN_API_KEY:
        rprint("[yellow]⚠  SHODAN_API_KEY not set — skipping Shodan lookup.[/yellow]")
        return {}

    try:
        api = shodan.Shodan(SHODAN_API_KEY)
        host: dict[str, Any] = api.host(target)

        banners: list[str] = []
        for item in host.get("data", []):
            banner = item.get("data", "").strip()
            if banner:
                banners.append(banner)

        return {
            "open_ports": host.get("ports", []),
            "banners": banners,
            "vulns": host.get("vulns", []),
            "org": host.get("org", ""),
            "country": host.get("country_name", ""),
        }
    except shodan.APIError as exc:
        rprint(f"[yellow]⚠  Shodan API error: {exc}[/yellow]")
        return {}
    except Exception as exc:
        rprint(f"[yellow]⚠  Shodan lookup failed: {exc}[/yellow]")
        return {}


# ---------------------------------------------------------------------------
# 5. Run full reconnaissance phase
# ---------------------------------------------------------------------------

def run_recon(target: str) -> dict[str, Any]:
    """Execute all recon functions and persist the combined results.

    A summary table is printed via rich, results are saved both to the
    central state (``state.set('recon', …)``) and to
    ``db/recon_results.json``.
    """
    console.rule("[bold cyan]Phase 1 — Reconnaissance[/bold cyan]")

    rprint(f"[cyan]  Target: {target}[/cyan]")

    dns_results: dict[str, list[str]] = dns_lookup(target)
    whois_results: dict[str, Any] = whois_lookup(target)
    subdomains: list[str] = subfinder_enum(target)
    shodan_results: dict[str, Any] = shodan_lookup(target)

    results: dict[str, Any] = {
        "dns": dns_results,
        "whois": whois_results,
        "subdomains": subdomains,
        "shodan": shodan_results,
        "timestamp": datetime.now().isoformat(),
    }

    # ---- Summary table ----
    table = RichTable(title="Recon Summary", show_lines=True)
    table.add_column("Recon Type", style="cyan", no_wrap=True)
    table.add_column("Results Found", style="green", justify="right")

    dns_count: int = sum(len(v) for v in dns_results.values())
    table.add_row("DNS Records", str(dns_count))
    table.add_row("WHOIS Fields", str(len(whois_results)))
    table.add_row("Subdomains", str(len(subdomains)))
    table.add_row(
        "Shodan Ports",
        str(len(shodan_results.get("open_ports", []))),
    )

    console.print(table)

    # ---- Persist to state ----
    state.set("recon", results)

    # ---- Persist to db/recon_results.json ----
    output_path: Path = Path("db") / "recon_results.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    rprint("[green]✔  Recon results saved.[/green]")
    return results


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> dict[str, Any]:
    """Entry-point called by the pipeline orchestrator."""
    return run_recon(target)


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        rprint("[red]Usage: python -m modules.recon <target>[/red]")
        sys.exit(1)
    run_recon(sys.argv[1])
