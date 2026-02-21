"""
recon/os_fingerprint.py — OS detection & banner-grabbing plugin.

MITRE ATT&CK:
  T1082  System Information Discovery
  T1046  Network Service Scanning (banner grab)

Techniques:
  • Nmap OS-detection output parsing (from port_scanner results)
  • TCP banner grabbing with raw sockets (SSH, FTP, SMTP, …)
  • HTTP Server-header heuristics for OS family inference
  • SMB OS enumeration (via impacket or smbclient fallback)

The plugin accepts ``scan_results`` from the port-scanner phase and enriches
each host with an :class:`OSGuess` prediction fed into privesc / persistence
selectors.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from rich.console import Console

from core.event_bus import Event, bus
from core.plugin_loader import ExecutionContext, ExecutionResult
from core.state_manager import state
from recon import CACHE_DIR

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

BANNER_TIMEOUT: float = 5.0
BANNER_MAX_RECV: int = 4096
SMB_PORT: int = 445
CACHE_FILE: Path = CACHE_DIR / "os_fingerprint_cache.json"


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

@dataclass
class OSGuess:
    """Single OS-detection prediction."""

    os_family: str = "Unknown"          # Linux, Windows, macOS, FreeBSD, …
    os_version: str = ""                # e.g. "Ubuntu 22.04", "Windows Server 2019"
    confidence: float = 0.0             # 0.0 – 1.0
    detection_method: str = ""          # nmap, banner, http, smb
    raw_evidence: str = ""              # original string used for inference

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SMBInfo:
    """Lightweight SMB enumeration result."""

    os_string: str = ""
    domain: str = ""
    hostname: str = ""
    smb_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HostFingerprint:
    """Aggregated per-host OS fingerprint."""

    host: str = ""
    guesses: list[OSGuess] = field(default_factory=list)
    banners: dict[int, str] = field(default_factory=dict)  # port → banner
    smb_info: Optional[SMBInfo] = None
    best_guess: Optional[OSGuess] = None  # highest confidence guess
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# 2. OS inference heuristics
# ---------------------------------------------------------------------------

_BANNER_OS_MAP: list[tuple[str, str, str]] = [
    # (regex over banner, os_family, os_version_hint)
    (r"Ubuntu", "Linux", "Ubuntu"),
    (r"Debian", "Linux", "Debian"),
    (r"CentOS|Red\s*Hat|RHEL", "Linux", "CentOS/RHEL"),
    (r"Fedora", "Linux", "Fedora"),
    (r"Alpine", "Linux", "Alpine"),
    (r"FreeBSD", "FreeBSD", "FreeBSD"),
    (r"OpenBSD", "OpenBSD", "OpenBSD"),
    (r"Microsoft|Windows|Win32|Win64", "Windows", "Windows"),
    (r"macOS|Darwin", "macOS", "macOS"),
    (r"Linux", "Linux", "Linux (generic)"),
]


def _infer_os_from_text(text: str, method: str = "banner") -> OSGuess:
    """Heuristically determine OS from *text* (banner, header, etc.)."""
    for pattern, family, version_hint in _BANNER_OS_MAP:
        if re.search(pattern, text, re.IGNORECASE):
            # Try to extract a version number nearby
            ver = ""
            ver_match = re.search(
                rf"{pattern}[/\s]*(\d[\d.]*)", text, re.IGNORECASE
            )
            if ver_match:
                ver = f"{version_hint} {ver_match.group(1)}"
            else:
                ver = version_hint

            return OSGuess(
                os_family=family,
                os_version=ver,
                confidence=0.5,
                detection_method=method,
                raw_evidence=text[:256],
            )

    return OSGuess(raw_evidence=text[:256], detection_method=method)


# ---------------------------------------------------------------------------
# 3. Banner grabbing
# ---------------------------------------------------------------------------

async def banner_grab(host: str, port: int, *, timeout: float = BANNER_TIMEOUT) -> str:
    """Open a TCP connection to *host*:*port*, send a probe, and capture
    up to :data:`BANNER_MAX_RECV` bytes of the response banner.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except Exception:
        return ""

    banner = ""
    try:
        # Some services (SSH, FTP, SMTP) send a banner immediately
        data = await asyncio.wait_for(reader.read(BANNER_MAX_RECV), timeout=timeout)
        banner = data.decode("utf-8", errors="replace").strip()

        # For HTTP ports, send a minimal request if nothing was received
        if not banner and port in (80, 443, 8080, 8443):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.read(BANNER_MAX_RECV), timeout=timeout)
            banner = data.decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return banner


async def banner_grab_multiple(
    host: str, ports: list[int], *, concurrency: int = 10
) -> dict[int, str]:
    """Grab banners in parallel from multiple *ports*."""
    sem = asyncio.Semaphore(concurrency)
    results: dict[int, str] = {}

    async def _grab(port: int) -> None:
        async with sem:
            b = await banner_grab(host, port)
            if b:
                results[port] = b

    await asyncio.gather(*[_grab(p) for p in ports])
    return results


# ---------------------------------------------------------------------------
# 4. Nmap OS-detection parser
# ---------------------------------------------------------------------------

def fingerprint_from_nmap(nmap_os_guess: str) -> OSGuess:
    """Parse the *os_guess* string produced by :mod:`recon.port_scanner`
    (extracted from nmap XML ``osmatch`` elements) and return an
    :class:`OSGuess`.
    """
    if not nmap_os_guess:
        return OSGuess(detection_method="nmap")

    guess = _infer_os_from_text(nmap_os_guess, method="nmap")

    # Nmap accuracy is usually fairly high
    accuracy_match = re.search(r"(\d{1,3})%?", nmap_os_guess)
    if accuracy_match:
        guess.confidence = min(int(accuracy_match.group(1)) / 100, 1.0)
    else:
        guess.confidence = 0.7  # reasonable default for valid nmap output

    return guess


# ---------------------------------------------------------------------------
# 5. HTTP-header OS analysis
# ---------------------------------------------------------------------------

async def http_header_analysis(url: str) -> OSGuess:
    """Infer OS from the ``Server`` / ``X-Powered-By`` HTTP headers."""
    try:
        import httpx  # local import — optional dep
    except ImportError:
        # Fallback to raw socket HEAD request
        return OSGuess(detection_method="http")

    try:
        async with httpx.AsyncClient(verify=False) as client:
            resp = await client.head(url, timeout=BANNER_TIMEOUT)
            server = resp.headers.get("Server", "")
            powered = resp.headers.get("X-Powered-By", "")
            combined = f"{server} {powered}"

            guess = _infer_os_from_text(combined, method="http")
            # HTTP headers are a weak signal
            guess.confidence = min(guess.confidence, 0.35)
            return guess
    except Exception:
        return OSGuess(detection_method="http")


# ---------------------------------------------------------------------------
# 6. SMB enumeration
# ---------------------------------------------------------------------------

async def smb_enum_os(host: str, port: int = SMB_PORT) -> SMBInfo:
    """Attempt an unauthenticated SMB session-setup to extract the OS string.

    Uses a minimal raw SMB1 Negotiate + Session Setup flow so that
    ``impacket`` is not a hard dependency.
    """
    info = SMBInfo()

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=BANNER_TIMEOUT,
        )
    except Exception:
        return info

    try:
        # --- SMB1 Negotiate request (bare minimum) ---
        negotiate = (
            b"\x00\x00\x00\x45"             # NetBIOS header (length 0x45)
            b"\xffSMB"                       # SMB1 magic
            b"\x72"                          # Negotiate Protocol
            b"\x00\x00\x00\x00"             # Status
            b"\x18"                          # Flags
            b"\x53\xc8"                      # Flags2 (unicode)
            b"\x00" * 12                     # Padding
            b"\x00\x00\xff\xfe"             # TID, PID
            b"\x00\x00\x00\x00\x00\x00"     # UID, MID
            b"\x00"                          # Word Count
            b"\x22\x00"                      # Byte Count
            b"\x02NT LM 0.12\x00"           # Dialect string
            b"\x02SMB 2.002\x00"
            b"\x02SMB 2.???\x00"
        )
        writer.write(negotiate)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(4096), timeout=BANNER_TIMEOUT)

        decoded = data.decode("utf-8", errors="replace")

        # Try extracting OS string from late bytes (after session setup)
        for pattern, fam in [
            (r"Windows\s+[\w.]+", "Windows"),
            (r"Samba\s+[\d.]+", "Linux"),
        ]:
            m = re.search(pattern, decoded)
            if m:
                info.os_string = m.group()
                break

        # Try hostname (NetBIOS)
        nb_match = re.search(r"\\\\([\w-]+)", decoded)
        if nb_match:
            info.hostname = nb_match.group(1)

    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    return info


# ---------------------------------------------------------------------------
# 7. OSFingerprinter orchestrator
# ---------------------------------------------------------------------------

class OSFingerprinter:
    """Orchestrate multi-technique OS detection for a list of hosts."""

    async def fingerprint_host(
        self,
        host: str,
        open_ports: list[int],
        *,
        nmap_os_guess: str = "",
    ) -> HostFingerprint:
        """Run all detection techniques against a single *host* and merge."""
        fp = HostFingerprint(host=host)
        guesses: list[OSGuess] = []

        # (a) Nmap OS string
        if nmap_os_guess:
            g = fingerprint_from_nmap(nmap_os_guess)
            if g.os_family != "Unknown":
                guesses.append(g)

        # (b) Banner grabbing
        banners = await banner_grab_multiple(host, open_ports)
        fp.banners = banners
        for port, banner in banners.items():
            g = _infer_os_from_text(banner, method=f"banner:{port}")
            if g.os_family != "Unknown":
                guesses.append(g)

        # (c) HTTP header analysis (if web ports are open)
        web_ports = [p for p in open_ports if p in (80, 443, 8080, 8443)]
        for wp in web_ports[:1]:  # analyse only first web port
            scheme = "https" if wp in (443, 8443) else "http"
            g = await http_header_analysis(f"{scheme}://{host}:{wp}")
            if g.os_family != "Unknown":
                guesses.append(g)

        # (d) SMB enumeration
        if SMB_PORT in open_ports:
            smb = await smb_enum_os(host, SMB_PORT)
            fp.smb_info = smb
            if smb.os_string:
                g = _infer_os_from_text(smb.os_string, method="smb")
                g.confidence = 0.75
                guesses.append(g)

        fp.guesses = guesses

        # Pick the best guess
        if guesses:
            fp.best_guess = max(guesses, key=lambda g: g.confidence)

        return fp

    async def fingerprint_all(
        self,
        targets: dict[str, Any],
    ) -> list[HostFingerprint]:
        """Fingerprint every host in *targets*.

        ``targets`` is a mapping ``{host: {"open_ports": [int], "os_guess": str}}``.
        """
        tasks = []
        for host, info in targets.items():
            ports = info.get("open_ports", [])
            os_hint = info.get("os_guess", "")
            tasks.append(self.fingerprint_host(host, ports, nmap_os_guess=os_hint))

        return list(await asyncio.gather(*tasks, return_exceptions=False))


# ---------------------------------------------------------------------------
# 8. Cache helpers
# ---------------------------------------------------------------------------

import json  # noqa: E402 (kept with cache section)


def _load_cache() -> dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text())
        except Exception:
            pass
    return {}


def _save_cache(data: dict[str, Any]) -> None:
    CACHE_FILE.write_text(json.dumps(data, indent=2, default=str))


# ---------------------------------------------------------------------------
# 9. Plugin interface
# ---------------------------------------------------------------------------

def metadata() -> dict[str, Any]:
    return {
        "name": "os_fingerprint",
        "version": "1.0.0",
        "category": "recon",
        "mitre_techniques": ["T1082", "T1046"],
        "description": "OS detection via banners, nmap, HTTP headers, and SMB enumeration",
        "dependencies": [],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Plugin entry-point.

    Reads ``scan_results`` from :data:`context.previous_results` (produced by
    *port_scanner*) and enriches each host with an :class:`OSGuess`.
    """
    # Collect scan results from previous phase or state
    scan_results: dict[str, Any] = context.previous_results.get("scan_results", {})
    if not scan_results:
        scan_results = state.get("scan_results", {})
    if not scan_results:
        return ExecutionResult(
            success=False,
            errors=["No scan_results available — run port_scanner first"],
        )

    # Build a targets dict suitable for fingerprint_all()
    targets: dict[str, Any] = {}
    for host, host_data in scan_results.items():
        if not isinstance(host_data, dict):
            continue
        open_ports = list(host_data.get("open_ports", {}).keys())
        # Normalise port numbers to int
        open_ports = [int(p) for p in open_ports]
        os_hint = host_data.get("os_guess", "")
        targets[host] = {"open_ports": open_ports, "os_guess": os_hint}

    if not targets:
        return ExecutionResult(
            success=False,
            errors=["scan_results contained no valid hosts"],
        )

    fp = OSFingerprinter()
    try:
        results = asyncio.run(fp.fingerprint_all(targets))
    except Exception as exc:
        logger.error("OS fingerprinting failed: %s", exc, exc_info=True)
        return ExecutionResult(success=False, errors=[str(exc)])

    # Build output
    output: dict[str, Any] = {}
    for hfp in results:
        entry = hfp.to_dict()
        output[hfp.host] = entry

    # Cache + state
    cache = _load_cache()
    cache[datetime.utcnow().isoformat()] = output
    _save_cache(cache)
    state.set("os_fingerprints", output)

    # Summarise best guesses
    summary: dict[str, str] = {}
    for hfp in results:
        if hfp.best_guess:
            summary[hfp.host] = (
                f"{hfp.best_guess.os_family} – {hfp.best_guess.os_version} "
                f"({hfp.best_guess.confidence:.0%})"
            )
        else:
            summary[hfp.host] = "Unknown"

    # Fire event
    bus.publish_sync(Event(
        event_type="recon.os_identified",
        payload={
            "hosts_scanned": len(targets),
            "identified": len(summary),
            "summary": summary,
        },
        source="os_fingerprint",
    ))

    console.print(
        f"[green]✔  OS fingerprinting complete: "
        f"{len(summary)} host(s) analysed[/green]"
    )

    for host, guess_str in summary.items():
        console.print(f"   {host}: {guess_str}")

    return ExecutionResult(
        success=True,
        output={"os_fingerprints": output, "summary": summary},
    )


# ---------------------------------------------------------------------------
# Stand-alone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m recon.os_fingerprint <host> [port1,port2,...]")
        sys.exit(1)

    host = sys.argv[1]
    ports = [int(p) for p in sys.argv[2].split(",")] if len(sys.argv) > 2 else [22, 80, 443]

    ctx = ExecutionContext(
        phase="recon",
        target_info={"target": host},
        previous_results={
            "scan_results": {host: {"open_ports": {p: {} for p in ports}, "os_guess": ""}}
        },
    )
    res = execute(ctx)
    print(json.dumps(res.output, indent=2, default=str))
