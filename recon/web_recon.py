"""
recon/web_recon.py — Web reconnaissance plugin for the AI Red Team Framework.

MITRE ATT&CK:
  T1595.002  Active Scanning: Vulnerability Scanning
  T1592.004  Gather Victim Host Information: Client Configurations (tech detect)

Performs:
  • Directory / path brute-force (async with ``httpx``)
  • Technology fingerprinting (Wappalyzer-style heuristics)
  • Web-server fingerprinting (headers, Server, X-Powered-By)
  • Interesting-endpoint discovery (admin panels, config files, backups)
  • Security-header audit (HSTS, CSP, X-Frame-Options, …)

HTTP requests use the ``httpx`` async client with retry + exponential
backoff.  Results are cached in ``.cache/web_scan_results.json``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:  # pragma: no cover — fallback when httpx is absent
    httpx = None  # type: ignore[assignment]

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

CACHE_FILE: Path = CACHE_DIR / "web_scan_results.json"
MAX_CONCURRENCY: int = 20
REQUEST_TIMEOUT: float = 10.0
MAX_RETRIES: int = 3
BACKOFF_FACTOR: float = 0.5

DEFAULT_DIR_WORDLIST: list[str] = [
    "/admin", "/login", "/wp-admin", "/administrator",
    "/panel", "/dashboard", "/config", "/setup",
    "/phpmyadmin", "/server-status", "/robots.txt",
    "/.env", "/.git/config", "/backup", "/api",
    "/api/v1", "/swagger", "/graphql", "/wp-login.php",
    "/sitemap.xml", "/.well-known/security.txt",
]

SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

@dataclass
class ServerFingerprint:
    """Captured web-server identity information."""

    software: str = ""
    version: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WebReconResult:
    """Aggregated web-recon output for one URL."""

    url: str = ""
    domains: list[str] = field(default_factory=list)
    open_endpoints: list[str] = field(default_factory=list)
    technologies: dict[str, str] = field(default_factory=dict)
    security_headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    server_fingerprint: ServerFingerprint = field(default_factory=ServerFingerprint)
    interesting_findings: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# 2. Technology detection patterns
# ---------------------------------------------------------------------------

# Maps a technology label to a compile-ready regex applied to response body
# OR to a (header_name, regex) tuple.
_TECH_BODY_PATTERNS: dict[str, str] = {
    "WordPress": r"wp-content|wp-includes",
    "Joomla": r"Joomla!|com_content",
    "Drupal": r'Drupal\.settings|sites/default/files',
    "jQuery": r'jquery[-.]\d+\.\d+',
    "React": r'react\.production\.min|__NEXT_DATA__',
    "Vue.js": r'vue\.runtime|v-cloak',
    "Angular": r'ng-version|angular\.min',
    "Bootstrap": r'bootstrap\.min\.(css|js)',
    "Laravel": r'laravel_session|XSRF-TOKEN',
    "Django": r'csrfmiddlewaretoken|__admin_media_prefix__',
    "Flask": r'Werkzeug|flask\.app',
    "ASP.NET": r'__VIEWSTATE|asp\.net',
    "PHP": r'\.php["\s?]|PHPSESSID',
}

_TECH_HEADER_PATTERNS: dict[str, tuple[str, str]] = {
    "Nginx": ("Server", r"nginx"),
    "Apache": ("Server", r"Apache"),
    "IIS": ("Server", r"Microsoft-IIS"),
    "Express": ("X-Powered-By", r"Express"),
    "PHP (header)": ("X-Powered-By", r"PHP"),
    "Cloudflare WAF": ("Server", r"cloudflare"),
    "AWS ALB": ("Server", r"awselb"),
}


# ---------------------------------------------------------------------------
# 3. Async HTTP helper with retry + backoff
# ---------------------------------------------------------------------------

async def _fetch(
    client: "httpx.AsyncClient",
    url: str,
    method: str = "GET",
    *,
    retries: int = MAX_RETRIES,
    follow_redirects: bool = True,
) -> Optional["httpx.Response"]:
    """Execute an HTTP request with exponential-backoff retries."""
    for attempt in range(retries):
        try:
            resp = await client.request(
                method,
                url,
                follow_redirects=follow_redirects,
                timeout=REQUEST_TIMEOUT,
            )
            return resp
        except Exception:
            if attempt < retries - 1:
                await asyncio.sleep(BACKOFF_FACTOR * (2 ** attempt))
    return None


# ---------------------------------------------------------------------------
# 4. WebScanner
# ---------------------------------------------------------------------------

class WebScanner:
    """Async web reconnaissance scanner."""

    def __init__(self) -> None:
        self._ensure_httpx()

    @staticmethod
    def _ensure_httpx() -> None:
        if httpx is None:
            raise ImportError(
                "httpx is required for web_recon — install with: pip install httpx"
            )

    # ------------------------------------------------------------------
    # 4a. Directory brute-force
    # ------------------------------------------------------------------

    async def directory_brute_force(
        self,
        url: str,
        wordlist: Optional[list[str]] = None,
    ) -> list[str]:
        """Probe *url* + each path in *wordlist* and return those that
        respond with 2xx or 3xx.
        """
        paths = wordlist or DEFAULT_DIR_WORDLIST
        found: list[str] = []
        sem = asyncio.Semaphore(MAX_CONCURRENCY)

        async with httpx.AsyncClient(verify=False) as client:

            async def _probe(path: str) -> None:
                target = url.rstrip("/") + path
                async with sem:
                    resp = await _fetch(client, target, retries=1)
                    if resp is not None and resp.status_code < 400:
                        found.append(target)

            await asyncio.gather(*[_probe(p) for p in paths])

        found.sort()
        return found

    # ------------------------------------------------------------------
    # 4b. Technology detection
    # ------------------------------------------------------------------

    async def detect_technologies(self, url: str) -> dict[str, str]:
        """Identify technologies from response body and headers."""
        detected: dict[str, str] = {}

        async with httpx.AsyncClient(verify=False) as client:
            resp = await _fetch(client, url)
            if resp is None:
                return detected

            body = resp.text
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Body patterns
            for tech, pattern in _TECH_BODY_PATTERNS.items():
                if re.search(pattern, body, re.IGNORECASE):
                    detected[tech] = "detected (body)"

            # Header patterns
            for tech, (header, pattern) in _TECH_HEADER_PATTERNS.items():
                header_val = headers.get(header.lower(), "")
                if re.search(pattern, header_val, re.IGNORECASE):
                    # Extract version if possible
                    ver_match = re.search(r"[\d]+(?:\.[\d]+)+", header_val)
                    detected[tech] = ver_match.group() if ver_match else "detected"

        return detected

    # ------------------------------------------------------------------
    # 4c. Server fingerprinting
    # ------------------------------------------------------------------

    async def fingerprint_web_server(self, url: str) -> ServerFingerprint:
        """Return a :class:`ServerFingerprint` from response headers."""
        fp = ServerFingerprint()

        async with httpx.AsyncClient(verify=False) as client:
            resp = await _fetch(client, url)
            if resp is None:
                return fp

            fp.headers = dict(resp.headers)

            server_header = resp.headers.get("Server", "")
            fp.software = server_header.split("/")[0] if "/" in server_header else server_header
            ver_match = re.search(r"[\d]+(?:\.[\d]+)+", server_header)
            if ver_match:
                fp.version = ver_match.group()

            # Merge technology detection
            techs = await self.detect_technologies(url)
            fp.technologies = list(techs.keys())

        return fp

    # ------------------------------------------------------------------
    # 4d. Interesting endpoints
    # ------------------------------------------------------------------

    async def find_interesting_endpoints(self, url: str) -> list[str]:
        """Probe for admin panels, config files, backups, etc."""
        interesting_paths = [
            "/admin", "/login", "/administrator", "/wp-admin",
            "/config.php", "/config.yml", "/config.json",
            "/.env", "/.git/config", "/.git/HEAD",
            "/backup.zip", "/backup.tar.gz", "/db.sql",
            "/server-info", "/server-status",
            "/phpinfo.php", "/info.php",
        ]
        return await self.directory_brute_force(url, interesting_paths)

    # ------------------------------------------------------------------
    # 4e. Security-header audit
    # ------------------------------------------------------------------

    async def audit_security_headers(self, url: str) -> tuple[dict[str, str], list[str]]:
        """Check for the presence of recommended security headers.

        Returns (present_headers, missing_headers).
        """
        present: dict[str, str] = {}
        missing: list[str] = []

        async with httpx.AsyncClient(verify=False) as client:
            resp = await _fetch(client, url)
            if resp is None:
                return present, SECURITY_HEADERS[:]

            lowercase_headers = {k.lower(): v for k, v in resp.headers.items()}
            for hdr in SECURITY_HEADERS:
                val = lowercase_headers.get(hdr.lower())
                if val:
                    present[hdr] = val
                else:
                    missing.append(hdr)

        return present, missing

    # ------------------------------------------------------------------
    # 4f. Full scan
    # ------------------------------------------------------------------

    async def full_scan(self, url: str) -> WebReconResult:
        """Run all web-recon techniques against *url* concurrently."""
        dir_task = self.directory_brute_force(url)
        tech_task = self.detect_technologies(url)
        fp_task = self.fingerprint_web_server(url)
        interesting_task = self.find_interesting_endpoints(url)
        header_task = self.audit_security_headers(url)

        dirs, techs, fp, interesting, (sec_present, sec_missing) = await asyncio.gather(
            dir_task, tech_task, fp_task, interesting_task, header_task
        )

        return WebReconResult(
            url=url,
            open_endpoints=dirs,
            technologies=techs,
            security_headers=sec_present,
            missing_security_headers=sec_missing,
            server_fingerprint=fp,
            interesting_findings=interesting,
        )


# ---------------------------------------------------------------------------
# 5. Cache helpers
# ---------------------------------------------------------------------------

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
# 6. Plugin interface
# ---------------------------------------------------------------------------

def metadata() -> dict[str, Any]:
    return {
        "name": "web_recon",
        "version": "1.0.0",
        "category": "recon",
        "mitre_techniques": ["T1595.002", "T1592.004"],
        "description": "Web technology detection, directory brute-force, and security-header audit",
        "dependencies": ["httpx"],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Plugin entry-point.

    Reads discovered subdomains / domains from ``context.previous_results``
    and returns technology stacks, endpoints, and server info.
    """
    if httpx is None:
        return ExecutionResult(
            success=False,
            errors=["httpx not installed — run: pip install httpx"],
        )

    # Determine URLs to scan
    target = context.target_info.get("target", "")
    domains: list[str] = context.target_info.get("domains", [])

    if not domains and target:
        # Build URL from target
        url = target if target.startswith("http") else f"http://{target}"
        domains = [url]

    if not domains:
        return ExecutionResult(success=False, errors=["No domains/URLs provided"])

    scanner = WebScanner()
    all_results: list[dict[str, Any]] = []

    for domain in domains:
        url = domain if domain.startswith("http") else f"http://{domain}"
        try:
            result = asyncio.run(scanner.full_scan(url))
            all_results.append(result.to_dict())
        except Exception as exc:
            logger.warning("Web recon failed for %s: %s", url, exc)
            all_results.append({"url": url, "error": str(exc)})

    # Cache
    cache = _load_cache()
    cache[datetime.utcnow().isoformat()] = all_results
    _save_cache(cache)

    # Persist
    state.set("web_recon", all_results)

    # Aggregate technologies
    all_techs: dict[str, str] = {}
    for r in all_results:
        all_techs.update(r.get("technologies", {}))

    # Fire event
    bus.publish_sync(Event(
        event_type="recon.web_technologies_found",
        payload={
            "domains_scanned": len(domains),
            "technologies": all_techs,
            "total_endpoints": sum(
                len(r.get("open_endpoints", [])) for r in all_results
            ),
        },
        source="web_recon",
    ))

    console.print(
        f"[green]✔  Web recon complete: "
        f"{len(all_techs)} technologies, "
        f"{sum(len(r.get('open_endpoints', [])) for r in all_results)} endpoints "
        f"across {len(domains)} domain(s)[/green]"
    )

    return ExecutionResult(
        success=True,
        output={"web_recon": all_results, "technologies": all_techs},
    )


# ---------------------------------------------------------------------------
# Stand-alone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from core.state_manager import state as _state
    _target = sys.argv[1] if len(sys.argv) > 1 else _state.target_ip or "<TARGET>"
    url = _target if _target.startswith("http") else f"http://{_target}"
    ctx = ExecutionContext(phase="recon", target_info={"target": url})
    res = execute(ctx)
    print(json.dumps(res.output, indent=2, default=str))
