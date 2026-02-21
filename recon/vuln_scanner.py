"""
recon/vuln_scanner.py — Vulnerability scanning plugin for the AI Red Team
Framework.

MITRE ATT&CK:
  T1595.002  Active Scanning: Vulnerability Scanning
  T1190      Exploit Public-Facing Application

Maps discovered services to known CVEs by querying the NVD REST API and
a local ``searchsploit`` database.  Results are ranked by a composite
risk score that combines CVSS base score and public-exploit availability.

CVE data is cached locally in ``.cache/vuln_cache.db`` (SQLite) with a
configurable TTL (default 24 h) to minimise API traffic.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import requests
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

NVD_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RESULTS_PER_PAGE: int = 10
NVD_RATE_LIMIT_SLEEP: float = 1.0
CACHE_DB: Path = CACHE_DIR / "vuln_cache.db"
CACHE_TTL_SECONDS: int = 86_400  # 24 h


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

@dataclass
class CVE:
    """A single CVE entry."""

    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    severity: str = ""              # LOW / MEDIUM / HIGH / CRITICAL
    has_public_poc: bool = False
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Exploit:
    """A local searchsploit match."""

    title: str = ""
    path: str = ""
    edb_id: str = ""
    exploit_type: str = ""   # remote, local, webapps, dos
    has_rce: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VulnerabilityReport:
    """Aggregated vulnerability report for a single service."""

    service: str = ""
    version: str = ""
    port: int = 0
    cves: list[CVE] = field(default_factory=list)
    exploits: list[Exploit] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# 2. SQLite cache
# ---------------------------------------------------------------------------

def _init_cache() -> sqlite3.Connection:
    conn = sqlite3.connect(str(CACHE_DB))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS vuln_cache (
            cache_key  TEXT PRIMARY KEY,
            data       TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _cache_key(prefix: str, value: str) -> str:
    raw = f"{prefix}:{value}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_get(conn: sqlite3.Connection, key: str) -> Optional[Any]:
    row = conn.execute(
        "SELECT data, created_at FROM vuln_cache WHERE cache_key = ?", (key,)
    ).fetchone()
    if row is None:
        return None
    data, created_at = row
    if time.time() - created_at > CACHE_TTL_SECONDS:
        conn.execute("DELETE FROM vuln_cache WHERE cache_key = ?", (key,))
        conn.commit()
        return None
    return json.loads(data)


def _cache_set(conn: sqlite3.Connection, key: str, data: Any) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO vuln_cache (cache_key, data, created_at) VALUES (?, ?, ?)",
        (key, json.dumps(data), time.time()),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# 3. NVDScanner
# ---------------------------------------------------------------------------

class NVDScanner:
    """Query the NIST NVD REST API for CVEs matching a service + version."""

    def __init__(
        self,
        api_key: str = "",
        cache_conn: Optional[sqlite3.Connection] = None,
    ) -> None:
        self._api_key = api_key
        self._conn = cache_conn or _init_cache()

    def query_nvd(self, service_name: str, version: str) -> list[CVE]:
        """Return CVEs for *service_name* + *version* (up to
        :data:`NVD_RESULTS_PER_PAGE` results).
        """
        if not service_name:
            return []

        keyword = f"{service_name} {version}".strip()
        key = _cache_key("nvd", keyword)
        cached = _cache_get(self._conn, key)
        if cached is not None:
            return [CVE(**c) for c in cached]

        time.sleep(NVD_RATE_LIMIT_SLEEP)

        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
        }
        headers: dict[str, str] = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            logger.warning("NVD query failed for %s: %s", keyword, exc)
            return []

        cves: list[CVE] = []
        for vuln in data.get("vulnerabilities", []):
            cve_item = vuln.get("cve", {})
            cve = self._parse_cve(cve_item)
            cves.append(cve)

        _cache_set(self._conn, key, [c.to_dict() for c in cves])
        return cves

    # ------------------------------------------------------------------

    @staticmethod
    def parse_cvss_score(cve: CVE) -> float:
        """Return the CVSS base score (0–10) of *cve*."""
        return cve.cvss_score

    @staticmethod
    def cve_is_exploitable(cve: CVE) -> bool:
        """Return ``True`` if the CVE has a known public PoC / exploit."""
        return cve.has_public_poc

    # ------------------------------------------------------------------

    @staticmethod
    def _parse_cve(cve_item: dict[str, Any]) -> CVE:
        """Parse a single CVE entry from the NVD JSON schema."""
        cve_id = cve_item.get("id", "")

        # Description (English)
        description = ""
        for desc in cve_item.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:500]
                break

        # CVSS — try v3.1, v3.0, then v2
        cvss_score = 0.0
        cvss_vector = ""
        severity = ""
        metrics = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity = cvss_data.get("baseSeverity", "")
                break

        if not severity:
            if cvss_score >= 9.0:
                severity = "CRITICAL"
            elif cvss_score >= 7.0:
                severity = "HIGH"
            elif cvss_score >= 4.0:
                severity = "MEDIUM"
            else:
                severity = "LOW"

        # References — look for exploit-db / PoC indicators
        references: list[str] = []
        has_poc = False
        for ref in cve_item.get("references", []):
            url = ref.get("url", "")
            references.append(url)
            tags = ref.get("tags", [])
            if "Exploit" in tags or "exploit-db" in url.lower():
                has_poc = True

        return CVE(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            severity=severity,
            has_public_poc=has_poc,
            references=references[:10],
        )


# ---------------------------------------------------------------------------
# 4. SearchsploitScanner
# ---------------------------------------------------------------------------

class SearchsploitScanner:
    """Query a local ``searchsploit`` (ExploitDB) installation."""

    @staticmethod
    def local_searchsploit_query(service: str) -> list[Exploit]:
        """Run ``searchsploit --json`` and return matching exploits."""
        try:
            proc = subprocess.run(
                ["searchsploit", "--json", service],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except FileNotFoundError:
            logger.info("searchsploit not installed — skipping")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("searchsploit timed out for %s", service)
            return []
        except Exception as exc:
            logger.warning("searchsploit error: %s", exc)
            return []

        exploits: list[Exploit] = []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        for entry in data.get("RESULTS_EXPLOIT", []):
            title = entry.get("Title", "")
            path = entry.get("Path", "")
            edb_id = entry.get("EDB-ID", "")
            etype = entry.get("Type", "")

            has_rce = SearchsploitScanner.exploit_has_rce_from_text(title)

            exploits.append(Exploit(
                title=title,
                path=path,
                edb_id=str(edb_id),
                exploit_type=etype,
                has_rce=has_rce,
            ))

        return exploits

    @staticmethod
    def exploit_has_rce(exploit: Exploit) -> bool:
        """Return ``True`` if *exploit* grants remote code execution."""
        return exploit.has_rce

    @staticmethod
    def exploit_has_rce_from_text(text: str) -> bool:
        """Heuristically detect RCE from exploit title / description."""
        rce_patterns = [
            r"\bRCE\b",
            r"remote\s+code\s+exec",
            r"command\s+inject",
            r"shell\s+upload",
            r"reverse\s+shell",
            r"arbitrary\s+code",
        ]
        text_lower = text.lower()
        return any(re.search(p, text_lower) for p in rce_patterns)


# ---------------------------------------------------------------------------
# 5. Risk scoring
# ---------------------------------------------------------------------------

def compute_risk_score(cves: list[CVE], exploits: list[Exploit]) -> float:
    """Compute a composite risk score (0–10) for a service.

    Formula:
        base = max(CVSS scores)
        bonus = +0.5 per public PoC CVE (max +2)
        bonus += +0.5 per RCE exploit  (max +2)
        clamped to [0, 10]
    """
    if not cves and not exploits:
        return 0.0

    base = max((c.cvss_score for c in cves), default=0.0)
    poc_bonus = min(sum(0.5 for c in cves if c.has_public_poc), 2.0)
    rce_bonus = min(sum(0.5 for e in exploits if e.has_rce), 2.0)
    return min(base + poc_bonus + rce_bonus, 10.0)


# ---------------------------------------------------------------------------
# 6. Parallel service scanner
# ---------------------------------------------------------------------------

async def scan_service(
    service: str,
    version: str,
    port: int,
    nvd_api_key: str = "",
    cache_conn: Optional[sqlite3.Connection] = None,
) -> VulnerabilityReport:
    """Scan a single service for CVEs and exploits."""
    conn = cache_conn or _init_cache()
    loop = asyncio.get_running_loop()

    nvd = NVDScanner(api_key=nvd_api_key, cache_conn=conn)
    ssploit = SearchsploitScanner()

    query_str = f"{service} {version}".strip()

    cves, exploits = await asyncio.gather(
        loop.run_in_executor(None, nvd.query_nvd, service, version),
        loop.run_in_executor(None, ssploit.local_searchsploit_query, query_str),
    )

    risk = compute_risk_score(cves, exploits)

    return VulnerabilityReport(
        service=service,
        version=version,
        port=port,
        cves=cves,
        exploits=exploits,
        risk_score=round(risk, 2),
    )


async def scan_all_services(
    services: list[dict[str, Any]],
    nvd_api_key: str = "",
) -> list[VulnerabilityReport]:
    """Scan all *services* in parallel.

    Each entry is a dict with keys: ``service``, ``version``, ``port``.
    """
    conn = _init_cache()
    tasks = [
        scan_service(
            svc.get("service", ""),
            svc.get("version", ""),
            int(svc.get("port", 0)),
            nvd_api_key=nvd_api_key,
            cache_conn=conn,
        )
        for svc in services
    ]
    return list(await asyncio.gather(*tasks))


# ---------------------------------------------------------------------------
# 7. Plugin interface
# ---------------------------------------------------------------------------

def metadata() -> dict[str, Any]:
    return {
        "name": "vuln_scanner",
        "version": "1.0.0",
        "category": "recon",
        "mitre_techniques": ["T1595.002", "T1190"],
        "description": "NVD + searchsploit vulnerability scanner with risk scoring",
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Plugin entry-point.

    Reads services from ``context.previous_results`` (the scan phase's
    output) and returns CVE lists with CVSS scores and PoC availability.
    """
    # Build service list from previous scan results
    scan_data: dict[str, Any] = (
        context.previous_results.get("scanning", {}).get("scan_results", {})
    )
    if not scan_data:
        scan_data = state.get("scan_results", {})

    if not scan_data:
        return ExecutionResult(success=False, errors=["No scan results available"])

    services: list[dict[str, Any]] = []
    for port_str, info in scan_data.items():
        svc = info.get("service", "")
        ver = info.get("version", "")
        if svc:
            services.append({"service": svc, "version": ver, "port": int(port_str)})

    if not services:
        return ExecutionResult(success=True, output={"vulnerabilities": []})

    nvd_key = context.config.get("nvd_api_key", "")

    try:
        reports = asyncio.run(scan_all_services(services, nvd_api_key=nvd_key))
    except Exception as exc:
        logger.exception("Vulnerability scanning failed")
        return ExecutionResult(success=False, errors=[str(exc)])

    # Attach CVEs back onto scan_results for backward compatibility
    for report in reports:
        port_key = str(report.port)
        if port_key in scan_data:
            scan_data[port_key]["cves"] = [c.to_dict() for c in report.cves]

    state.set("scan_results", scan_data)

    output = {
        "vulnerabilities": [r.to_dict() for r in reports],
        "total_cves": sum(len(r.cves) for r in reports),
        "critical_services": [
            r.service for r in reports if r.risk_score >= 8.0
        ],
    }

    # Fire event
    bus.publish_sync(Event(
        event_type="scan.vulnerabilities_found",
        payload={
            "total_cves": output["total_cves"],
            "critical_services": output["critical_services"],
        },
        source="vuln_scanner",
    ))

    console.print(
        f"[green]✔  Vulnerability scan complete: "
        f"{output['total_cves']} CVEs across {len(reports)} services[/green]"
    )

    return ExecutionResult(success=True, output=output)


# ---------------------------------------------------------------------------
# Stand-alone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    svc = sys.argv[1] if len(sys.argv) > 1 else "openssh"
    ver = sys.argv[2] if len(sys.argv) > 2 else "8.9"
    report = asyncio.run(scan_service(svc, ver, 22))
    print(json.dumps(report.to_dict(), indent=2))
