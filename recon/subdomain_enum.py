"""
recon/subdomain_enum.py — Subdomain enumeration plugin for the AI Red Team
Framework.

MITRE ATT&CK:
  T1595.002  Active Scanning: Vulnerability Scanning (subdomain brute-force)
  T1596.001  Search Open Technical Databases (crt.sh, Shodan)

Combines three discovery techniques:
  1. DNS brute-force against a wordlist (async for parallelism)
  2. Certificate Transparency log queries via crt.sh
  3. Shodan passive DNS lookup

Results are cached in ``.cache/subdomain_cache.db`` (SQLite) so
duplicate API calls within a configurable TTL are avoided.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import dns.resolver
import requests
from rich.console import Console

from config.settings import SHODAN_API_KEY, WORDLISTS_DIR
from core.event_bus import Event, bus
from core.plugin_loader import ExecutionContext, ExecutionResult
from core.state_manager import state
from recon import CACHE_DIR

logger = logging.getLogger(__name__)
console = Console()

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

CACHE_DB: Path = CACHE_DIR / "subdomain_cache.db"
CACHE_TTL_SECONDS: int = 86_400  # 24 h
CRT_SH_URL: str = "https://crt.sh/"
DEFAULT_WORDLIST: Path = WORDLISTS_DIR / "subdomains_small.txt"
DNS_CONCURRENCY: int = 50  # max parallel DNS queries


# ---------------------------------------------------------------------------
# 1. Data structures
# ---------------------------------------------------------------------------

@dataclass
class EnumerationResult:
    """Result container for the subdomain-enumeration plugin."""

    discovered_subdomains: list[str] = field(default_factory=list)
    dns_records: dict[str, list[str]] = field(default_factory=dict)
    suspicious_records: list[str] = field(default_factory=list)
    source_counts: dict[str, int] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# 2. SQLite cache
# ---------------------------------------------------------------------------

def _init_cache() -> sqlite3.Connection:
    """Create (or open) the SQLite cache and return a connection."""
    conn = sqlite3.connect(str(CACHE_DB))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS subdomain_cache (
            cache_key  TEXT PRIMARY KEY,
            data       TEXT NOT NULL,
            created_at REAL NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _cache_get(conn: sqlite3.Connection, key: str) -> Optional[list[str]]:
    """Return cached subdomains for *key*, or ``None`` if expired / missing."""
    row = conn.execute(
        "SELECT data, created_at FROM subdomain_cache WHERE cache_key = ?",
        (key,),
    ).fetchone()
    if row is None:
        return None
    data, created_at = row
    if time.time() - created_at > CACHE_TTL_SECONDS:
        conn.execute("DELETE FROM subdomain_cache WHERE cache_key = ?", (key,))
        conn.commit()
        return None
    return json.loads(data)


def _cache_set(conn: sqlite3.Connection, key: str, subdomains: list[str]) -> None:
    """Store *subdomains* in the cache under *key*."""
    conn.execute(
        """
        INSERT OR REPLACE INTO subdomain_cache (cache_key, data, created_at)
        VALUES (?, ?, ?)
        """,
        (key, json.dumps(subdomains), time.time()),
    )
    conn.commit()


def _cache_key(prefix: str, domain: str) -> str:
    """Build a deterministic cache key."""
    raw = f"{prefix}:{domain}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# 3. SubdomainEnumerator
# ---------------------------------------------------------------------------

class SubdomainEnumerator:
    """Discovers subdomains via brute-force DNS, crt.sh, and Shodan."""

    def __init__(self, cache_conn: Optional[sqlite3.Connection] = None) -> None:
        self._conn = cache_conn or _init_cache()

    # ------------------------------------------------------------------
    # 3a. DNS brute-force (async)
    # ------------------------------------------------------------------

    async def brute_force_dns(
        self,
        domain: str,
        wordlist_path: str | Path | None = None,
    ) -> list[str]:
        """Resolve ``<word>.<domain>`` for every word in the wordlist.

        Runs up to :data:`DNS_CONCURRENCY` queries in parallel using
        ``asyncio``.
        """
        key = _cache_key("dns_brute", domain)
        cached = _cache_get(self._conn, key)
        if cached is not None:
            logger.info("DNS brute cache hit for %s (%d entries)", domain, len(cached))
            return cached

        wl_path = Path(wordlist_path) if wordlist_path else DEFAULT_WORDLIST
        if not wl_path.exists():
            logger.warning("Wordlist not found: %s", wl_path)
            return []

        words = [w.strip() for w in wl_path.read_text().splitlines() if w.strip()]

        semaphore = asyncio.Semaphore(DNS_CONCURRENCY)
        found: list[str] = []
        lock = asyncio.Lock()

        async def _resolve(word: str) -> None:
            fqdn = f"{word}.{domain}"
            async with semaphore:
                try:
                    loop = asyncio.get_running_loop()
                    answers = await loop.run_in_executor(
                        None, lambda: dns.resolver.resolve(fqdn, "A")
                    )
                    if answers:
                        async with lock:
                            found.append(fqdn)
                except Exception:
                    pass

        await asyncio.gather(*[_resolve(w) for w in words])
        found.sort()
        _cache_set(self._conn, key, found)
        return found

    # ------------------------------------------------------------------
    # 3b. Certificate Transparency logs (crt.sh)
    # ------------------------------------------------------------------

    def query_ct_logs(self, domain: str) -> list[str]:
        """Query crt.sh for subdomains appearing in CT logs."""
        key = _cache_key("crtsh", domain)
        cached = _cache_get(self._conn, key)
        if cached is not None:
            logger.info("crt.sh cache hit for %s (%d entries)", domain, len(cached))
            return cached

        try:
            resp = requests.get(
                CRT_SH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                timeout=30,
            )
            resp.raise_for_status()
            entries: list[dict[str, Any]] = resp.json()
        except Exception as exc:
            logger.warning("crt.sh query failed for %s: %s", domain, exc)
            return []

        raw_names: set[str] = set()
        for entry in entries:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and name.endswith(f".{domain}") and "*" not in name:
                    raw_names.add(name)

        result = sorted(raw_names)
        _cache_set(self._conn, key, result)
        return result

    # ------------------------------------------------------------------
    # 3c. Shodan passive DNS
    # ------------------------------------------------------------------

    def query_shodan(self, domain: str, api_key: str = "") -> list[str]:
        """Query Shodan's DNS endpoint for subdomains of *domain*."""
        api_key = api_key or SHODAN_API_KEY
        if not api_key:
            logger.info("No Shodan API key — skipping Shodan subdomain lookup.")
            return []

        key = _cache_key("shodan_dns", domain)
        cached = _cache_get(self._conn, key)
        if cached is not None:
            logger.info("Shodan cache hit for %s (%d entries)", domain, len(cached))
            return cached

        try:
            resp = requests.get(
                f"https://api.shodan.io/dns/domain/{domain}",
                params={"key": api_key},
                timeout=30,
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
        except Exception as exc:
            logger.warning("Shodan DNS query failed for %s: %s", domain, exc)
            return []

        subdomains: list[str] = []
        for record in data.get("subdomains", []):
            fqdn = f"{record}.{domain}"
            subdomains.append(fqdn)

        subdomains.sort()
        _cache_set(self._conn, key, subdomains)
        return subdomains

    # ------------------------------------------------------------------
    # 3d. DNS record lookup (A, MX, NS, TXT)
    # ------------------------------------------------------------------

    @staticmethod
    async def resolve_dns_records(domain: str) -> dict[str, list[str]]:
        """Resolve common DNS record types for *domain* in parallel."""
        record_types = ["A", "MX", "NS", "TXT"]
        results: dict[str, list[str]] = {}
        loop = asyncio.get_running_loop()

        async def _resolve_type(rtype: str) -> tuple[str, list[str]]:
            try:
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(domain, rtype)
                )
                return rtype, [str(rdata) for rdata in answers]
            except Exception:
                return rtype, []

        pairs = await asyncio.gather(*[_resolve_type(rt) for rt in record_types])
        for rtype, records in pairs:
            results[rtype] = records

        return results

    # ------------------------------------------------------------------
    # 3e. Suspicious-record detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_suspicious(
        subdomains: list[str], domain: str
    ) -> list[str]:
        """Flag subdomains that look like typosquatting, dev/staging, or
        dead DNS entries.
        """
        suspicious: list[str] = []
        patterns = [
            r"^(test|dev|staging|internal|debug|temp|tmp)\.",
            r"(phish|spoof|typo|fake)",
            r"\d{5,}",  # long numeric sequences
        ]
        for sub in subdomains:
            label = sub.replace(f".{domain}", "")
            for pat in patterns:
                if re.search(pat, label, re.IGNORECASE):
                    suspicious.append(sub)
                    break
        return suspicious

    # ------------------------------------------------------------------
    # 3f. Full enumeration
    # ------------------------------------------------------------------

    async def enumerate(
        self,
        domain: str,
        wordlist_path: str | Path | None = None,
        shodan_api_key: str = "",
    ) -> EnumerationResult:
        """Run all three enumeration sources in parallel and merge."""
        # Launch brute-force (async) and CT logs + Shodan (sync, via executor)
        loop = asyncio.get_running_loop()

        brute_task = self.brute_force_dns(domain, wordlist_path)
        ct_task = loop.run_in_executor(None, self.query_ct_logs, domain)
        shodan_task = loop.run_in_executor(
            None, self.query_shodan, domain, shodan_api_key
        )
        dns_task = self.resolve_dns_records(domain)

        brute_results, ct_results, shodan_results, dns_records = await asyncio.gather(
            brute_task, ct_task, shodan_task, dns_task
        )

        # Merge & deduplicate
        all_subs: set[str] = set(brute_results) | set(ct_results) | set(shodan_results)
        sorted_subs = sorted(all_subs)
        suspicious = self.detect_suspicious(sorted_subs, domain)

        return EnumerationResult(
            discovered_subdomains=sorted_subs,
            dns_records=dns_records,
            suspicious_records=suspicious,
            source_counts={
                "dns_brute": len(brute_results),
                "ct_logs": len(ct_results),
                "shodan": len(shodan_results),
            },
        )


# ---------------------------------------------------------------------------
# 4. Plugin interface (new-style)
# ---------------------------------------------------------------------------

def metadata() -> dict[str, Any]:
    """Return plugin metadata for the registry."""
    return {
        "name": "subdomain_enum",
        "version": "1.0.0",
        "category": "recon",
        "mitre_techniques": ["T1595.002", "T1596.001"],
        "description": "Subdomain enumeration via DNS brute-force, crt.sh, and Shodan",
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Plugin entry-point called by the engine.

    Reads the target domain from ``context.target_info["domain"]``
    (falls back to ``context.target_info["target"]``).
    """
    domain = context.target_info.get("domain") or context.target_info.get("target", "")
    if not domain:
        return ExecutionResult(success=False, errors=["No domain/target provided"])

    wordlist = context.config.get("wordlist")
    shodan_key = context.config.get("shodan_api_key", "")

    enumerator = SubdomainEnumerator()

    try:
        result: EnumerationResult = asyncio.run(
            enumerator.enumerate(domain, wordlist_path=wordlist, shodan_api_key=shodan_key)
        )
    except Exception as exc:
        logger.exception("Subdomain enumeration failed")
        return ExecutionResult(success=False, errors=[str(exc)])

    output = result.to_dict()

    # Persist to legacy state
    state.set("recon_subdomains", output)

    # Fire event
    bus.publish_sync(Event(
        event_type="recon.subdomains_found",
        payload={
            "domain": domain,
            "count": len(result.discovered_subdomains),
            "subdomains": result.discovered_subdomains,
            "suspicious": result.suspicious_records,
            "source_counts": result.source_counts,
        },
        source="subdomain_enum",
    ))

    console.print(
        f"[green]✔  Subdomain enumeration complete: "
        f"{len(result.discovered_subdomains)} found "
        f"({result.source_counts})[/green]"
    )

    return ExecutionResult(success=True, output=output)


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    ctx = ExecutionContext(phase="recon", target_info={"domain": target})
    res = execute(ctx)
    print(json.dumps(res.output, indent=2))
