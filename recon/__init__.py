"""
recon — Reconnaissance plugin modules for the AI Red Team Framework.

Modules in this package are auto-discovered by
:func:`core.plugin_loader.load_all_plugins` and registered under the
``recon`` category.

Available plugins:
    subdomain_enum   Subdomain enumeration (DNS brute-force, crt.sh, Shodan)
    port_scanner     Async Nmap wrapper for parallel port scanning
    vuln_scanner     NVD / searchsploit CVE mapping
    web_recon        Web technology detection & directory brute-force
    os_fingerprint   OS detection, banner grabbing, SMB enumeration
"""

from pathlib import Path

# Ensure the .cache/ directory exists at import time so every module in
# this package can rely on it.
CACHE_DIR: Path = Path(__file__).resolve().parent.parent / ".cache"
CACHE_DIR.mkdir(exist_ok=True)
