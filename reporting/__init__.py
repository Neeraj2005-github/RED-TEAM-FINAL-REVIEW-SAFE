"""
reporting — Reporting and visualization for the AI Red Team Framework.

Modules:
    attack_graph       NetworkX-based attack-path graph with export to JSON/DOT/PNG
    report_generator   Comprehensive HTML + JSON report generation
"""

from pathlib import Path

CACHE_DIR: Path = Path(__file__).resolve().parent.parent / ".cache"
CACHE_DIR.mkdir(exist_ok=True)
