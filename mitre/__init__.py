"""
mitre — MITRE ATT&CK integration for the AI Red Team Framework.

Modules:
    attack_map     Technique database and action-to-technique mapping
    navigator      ATT&CK Navigator JSON layer export
"""

from pathlib import Path

CACHE_DIR: Path = Path(__file__).resolve().parent.parent / ".cache"
CACHE_DIR.mkdir(exist_ok=True)
