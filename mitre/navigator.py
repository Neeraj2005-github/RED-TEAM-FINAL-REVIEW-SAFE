"""
mitre/navigator.py — ATT&CK Navigator layer export for the AI Red Team
Framework.

Generates a JSON file importable into the official MITRE ATT&CK Navigator
(https://mitre-attack.github.io/attack-navigator/) showing which
techniques were used during an engagement, colour-coded by tactic.

Usage::

    from mitre.navigator import generate_navigator_layer
    layer_json = generate_navigator_layer(context, results)

Classes:
    NavigatorTechnique   One technique entry in a Navigator layer
    NavigatorLayer       Full layer structure

Function:
    generate_navigator_layer(context, results) → dict  (also saves .json)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

from config.settings import REPORTS_DIR
from core.plugin_loader import ExecutionContext, ExecutionResult
from core.state_manager import state
from mitre.attack_map import ATTACK_DB, AttackMatrix, AttackTechnique, TechniqueMapper

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Colour scheme — one colour per tactic
# ═══════════════════════════════════════════════════════════════════════════

TACTIC_COLORS: dict[str, str] = {
    "Reconnaissance":       "#2196F3",   # Blue
    "Resource Development": "#1976D2",   # Darker blue
    "Initial Access":       "#4CAF50",   # Green
    "Execution":            "#FFEB3B",   # Yellow
    "Persistence":          "#F44336",   # Red
    "Privilege Escalation": "#FF9800",   # Orange
    "Defense Evasion":      "#9E9E9E",   # Grey
    "Credential Access":    "#E91E63",   # Pink
    "Discovery":            "#00BCD4",   # Cyan
    "Lateral Movement":     "#9C27B0",   # Purple
    "Collection":           "#795548",   # Brown
    "Command and Control":  "#607D8B",   # Blue grey
    "Exfiltration":         "#FF5722",   # Deep orange
    "Impact":               "#B71C1C",   # Dark red
}

DEFAULT_COLOR = "#BDBDBD"  # light grey


# ═══════════════════════════════════════════════════════════════════════════
# 2. Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class NavigatorTechnique:
    """One technique entry inside a Navigator layer."""

    techniqueID: str = ""          # e.g. "T1046"
    tactic: str = ""               # e.g. "discovery"  (lowercase, hyphenated)
    score: int = 50                # 1-100 intensity
    color: str = ""                # hex colour
    comment: str = ""              # free-text
    enabled: bool = True
    showSubtechniques: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NavigatorLayer:
    """Complete ATT&CK Navigator layer (schema v4.5)."""

    name: str = "Red Team Execution"
    description: str = ""
    domain: str = "enterprise-attack"
    versions: dict[str, str] = field(default_factory=lambda: {
        "attack": "14",
        "navigator": "4.9.5",
        "layer": "4.5",
    })
    techniques: list[NavigatorTechnique] = field(default_factory=list)
    gradient: dict[str, Any] = field(default_factory=lambda: {
        "colors": ["#ffffff", "#ff6666"],
        "minValue": 0,
        "maxValue": 100,
    })
    legendItems: list[dict[str, str]] = field(default_factory=list)
    showTacticRowBackground: bool = True
    tacticRowBackground: str = "#205b8f"
    selectTechniquesAcrossTactics: bool = True
    selectSubtechniquesWithParent: bool = False

    # ── helpers ───────────────────────────────────────────────────────

    def add_technique(
        self,
        attack_tech: AttackTechnique,
        *,
        score: int = 80,
        comment: str = "",
        success: bool = True,
    ) -> None:
        """Add an AttackTechnique to the layer."""
        colour = TACTIC_COLORS.get(attack_tech.tactic, DEFAULT_COLOR)
        if not success:
            score = max(score // 3, 1)

        # Navigator expects tactic as lowercase-hyphenated slug
        tactic_slug = attack_tech.tactic.lower().replace(" ", "-")

        self.techniques.append(NavigatorTechnique(
            techniqueID=attack_tech.technique_id,
            tactic=tactic_slug,
            score=score,
            color=colour if success else "#BDBDBD",
            comment=comment or f"{'✔ Success' if success else '✘ Failed'}",
        ))

    def to_json(self) -> dict[str, Any]:
        """Return the layer as a plain dict ready for ``json.dumps``."""
        return {
            "name": self.name,
            "versions": self.versions,
            "domain": self.domain,
            "description": self.description,
            "techniques": [t.to_dict() for t in self.techniques],
            "gradient": self.gradient,
            "legendItems": self.legendItems or _default_legend(),
            "showTacticRowBackground": self.showTacticRowBackground,
            "tacticRowBackground": self.tacticRowBackground,
            "selectTechniquesAcrossTactics": self.selectTechniquesAcrossTactics,
            "selectSubtechniquesWithParent": self.selectSubtechniquesWithParent,
        }


def _default_legend() -> list[dict[str, str]]:
    """Build a legend mapping tactic → colour."""
    return [
        {"label": tactic, "color": color}
        for tactic, color in TACTIC_COLORS.items()
    ]


# ═══════════════════════════════════════════════════════════════════════════
# 3. Generator function
# ═══════════════════════════════════════════════════════════════════════════

def generate_navigator_layer(
    context: ExecutionContext | None = None,
    matrix: AttackMatrix | None = None,
    *,
    target: str = "",
    save: bool = True,
    filter_tactic: str = "",
    filter_success: bool | None = None,
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer from an :class:`AttackMatrix`.

    Parameters
    ----------
    context : ExecutionContext, optional
        Execution context (used for target info).
    matrix : AttackMatrix, optional
        Pre-built matrix.  If ``None``, one is read from state.
    target : str
        Override target name for the layer title.
    save : bool
        Whether to write a ``.json`` file to ``REPORTS_DIR``.
    filter_tactic : str
        If set, only include techniques from this tactic.
    filter_success : bool or None
        ``True`` → only successes, ``False`` → only failures, ``None`` → all.

    Returns
    -------
    dict
        The Navigator layer JSON, importable at
        https://mitre-attack.github.io/attack-navigator/
    """
    if target == "" and context:
        target = context.target_info.get("target", "")
    if not target:
        target = state.get("target", "unknown")

    # Build or load matrix
    if matrix is None:
        matrix_data = state.get("attack_matrix", {})
        matrix = AttackMatrix()
        mapper = TechniqueMapper()
        for t_dict in matrix_data.get("techniques_executed", []):
            tid = t_dict.get("technique_id", "")
            tech = mapper.map_technique_id(tid)
            if tech:
                matrix.add_technique(tech)

    # Construct layer
    layer = NavigatorLayer(
        name=f"Red Team Execution — {target}",
        description=(
            f"Auto-generated ATT&CK Navigator layer for engagement "
            f"against {target} on {datetime.utcnow().strftime('%Y-%m-%d')}."
        ),
    )

    for tech in matrix.techniques_executed:
        if filter_tactic and tech.tactic.lower() != filter_tactic.lower():
            continue
        layer.add_technique(tech, score=80, success=True)

    layer_json = layer.to_json()

    # Save to file
    if save:
        os.makedirs(str(REPORTS_DIR), exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filepath = str(REPORTS_DIR / f"navigator_layer_{ts}.json")
        with open(filepath, "w") as fh:
            json.dump(layer_json, fh, indent=2)
        logger.info("Navigator layer saved to %s", filepath)

    return layer_json


# ═══════════════════════════════════════════════════════════════════════════
# 4. Plugin interface
# ═══════════════════════════════════════════════════════════════════════════

def metadata() -> dict[str, Any]:
    return {
        "name": "navigator",
        "version": "1.0.0",
        "category": "mitre",
        "description": (
            "Export engagement as an ATT&CK Navigator JSON layer "
            "importable at https://mitre-attack.github.io/attack-navigator/"
        ),
        "dependencies": [],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Generate and persist a Navigator layer from current state."""
    layer_json = generate_navigator_layer(context, save=True)
    state.set("navigator_layer", layer_json)
    return ExecutionResult(
        success=True,
        output=layer_json,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Stand-alone
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    from core.state_manager import state as _st
    _target = sys.argv[1] if len(sys.argv) > 1 else _st.target_ip or "<TARGET>"
    ctx = ExecutionContext(phase="reporting", target_info={"target": _target})
    res = execute(ctx)
    print(json.dumps(res.output, indent=2))
