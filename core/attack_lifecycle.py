"""
core/attack_lifecycle.py — Phase state-machine for the AI Red Team Framework.

Manages the attack-assessment lifecycle through well-defined phases with
validated transitions, timestamp tracking, and full serialisation to
``db/state.json``.

Phases:
  INIT → RECON → SCANNING → ANALYSIS → EXPLOITATION → POST_EXPLOIT → REPORTING → COMPLETE
"""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

from core.state_manager import state


# ---------------------------------------------------------------------------
# 1. Phase Enum
# ---------------------------------------------------------------------------

class Phase(Enum):
    """Ordered assessment phases."""

    INIT = "init"
    RECON = "recon"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    EXPLOITATION = "exploitation"
    POST_EXPLOIT = "post_exploit"
    REPORTING = "reporting"
    COMPLETE = "complete"


# Allowed forward transitions — each phase maps to the set of phases it
# may legally transition to.  ``INIT`` can jump to ``RECON`` or
# ``SCANNING`` (when recon is skipped).
_VALID_TRANSITIONS: dict[Phase, set[Phase]] = {
    Phase.INIT:          {Phase.RECON, Phase.SCANNING},
    Phase.RECON:         {Phase.SCANNING},
    Phase.SCANNING:      {Phase.ANALYSIS},
    Phase.ANALYSIS:      {Phase.EXPLOITATION},
    Phase.EXPLOITATION:  {Phase.POST_EXPLOIT},
    Phase.POST_EXPLOIT:  {Phase.REPORTING},
    Phase.REPORTING:     {Phase.COMPLETE},
    Phase.COMPLETE:      set(),  # terminal
}

# Mapping from legacy engine phase-name keys to Phase enum members so
# that ``db/state.json`` written by the old engine can still be loaded.
_LEGACY_PHASE_MAP: dict[str, Phase] = {
    "Phase 1: Reconnaissance": Phase.RECON,
    "Phase 2: Port Scanning": Phase.SCANNING,
    "Phase 3a: AI Decision Engine": Phase.ANALYSIS,
    "Phase 3b: Exploitation": Phase.EXPLOITATION,
    "Phase 4a: Privilege Escalation": Phase.POST_EXPLOIT,
    "Phase 4b: Persistence Simulation": Phase.POST_EXPLOIT,
    "Phase 5: Report Generation": Phase.REPORTING,
}


# ---------------------------------------------------------------------------
# 2. AttackState dataclass
# ---------------------------------------------------------------------------

@dataclass
class AttackState:
    """Mutable state container that tracks every aspect of an assessment run."""

    current_phase: Phase = Phase.INIT
    target_info: dict[str, Any] = field(default_factory=dict)
    discovered_vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    executed_techniques: list[dict[str, Any]] = field(default_factory=list)
    phase_results: dict[str, Any] = field(default_factory=dict)
    phase_timestamps: dict[str, str] = field(default_factory=dict)
    # Stack of previous snapshots for rollback support.
    _history: list[dict[str, Any]] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------
    # Transition helpers
    # ------------------------------------------------------------------

    @staticmethod
    def is_valid_transition(current: Phase, next_phase: Phase) -> bool:
        """Return *True* if moving from *current* to *next_phase* is legal."""
        return next_phase in _VALID_TRANSITIONS.get(current, set())

    def transition_to_phase(self, next_phase: Phase) -> bool:
        """Attempt to move to *next_phase*.

        Saves a snapshot for rollback, updates the current phase, and
        records a timestamp.  Returns ``False`` without mutating state
        when the transition is invalid.
        """
        if not self.is_valid_transition(self.current_phase, next_phase):
            return False

        # Snapshot before mutation
        self._history.append(self._snapshot())

        self.current_phase = next_phase
        self.phase_timestamps[next_phase.value] = datetime.utcnow().isoformat()
        return True

    # ------------------------------------------------------------------
    # Data accessors
    # ------------------------------------------------------------------

    def update_phase_data(self, key: str, value: Any) -> None:
        """Store *value* under *key* in the current phase's results bucket."""
        phase_key = self.current_phase.value
        if phase_key not in self.phase_results:
            self.phase_results[phase_key] = {}
        self.phase_results[phase_key][key] = value

    def get_phase_results(self, phase: Phase) -> dict[str, Any]:
        """Return the results dict for a given *phase*, or ``{}``."""
        return self.phase_results.get(phase.value, {})

    def add_vulnerability(self, vuln: dict[str, Any]) -> None:
        """Append a vulnerability finding to the global list."""
        self.discovered_vulnerabilities.append(vuln)

    def add_technique(self, technique: dict[str, Any]) -> None:
        """Record an executed MITRE ATT&CK technique."""
        self.executed_techniques.append(technique)

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    def rollback(self) -> bool:
        """Revert to the most recent snapshot.  Returns ``False`` when
        there is nothing to roll back to.
        """
        if not self._history:
            return False
        snapshot = self._history.pop()
        self._restore(snapshot)
        return True

    # ------------------------------------------------------------------
    # Serialisation — compatible with legacy ``db/state.json`` layout
    # ------------------------------------------------------------------

    def serialize_to_json(self) -> dict[str, Any]:
        """Return a JSON-safe dict that can be written to ``db/state.json``.

        The output includes legacy top-level keys (``target``,
        ``recon``, ``scan_results``, etc.) so downstream code that reads
        the file directly keeps working.
        """
        # Build the canonical lifecycle payload
        data: dict[str, Any] = {
            "current_phase": self.current_phase.value,
            "target_info": self.target_info,
            "discovered_vulnerabilities": self.discovered_vulnerabilities,
            "executed_techniques": self.executed_techniques,
            "phase_results": self.phase_results,
            "phase_timestamps": self.phase_timestamps,
        }

        # --- Backward-compatible top-level keys ---
        data["target"] = self.target_info.get("target")
        data["recon"] = self.phase_results.get(Phase.RECON.value, {})
        data["scan_results"] = self.phase_results.get(Phase.SCANNING.value, {}).get(
            "scan_results", {}
        )
        data["ai_decisions"] = self.phase_results.get(Phase.ANALYSIS.value, {}).get(
            "ai_decisions", []
        )
        data["exploit_results"] = self.phase_results.get(Phase.EXPLOITATION.value, {}).get(
            "exploit_results", []
        )
        data["session_info"] = self.phase_results.get(Phase.EXPLOITATION.value, {}).get(
            "session_info", {}
        )
        data["privesc_results"] = self.phase_results.get(Phase.POST_EXPLOIT.value, {}).get(
            "privesc_results", {}
        )
        data["persistence_simulated"] = self.phase_results.get(Phase.POST_EXPLOIT.value, {}).get(
            "persistence_simulated", []
        )

        return data

    @classmethod
    def deserialize_from_json(cls, data: dict[str, Any]) -> "AttackState":
        """Reconstruct an ``AttackState`` from a previously serialised dict.

        Handles both the new lifecycle format **and** legacy flat
        ``db/state.json`` files produced by the old engine.
        """
        obj = cls()

        if "current_phase" in data:
            # New-format payload
            try:
                obj.current_phase = Phase(data["current_phase"])
            except ValueError:
                obj.current_phase = Phase.INIT
            obj.target_info = data.get("target_info", {})
            obj.discovered_vulnerabilities = data.get("discovered_vulnerabilities", [])
            obj.executed_techniques = data.get("executed_techniques", [])
            obj.phase_results = data.get("phase_results", {})
            obj.phase_timestamps = data.get("phase_timestamps", {})
        else:
            # Legacy format — reconstruct from flat keys
            target = data.get("target")
            obj.target_info = {"target": target} if target else {}

            if data.get("recon"):
                obj.phase_results[Phase.RECON.value] = data["recon"]
            if data.get("scan_results"):
                obj.phase_results[Phase.SCANNING.value] = {
                    "scan_results": data["scan_results"]
                }
            if data.get("ai_decisions"):
                obj.phase_results[Phase.ANALYSIS.value] = {
                    "ai_decisions": data["ai_decisions"]
                }
            exploit_data: dict[str, Any] = {}
            if data.get("exploit_results"):
                exploit_data["exploit_results"] = data["exploit_results"]
            if data.get("session_info"):
                exploit_data["session_info"] = data["session_info"]
            if exploit_data:
                obj.phase_results[Phase.EXPLOITATION.value] = exploit_data

            post: dict[str, Any] = {}
            if data.get("privesc_results"):
                post["privesc_results"] = data["privesc_results"]
            if data.get("persistence_simulated"):
                post["persistence_simulated"] = data["persistence_simulated"]
            if post:
                obj.phase_results[Phase.POST_EXPLOIT.value] = post

            # Guess current phase from what data was populated
            obj.current_phase = Phase.INIT
            for legacy_name in reversed(list(_LEGACY_PHASE_MAP)):
                phase = _LEGACY_PHASE_MAP[legacy_name]
                if phase.value in obj.phase_results:
                    obj.current_phase = phase
                    break

        return obj

    # ------------------------------------------------------------------
    # Persist / load via StateManager (convenience wrappers)
    # ------------------------------------------------------------------

    def persist(self) -> None:
        """Write the full serialised state to ``db/state.json`` through
        the existing :class:`~core.state_manager.StateManager`.
        """
        payload = self.serialize_to_json()
        for key, value in payload.items():
            state.set(key, value)

    @classmethod
    def load(cls) -> "AttackState":
        """Load the current ``db/state.json`` and return an ``AttackState``."""
        # Read every key from the state manager into a flat dict
        raw: dict[str, Any] = {}
        for key in (
            "target", "current_phase", "target_info",
            "discovered_vulnerabilities", "executed_techniques",
            "phase_results", "phase_timestamps",
            "recon", "scan_results", "ai_decisions",
            "exploit_results", "session_info",
            "privesc_results", "persistence_simulated",
        ):
            val = state.get(key)
            if val is not None:
                raw[key] = val
        return cls.deserialize_from_json(raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _snapshot(self) -> dict[str, Any]:
        """Return a deep-copy dict of all mutable fields (excludes _history)."""
        return {
            "current_phase": self.current_phase,
            "target_info": copy.deepcopy(self.target_info),
            "discovered_vulnerabilities": copy.deepcopy(self.discovered_vulnerabilities),
            "executed_techniques": copy.deepcopy(self.executed_techniques),
            "phase_results": copy.deepcopy(self.phase_results),
            "phase_timestamps": copy.deepcopy(self.phase_timestamps),
        }

    def _restore(self, snapshot: dict[str, Any]) -> None:
        """Overwrite mutable fields from *snapshot*."""
        self.current_phase = snapshot["current_phase"]
        self.target_info = snapshot["target_info"]
        self.discovered_vulnerabilities = snapshot["discovered_vulnerabilities"]
        self.executed_techniques = snapshot["executed_techniques"]
        self.phase_results = snapshot["phase_results"]
        self.phase_timestamps = snapshot["phase_timestamps"]
