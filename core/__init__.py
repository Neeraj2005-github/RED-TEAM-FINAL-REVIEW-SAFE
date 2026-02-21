"""
core — AI Red Team Framework internals.

Public API re-exports for convenience::

    from core import AttackState, Phase, bus, Event, registry
"""

from core.attack_lifecycle import AttackState, Phase
from core.event_bus import Event, EventBus, bus
from core.plugin_loader import (
    ExecutionContext,
    ExecutionResult,
    ModuleRegistry,
    PluginModule,
    load_all_plugins,
    registry,
)
from core.state_manager import StateManager, state

__all__ = [
    "AttackState",
    "Phase",
    "Event",
    "EventBus",
    "bus",
    "ExecutionContext",
    "ExecutionResult",
    "ModuleRegistry",
    "PluginModule",
    "load_all_plugins",
    "registry",
    "StateManager",
    "state",
]
