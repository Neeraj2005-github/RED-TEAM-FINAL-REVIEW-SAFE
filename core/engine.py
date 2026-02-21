"""
core/engine.py — Main orchestrator for the AI Red Team Framework.

Runs all assessment phases through a **plugin architecture** with:

* :mod:`core.attack_lifecycle` — phase state-machine
* :mod:`core.event_bus`        — async pub/sub for cross-module events
* :mod:`core.plugin_loader`    — dynamic module discovery (no hard-coded imports)

Supports both:
  * Legacy CLI: ``run_pipeline(target, verbose, skip_recon, wordlist)``
  * Config-driven: ``run_pipeline(target, ..., config=ConfigManager(…))``
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import sys
import time
import traceback
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel

from core.attack_lifecycle import AttackState, Phase
from core.event_bus import Event, bus
from core.network_validator import validate_target
from core.plugin_loader import (
    ExecutionContext,
    ExecutionResult,
    PluginModule,
    load_all_plugins,
    registry,
)
from core.state_manager import state

logger = logging.getLogger(__name__)
console = Console()

# Optional import — ConfigManager may not yet exist when running legacy mode
try:
    from config.settings import ConfigManager as _ConfigManager  # noqa: F401
except ImportError:  # pragma: no cover
    _ConfigManager = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Part 1 — Scope enforcement (MANDATORY SAFETY)
# ---------------------------------------------------------------------------

ALLOWED_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def _load_scope_ranges(config: Any = None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Build allowed-ranges list, merging config & defaults."""
    ranges = list(ALLOWED_RANGES)
    if config is not None and hasattr(config, "get"):
        extra = config.get("scope.include_ips", [])
        if isinstance(extra, list):
            for cidr in extra:
                try:
                    ranges.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
    return ranges


def enforce_scope(target: str) -> bool:
    """Return True if *target* is a domain or an IP inside ALLOWED_RANGES.

    Prints red error messages and returns False when the IP falls outside
    the permitted private/loopback ranges.
    """
    raw_ip = target.split("/")[0]
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        # Not a valid IP — treat as a domain name and allow.
        return True

    allowed = _load_scope_ranges()
    for network in allowed:
        if addr in network:
            return True

    console.print(
        "[bold red]ERROR: Target is outside allowed scope![/bold red]"
    )
    console.print(
        "[red]This tool is for authorised lab / test-environment use only.[/red]"
    )
    console.print(
        f"[red]Target {target} does not fall within any allowed range:[/red]"
    )
    for net in _load_scope_ranges():
        console.print(f"[red]  • {net}[/red]")
    return False


# ---------------------------------------------------------------------------
# Part 2 — CLI with argparse
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the framework CLI."""
    parser = argparse.ArgumentParser(
        description="AI-Powered Red Team Framework — Automated Penetration Testing Pipeline",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address, CIDR range, or domain name",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="Enable verbose output",
    )
    parser.add_argument(
        "--skip-recon",
        action="store_true",
        default=False,
        help="Skip the reconnaissance phase",
    )
    parser.add_argument(
        "--wordlist",
        type=str,
        default=None,
        help="Path to a custom wordlist file",
    )
    return parser


# ---------------------------------------------------------------------------
# Part 3 — Phase ↔ plugin mapping
# ---------------------------------------------------------------------------

# Each lifecycle phase maps to an ordered list of plugin names that should
# be executed.  The plugin_loader discovers these at runtime from the
# ``modules/`` directory (and optional extra dirs), so the engine never
# hard-codes ``from modules import …``.

PHASE_PLUGINS: dict[Phase, list[str]] = {
    Phase.RECON:         ["recon"],
    Phase.SCANNING:      ["scanner"],
    Phase.ANALYSIS:      ["ai_decision"],
    Phase.EXPLOITATION:  ["exploit"],
    Phase.POST_EXPLOIT:  ["privesc", "persistence"],
    Phase.REPORTING:     ["reporter"],
}

# Phases that may be run in parallel (async gather).
_PARALLEL_PHASES: set[Phase] = {Phase.RECON}


# ---------------------------------------------------------------------------
# Part 4 — ExecutionContext builder
# ---------------------------------------------------------------------------

def _build_context(
    attack_state: AttackState,
    phase: Phase,
    extra_config: dict[str, Any] | None = None,
    config_manager: Any = None,
) -> ExecutionContext:
    """Create an :class:`ExecutionContext` from the current lifecycle state.

    When a *config_manager* (:class:`ConfigManager`) is provided its full
    dict representation is merged into the context ``config`` so plugins
    can read typed settings via ``context.config``.
    """
    cfg: dict[str, Any] = {}
    if config_manager is not None and hasattr(config_manager, "to_dict"):
        cfg = config_manager.to_dict()
    if extra_config:
        cfg.update(extra_config)

    return ExecutionContext(
        phase=phase.value,
        target_info=dict(attack_state.target_info),
        previous_results=dict(attack_state.phase_results),
        config=cfg,
    )


# ---------------------------------------------------------------------------
# Part 5 — Single-phase runner (sync + async variants)
# ---------------------------------------------------------------------------

def _run_plugin_sync(
    plugin: PluginModule,
    context: ExecutionContext,
    attack_state: AttackState,
    phase: Phase,
    verbose: bool,
) -> ExecutionResult:
    """Execute *plugin* synchronously, publish events, and update state."""
    start = time.time()
    phase_label = f"{phase.value}/{plugin.name}"

    console.print(f"\n[bold blue]▶ Running {phase_label}…[/bold blue]")

    try:
        result = plugin.execute(context)
        elapsed = time.time() - start
        console.print(
            f"[bold green]✓ {phase_label} completed in {elapsed:.1f}s[/bold green]"
        )

        # Store result data in the lifecycle state
        attack_state.update_phase_data(plugin.name, result.output)

        # Publish completion event
        bus.publish_sync(Event(
            event_type=f"{phase.value}.complete",
            payload={"plugin": plugin.name, "success": result.success, "output": result.output},
            source=plugin.name,
        ))

        return result

    except Exception as exc:
        elapsed = time.time() - start
        console.print(
            f"[bold red]✗ {phase_label} FAILED after {elapsed:.1f}s: {exc}[/bold red]"
        )
        if verbose:
            traceback.print_exc()

        bus.publish_sync(Event(
            event_type="phase.error",
            payload={"plugin": plugin.name, "error": str(exc)},
            source=plugin.name,
        ))

        return ExecutionResult(success=False, errors=[str(exc)])


async def _run_plugins_async(
    plugins: list[PluginModule],
    context: ExecutionContext,
    attack_state: AttackState,
    phase: Phase,
    verbose: bool,
) -> list[ExecutionResult]:
    """Run a list of plugins concurrently using ``asyncio``."""

    async def _run_one(plugin: PluginModule) -> ExecutionResult:
        # Wrapping sync code in a thread so it doesn't block the loop.
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            _run_plugin_sync,
            plugin,
            context,
            attack_state,
            phase,
            verbose,
        )

    return list(await asyncio.gather(*[_run_one(p) for p in plugins]))


# ---------------------------------------------------------------------------
# Part 6 — Main pipeline
# ---------------------------------------------------------------------------

# The ordered list of phases the pipeline will walk through.
_PIPELINE_PHASES: list[Phase] = [
    Phase.RECON,
    Phase.SCANNING,
    Phase.ANALYSIS,
    Phase.EXPLOITATION,
    Phase.POST_EXPLOIT,
    Phase.REPORTING,
]

# Legacy phase display names (for backward-compatible output messages).
_PHASE_DISPLAY: dict[Phase, str] = {
    Phase.RECON:         "Phase 1: Reconnaissance",
    Phase.SCANNING:      "Phase 2: Port Scanning",
    Phase.ANALYSIS:      "Phase 3a: AI Decision Engine",
    Phase.EXPLOITATION:  "Phase 3b: Exploitation",
    Phase.POST_EXPLOIT:  "Phase 4: Post-Exploitation",
    Phase.REPORTING:     "Phase 5: Report Generation",
}


def run_pipeline(
    target: str,
    verbose: bool = False,
    skip_recon: bool = False,
    wordlist: Optional[str] = None,
    config: Any = None,
) -> dict[str, Any]:
    """Execute every assessment phase in order with rich progress output.

    Parameters
    ----------
    target : str
        IP, CIDR, or domain.
    verbose : bool
        Enable debug output.
    skip_recon : bool
        Skip the reconnaissance phase.
    wordlist : str, optional
        Custom wordlist path.
    config : ConfigManager, optional
        Fully-resolved configuration object.  When provided the engine
        reads timeouts, module toggles, and security settings from it.
        Legacy callers that omit *config* keep working as before.
    """
    # If a ConfigManager is provided, log its key settings
    if config is not None and hasattr(config, "get"):
        logger.info(
            "Config-driven run: target=%s  dry_run=%s  safe_mode=%s  log_level=%s",
            config.get("general.target", target),
            config.get("security.dry_run", "?"),
            config.get("security.safe_mode", "?"),
            config.get("general.log_level", "?"),
        )

    # --- Scope gate ---
    if not enforce_scope(target):
        console.print("[bold red]Aborting: target out of scope.[/bold red]")
        sys.exit(1)

    # --- Reset state from any previous run so stale data never leaks ---
    state.reset()
    state.target_ip = target
    if wordlist:
        state.set("custom_wordlist", wordlist)

    # --- Initialise lifecycle state machine ---
    attack_state = AttackState()
    attack_state.target_info = {"target": target}
    if wordlist:
        attack_state.target_info["wordlist"] = wordlist

    # --- Discover and register all plugins ---
    load_all_plugins()

    # --- Start banner ---
    logger.info("[INFO] Target: %s", target)
    console.print(
        Panel.fit(
            f"[bold red]🔴 AI RED TEAM FRAMEWORK[/bold red]\n"
            f"[yellow]Target: {target}[/yellow]",
            title="INITIALIZING",
            border_style="red",
        )
    )

    # --- Network validation (before exploitation) ---
    validate_target(target)

    bus.publish_sync(Event("phase.transition", {"from": "init", "to": "pipeline_start"}))

    extra_config: dict[str, Any] = {}
    if wordlist:
        extra_config["wordlist"] = wordlist

    results: dict[str, Any] = {}

    for phase in _PIPELINE_PHASES:
        display = _PHASE_DISPLAY.get(phase, phase.value)

        # --- Skip logic ---
        if phase == Phase.RECON and skip_recon:
            console.print(f"[yellow]⏭  Skipping {display}[/yellow]")
            bus.publish_sync(Event("phase.skipped", {"phase": phase.value}))
            # Jump directly to SCANNING (valid transition from INIT)
            attack_state.transition_to_phase(Phase.SCANNING)
            continue

        # --- Resolve plugins for this phase ---
        plugin_names = PHASE_PLUGINS.get(phase, [])
        plugins: list[PluginModule] = []
        for name in plugin_names:
            p = registry.get_by_name(name)
            if p is not None:
                plugins.append(p)
            else:
                console.print(f"[dim]  Plugin '{name}' not found — skipping[/dim]")

        if not plugins:
            console.print(f"[yellow]⚠  No plugins for {display} — skipping phase[/yellow]")
            continue

        # --- Transition the state machine ---
        if phase == Phase.RECON:
            attack_state.transition_to_phase(Phase.RECON)
        elif phase == Phase.SCANNING:
            # When skip_recon=True we already transitioned to SCANNING earlier.
            # Otherwise this is a normal RECON→SCANNING transition.
            if attack_state.current_phase != Phase.SCANNING:
                attack_state.transition_to_phase(Phase.SCANNING)
        else:
            if not attack_state.transition_to_phase(phase):
                console.print(
                    f"[yellow]⚠  Invalid phase transition to {phase.value} "
                    f"(current={attack_state.current_phase.value}) — skipping[/yellow]"
                )
                continue

        context = _build_context(attack_state, phase, extra_config, config_manager=config)

        # --- Execute plugins (parallel for recon, sequential otherwise) ---
        phase_start = time.time()

        if phase in _PARALLEL_PHASES and len(plugins) > 1:
            console.print(
                f"\n[bold blue]▶ Starting {display} "
                f"({len(plugins)} plugins, parallel)…[/bold blue]"
            )
            phase_results = asyncio.run(
                _run_plugins_async(plugins, context, attack_state, phase, verbose)
            )
        else:
            phase_results = [
                _run_plugin_sync(p, context, attack_state, phase, verbose)
                for p in plugins
            ]

        elapsed = time.time() - phase_start
        any_success = any(r.success for r in phase_results)
        results[display] = {
            "success": any_success,
            "elapsed": round(elapsed, 1),
            "plugins": [
                {"name": p.name, "success": r.success, "errors": r.errors}
                for p, r in zip(plugins, phase_results)
            ],
        }

        # Persist lifecycle state after every phase
        attack_state.persist()

    # --- Final transition ---
    attack_state.transition_to_phase(Phase.COMPLETE)
    attack_state.persist()

    # --- End banner ---
    console.print(
        Panel.fit(
            "[bold green]✅ PIPELINE COMPLETE[/bold green]\n"
            "Check reports/ directory for output",
            title="DONE",
            border_style="green",
        )
    )

    bus.publish_sync(Event("phase.transition", {"from": "pipeline", "to": "complete"}))

    return results


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse CLI arguments and launch the pipeline.

    Target can come from:
      1. ``--target`` CLI flag
      2. ``config.yaml``  (``general.target``)
      3. Interactive prompt (if both above are missing)

    For config-driven execution prefer ``cli.py`` which loads the
    full :class:`ConfigManager`.  This entry-point is kept for
    backward-compatible ``python -m core.engine --target …`` usage.
    """
    parser = build_parser()
    # Make --target optional so we can fall back to config / prompt
    parser._option_string_actions["--target"].required = False
    args = parser.parse_args()

    target = args.target

    # Fallback 1: read from config
    if not target:
        try:
            from config.settings import get_config
            cfg = get_config()
            target = cfg.get("general.target", "")
        except Exception:
            pass

    # Fallback 2: interactive prompt
    if not target:
        target = console.input("[bold yellow]Enter target IP/domain: [/bold yellow]").strip()

    if not target:
        console.print("[red]✘  No target provided. Exiting.[/red]")
        sys.exit(1)

    run_pipeline(
        target=target,
        verbose=args.verbose,
        skip_recon=args.skip_recon,
        wordlist=args.wordlist,
    )


if __name__ == "__main__":
    main()
