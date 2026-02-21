#!/usr/bin/env python3
"""
cli.py — Command-line interface for the AI Red Team Framework.

Loads configuration from YAML → env vars → CLI args (highest priority),
validates settings, and launches the attack pipeline.

Usage::

    python cli.py --target 192.168.1.1
    python cli.py --target 10.0.0.5 --dry-run --fast
    python cli.py --config custom.yaml --validate-only
    python cli.py --print-config
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from rich.console import Console

console = Console()
logger = logging.getLogger("cli")


# ---------------------------------------------------------------------------
# 1. Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the full argparse parser with all supported flags."""
    parser = argparse.ArgumentParser(
        prog="redteam",
        description=(
            "AI-Powered Red Team Framework — "
            "Automated Penetration Testing Pipeline"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Environment variable overrides:\n"
            "  REDTEAM_GENERAL_TARGET=10.0.0.5\n"
            "  REDTEAM_SECURITY_DRY_RUN=true\n"
            "  REDTEAM_TIMEOUT_SCAN_TIMEOUT=900\n"
        ),
    )

    # ── Target & paths ────────────────────────────────────────────────
    parser.add_argument(
        "--target", "-t",
        type=str,
        default=None,
        help="Target IP, CIDR range, or domain name (overrides config)",
    )
    parser.add_argument(
        "--config", "-c",
        type=str,
        default=None,
        help="Path to YAML config file (default: config/config.yaml)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        type=str,
        default=None,
        help="Output directory for reports (default: reports/)",
    )

    # ── Logging ───────────────────────────────────────────────────────
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Logging verbosity (default: from config or INFO)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Shortcut for --log-level DEBUG",
    )

    # ── Safety flags ──────────────────────────────────────────────────
    safety = parser.add_argument_group("safety controls")
    safety.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Simulate only — no real network traffic (sets security.dry_run=true)",
    )
    safety.add_argument(
        "--safe-mode",
        action="store_true",
        default=False,
        help="Skip destructive exploits (sets security.safe_mode=true)",
    )
    safety.add_argument(
        "--unsafe",
        action="store_true",
        default=False,
        help="Disable safe mode (sets security.safe_mode=false)",
    )

    # ── Speed profiles ────────────────────────────────────────────────
    speed = parser.add_argument_group("speed profiles")
    speed_group = speed.add_mutually_exclusive_group()
    speed_group.add_argument(
        "--fast",
        action="store_true",
        default=False,
        help="Aggressive: higher parallelisation, shorter timeouts",
    )
    speed_group.add_argument(
        "--slow",
        action="store_true",
        default=False,
        help="Stealthy: lower parallelisation, longer delays",
    )

    # ── Workflow ──────────────────────────────────────────────────────
    workflow = parser.add_argument_group("workflow")
    workflow.add_argument(
        "--skip-recon",
        action="store_true",
        default=False,
        help="Skip the reconnaissance phase entirely",
    )
    workflow.add_argument(
        "--wordlist",
        type=str,
        default=None,
        help="Path to a custom wordlist file",
    )

    # ── Info-only commands ────────────────────────────────────────────
    info = parser.add_argument_group("info / diagnostics")
    info.add_argument(
        "--validate-only",
        action="store_true",
        default=False,
        help="Validate configuration and exit (no attack)",
    )
    info.add_argument(
        "--print-config",
        action="store_true",
        default=False,
        help="Print resolved configuration summary and exit",
    )

    return parser


# ---------------------------------------------------------------------------
# 2. Build CLI overrides dict
# ---------------------------------------------------------------------------

def _build_overrides(args: argparse.Namespace) -> dict[str, Any]:
    """Translate argparse flags into a ``section.key`` override dict."""
    overrides: dict[str, Any] = {}

    if args.target:
        overrides["general.target"] = args.target
    if args.output_dir:
        overrides["general.output_dir"] = args.output_dir
    if args.log_level:
        overrides["general.log_level"] = args.log_level
    elif args.verbose:
        overrides["general.log_level"] = "DEBUG"

    # Safety
    if args.dry_run:
        overrides["security.dry_run"] = True
    if args.safe_mode:
        overrides["security.safe_mode"] = True
    if args.unsafe:
        overrides["security.safe_mode"] = False

    # Speed profiles
    if args.fast:
        overrides["recon.dns_parallelization"] = 200
        overrides["timeout.dns_timeout"] = 2
        overrides["timeout.scan_timeout"] = 300
        overrides["timeout.exploit_timeout"] = 120
        overrides["scanning.rate_limit"] = 5000
    elif args.slow:
        overrides["recon.dns_parallelization"] = 10
        overrides["timeout.dns_timeout"] = 10
        overrides["timeout.scan_timeout"] = 1200
        overrides["timeout.exploit_timeout"] = 600
        overrides["scanning.rate_limit"] = 100
        overrides["exploitation.brute_force_delay"] = 2.0

    return overrides


# ---------------------------------------------------------------------------
# 3. Validation printer
# ---------------------------------------------------------------------------

def _print_validation(issues: list[str]) -> bool:
    """Print validation issues.  Returns True if fatal errors found."""
    if not issues:
        console.print("[green]Configuration valid — no issues.[/green]")
        return False

    console.rule("[bold]Configuration Validation Results")
    has_errors = False
    for issue in issues:
        if issue.startswith("ERROR"):
            console.print(f"[bold red]  {issue}[/bold red]")
            has_errors = True
        elif issue.startswith("WARNING"):
            console.print(f"[yellow]  {issue}[/yellow]")
        else:
            console.print(f"  {issue}")
    console.rule()
    return has_errors


# ---------------------------------------------------------------------------
# 4. Main entry-point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    """Parse arguments, load config, validate, and run the pipeline."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # ── Load ConfigManager ────────────────────────────────────────────
    from config.settings import ConfigManager, load_config

    overrides = _build_overrides(args)
    config = load_config(config_path=args.config, cli_overrides=overrides)

    # ── Setup logging ─────────────────────────────────────────────────
    log_level = config.get("general.log_level", "INFO")
    logging.basicConfig(
        level=getattr(logging, log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Info-only modes ───────────────────────────────────────────────
    if args.print_config:
        config.print_config_summary()
        sys.exit(0)

    if args.validate_only:
        issues = config.validate_configuration()
        has_errors = _print_validation(issues)
        sys.exit(1 if has_errors else 0)

    # ── Validate ──────────────────────────────────────────────────────
    issues = config.validate_configuration()
    has_errors = _print_validation(issues)
    if has_errors:
        logger.error("Configuration has errors — aborting.")
        sys.exit(1)

    # ── Resolve target ────────────────────────────────────────────────
    target = config.get("general.target", "")
    if not target:
        console.print("[bold red]ERROR: No target specified.[/bold red]")
        console.print("Use --target <IP/DOMAIN> or set general.target in config.yaml")
        sys.exit(1)

    # ── Safety confirmation ───────────────────────────────────────────
    dry_run = config.get("security.dry_run", True)
    safe_mode = config.get("security.safe_mode", True)
    require_confirm = config.get("security.require_confirmation", True)

    if not dry_run and require_confirm:
        console.print(
            "\n[bold bright_yellow]WARNING: dry_run is OFF — "
            "this will send REAL traffic to the target![/bold bright_yellow]"
        )
        if not safe_mode:
            console.print(
                "[bold red]safe_mode is also OFF — "
                "destructive exploits are enabled![/bold red]"
            )
        try:
            response = input("Continue? (yes/no): ")
        except (EOFError, KeyboardInterrupt):
            response = "no"
        if response.strip().lower() != "yes":
            logger.info("Cancelled by user.")
            sys.exit(0)

    # ── Print summary ─────────────────────────────────────────────────
    config.print_config_summary()

    # ── Run pipeline ──────────────────────────────────────────────────
    from core.engine import run_pipeline

    try:
        verbose = log_level == "DEBUG"
        results = run_pipeline(
            target=target,
            verbose=verbose,
            skip_recon=args.skip_recon,
            wordlist=args.wordlist,
            config=config,
        )
        logger.info("Attack pipeline completed successfully.")
    except KeyboardInterrupt:
        logger.warning("Attack interrupted by user.")
        sys.exit(130)
    except Exception as exc:
        logger.error("Attack failed: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
