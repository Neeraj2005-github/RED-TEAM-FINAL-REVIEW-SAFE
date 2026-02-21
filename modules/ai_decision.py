"""
modules/ai_decision.py — AI-driven attack decision engine for the
AI Red Team Framework.

MITRE ATT&CK:
  T1110.001  Brute Force: Password Guessing
  T1190      Exploit Public-Facing Application
  T1078      Valid Accounts

Uses Groq (LLaMA 3.3 70B) as the primary LLM, with a local Ollama
Mistral fallback when the cloud API is unavailable.
"""

import json
import sys
from typing import Any

import groq
import requests
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from config.settings import GROQ_API_KEY
from core.state_manager import state

console = Console()

GROQ_MODEL: str = "llama-3.3-70b-versatile"

# Safe default decisions returned when both LLM backends fail
_DEFAULT_DECISIONS: list[dict[str, Any]] = [
    {
        "technique": "ssh_brute",
        "mitre_id": "T1110.001",
        "target_service": "ssh",
        "target_port": 22,
        "rationale": "SSH is commonly vulnerable to weak credentials",
        "priority": 1,
    },
    {
        "technique": "ftp_anon",
        "mitre_id": "T1078",
        "target_service": "ftp",
        "target_port": 21,
        "rationale": "FTP often allows anonymous login",
        "priority": 2,
    },
]


# ---------------------------------------------------------------------------
# 1. Prompt Builder
# ---------------------------------------------------------------------------

def build_prompt(scan_results: dict[str, Any]) -> str:
    """Build the system prompt that instructs the LLM to select attack techniques.

    The prompt embeds the scan results as formatted JSON and requests a
    strictly typed JSON response containing ranked decisions.
    """
    scan_json: str = json.dumps(scan_results, indent=2, default=str)

    return (
        "You are an expert red team operator and penetration tester.\n"
        "\n"
        "Below are the scan results from a network assessment:\n"
        "```json\n"
        f"{scan_json}\n"
        "```\n"
        "\n"
        "Based ONLY on the services and versions discovered above, select the\n"
        "most effective attack techniques.  Return ONLY valid JSON — no markdown\n"
        "fences, no commentary, no explanation outside the JSON object.\n"
        "\n"
        "Required output format:\n"
        '{"decisions": [\n'
        "  {\n"
        '    "technique": "<technique_name>",\n'
        '    "mitre_id": "<MITRE ATT&CK ID>",\n'
        '    "target_service": "<service name from scan>",\n'
        '    "target_port": <port number>,\n'
        '    "rationale": "<brief explanation>",\n'
        '    "priority": <int>  // 1 = highest\n'
        "  }\n"
        "]}\n"
        "\n"
        "You MUST only use these exact technique names (no others):\n"
        "  ssh_brute, ftp_anon, http_default_creds, smb_enum, cve_check\n"
        "\n"
        "Only include a technique if its port is actually open in the scan results.\n"
        "Return maximum 4 techniques. Priority 1 = most likely to succeed.\n"
        "\n"
        "Rules:\n"
        "  • Rank techniques by priority (1 = most impactful).\n"
        "  • Only include techniques relevant to services actually found in the scan.\n"
        "  • priority must be a unique integer starting from 1.\n"
    )


# ---------------------------------------------------------------------------
# 2. Groq Decision
# ---------------------------------------------------------------------------

def _groq_decision(scan_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Call the Groq cloud API (LLaMA 3.3 70B) to produce attack decisions."""
    client = groq.Groq(api_key=GROQ_API_KEY)

    response = client.chat.completions.create(
        model=GROQ_MODEL,
        temperature=0.2,
        response_format={"type": "json_object"},
        messages=[
            {"role": "user", "content": build_prompt(scan_results)},
        ],
    )

    content: str = response.choices[0].message.content or "{}"
    data: dict[str, Any] = json.loads(content)
    decisions: list[dict[str, Any]] = data.get("decisions", [])
    return sorted(decisions, key=lambda d: d.get("priority", 99))


# ---------------------------------------------------------------------------
# 3. Ollama (Mistral) Fallback
# ---------------------------------------------------------------------------

OLLAMA_URL: str = "http://localhost:11434/api/generate"


def _ollama_decision(scan_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Fall back to a local Ollama Mistral model for attack decisions."""
    payload: dict[str, Any] = {
        "model": "mistral",
        "prompt": build_prompt(scan_results),
        "format": "json",
        "stream": False,
    }

    resp = requests.post(OLLAMA_URL, json=payload, timeout=120)
    resp.raise_for_status()

    body: dict[str, Any] = resp.json()
    raw: str = body.get("response", "{}")
    data: dict[str, Any] = json.loads(raw)
    decisions: list[dict[str, Any]] = data.get("decisions", [])
    return sorted(decisions, key=lambda d: d.get("priority", 99))


# ---------------------------------------------------------------------------
# 4. Unified Decision Getter
# ---------------------------------------------------------------------------

# Normalize technique names the AI may invent back to canonical handler names
_TECHNIQUE_ALIASES: dict[str, str] = {
    "ssh_brute_force": "ssh_brute",
    "ftp_anonymous": "ftp_anon",
    "smb_null_session": "smb_enum",
    "http_creds": "http_default_creds",
    "lateral_movement": "cve_check",
    "smtp_user_enum": "cve_check",
}


def _normalize_decisions(decisions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map AI-generated technique names to canonical handler names."""
    for d in decisions:
        name = d.get("technique", "")
        d["technique"] = _TECHNIQUE_ALIASES.get(name, name)
    return decisions


def get_attack_decision(scan_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Return ranked attack decisions — tries Groq first, then Ollama,
    then falls back to a safe hard-coded default list.
    """
    # Try Groq (only if API key is present)
    if GROQ_API_KEY:
        try:
            decisions = _normalize_decisions(_groq_decision(scan_results))
            if decisions:
                console.print("[green]✔  Decisions obtained from Groq API.[/green]")
                state.set("ai_source", "groq")
                return decisions
        except Exception as exc:
            console.print(f"[yellow]⚠  Groq API failed: {exc}[/yellow]")
    else:
        console.print("[yellow]⚠  No Groq API key found. Trying local Ollama...[/yellow]")

    # Try Ollama
    try:
        decisions = _normalize_decisions(_ollama_decision(scan_results))
        if decisions:
            console.print("[green]✔  Decisions obtained from Ollama (Mistral).[/green]")
            state.set("ai_source", "ollama")
            return decisions
    except Exception as exc:
        console.print(f"[yellow]⚠  Ollama fallback failed: {exc}[/yellow]")

    # Hard-coded defaults
    console.print("[bold red]⚠  USING FALLBACK DECISIONS — AI unavailable[/bold red]")
    state.set("ai_source", "fallback")
    return _normalize_decisions(_DEFAULT_DECISIONS)


# ---------------------------------------------------------------------------
# 5. Run AI Decision Phase
# ---------------------------------------------------------------------------

def run_ai_decision() -> list[dict[str, Any]]:
    """Load scan results from state, generate attack decisions, and persist them."""
    console.rule("[bold cyan]Phase 3 — AI Decision Engine[/bold cyan]")

    scan_results: dict[str, Any] = state.get("scan_results", {})
    if not scan_results:
        # Try to build minimal scan data from open_ports (set by network validator
        # or scanner), so the AI engine can still produce useful decisions.
        open_ports = state.get_open_ports()
        if open_ports:
            console.print("[yellow]⚠  No detailed scan results — building from open ports.[/yellow]")
            scan_results = {
                str(p): {"service": svc if svc != "open" else "", "version": "", "cves": []}
                for p, svc in open_ports.items()
            }
        else:
            console.print("[yellow]⚠  No scan results — using default attack decisions.[/yellow]")
            decisions = _normalize_decisions(list(_DEFAULT_DECISIONS))
            state.set("ai_decisions", decisions)
            console.print("[green]✔  Default AI decisions saved to state.[/green]")
            return decisions

    decisions: list[dict[str, Any]] = get_attack_decision(scan_results)

    # ---- Pretty-print decisions ----
    for decision in decisions:
        technique: str = decision.get("technique", "unknown")
        mitre_id: str = decision.get("mitre_id", "")
        port: int = decision.get("target_port", 0)
        service: str = decision.get("target_service", "")
        rationale: str = decision.get("rationale", "")
        priority: int = decision.get("priority", 0)

        console.print(
            Panel(
                f"[bold]Technique:[/bold]  {technique}\n"
                f"[bold]MITRE ID:[/bold]   {mitre_id}\n"
                f"[bold]Service:[/bold]    {service}:{port}\n"
                f"[bold]Rationale:[/bold]  {rationale}",
                title=f"[bold white]Priority {priority}[/bold white]",
                border_style="cyan",
            )
        )

    # Show raw JSON for verbose review
    console.print(
        Syntax(
            json.dumps(decisions, indent=2, default=str),
            "json",
            theme="monokai",
            line_numbers=False,
        )
    )

    # ---- Persist ----
    state.set("ai_decisions", decisions)
    console.print("[green]✔  AI decisions saved to state.[/green]")
    return decisions


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Entry-point called by the pipeline orchestrator."""
    return run_ai_decision()


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_ai_decision()
