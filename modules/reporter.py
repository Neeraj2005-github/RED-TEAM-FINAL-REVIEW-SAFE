"""
modules/reporter.py — Reporting phase for the AI Red Team Framework.

Generates:
  • PDF assessment report with AI-written executive summary
  • JSON export of all state data
  • Attack-path graph (PNG)
  • MITRE ATT&CK mapping for every observed technique
"""

import json
import os
import sys
import traceback
from datetime import datetime
from typing import Any

import groq
import matplotlib
matplotlib.use("Agg")  # headless backend — must be set before pyplot import
import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import Patch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from rich.console import Console
from rich.panel import Panel

from config.settings import GRAPHS_DIR, GROQ_API_KEY, REPORTS_DIR
from core.state_manager import state

console = Console()


# ═══════════════════════════════════════════════════════════════════════════
# Cell Sanitiser — prevents reportlab crashes from bad data types
# ═══════════════════════════════════════════════════════════════════════════

def sanitize_cell(value: Any) -> str:
    """Convert any value into a safe string for a reportlab Table cell."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, list):
        return ", ".join(str(x) for x in value)
    if isinstance(value, dict):
        return json.dumps(value, indent=None, default=str)
    text = str(value)
    if len(text) > 80:
        return text[:77] + "..."
    return text


# ═══════════════════════════════════════════════════════════════════════════
# Part 1 — MITRE ATT&CK Mapping
# ═══════════════════════════════════════════════════════════════════════════

MITRE_MAP: dict[str, dict[str, str]] = {
    "T1595":     {"tactic": "Reconnaissance",        "name": "Active Scanning"},
    "T1589":     {"tactic": "Reconnaissance",        "name": "Gather Victim Identity Info"},
    "T1596":     {"tactic": "Reconnaissance",        "name": "Search Open Technical Databases"},
    "T1046":     {"tactic": "Discovery",             "name": "Network Service Discovery"},
    "T1082":     {"tactic": "Discovery",             "name": "System Information Discovery"},
    "T1016":     {"tactic": "Discovery",             "name": "System Network Config Discovery"},
    "T1110.001": {"tactic": "Credential Access",     "name": "Brute Force: Password Guessing"},
    "T1190":     {"tactic": "Initial Access",        "name": "Exploit Public-Facing Application"},
    "T1078":     {"tactic": "Initial Access",        "name": "Valid Accounts"},
    "T1548.001": {"tactic": "Privilege Escalation",  "name": "Abuse Elevation: Setuid/Setgid"},
    "T1574.009": {"tactic": "Privilege Escalation",  "name": "Hijack Execution Flow: Path Hijacking"},
    "T1053.003": {"tactic": "Persistence",           "name": "Scheduled Task/Job: Cron"},
    "T1547.001": {"tactic": "Persistence",           "name": "Boot or Logon Autostart: Registry Run Keys"},
    "T1021.002": {"tactic": "Lateral Movement",      "name": "Remote Services: SMB/Windows Admin Shares"},
    "T1005":     {"tactic": "Collection",            "name": "Data from Local System"},
    "T1037.004": {"tactic": "Persistence",           "name": "Boot or Logon Initialization Scripts: RC Scripts"},
}


def get_mitre_details(mitre_id: str) -> dict[str, str]:
    """Look up a MITRE ATT&CK technique by ID."""
    entry = MITRE_MAP.get(mitre_id, {})
    return {
        "id": mitre_id,
        "tactic": entry.get("tactic", "Unknown"),
        "name": entry.get("name", "Unknown Technique"),
    }


def collect_all_mitre_actions() -> list[dict[str, Any]]:
    """Aggregate every MITRE-mapped action from the current engagement state.

    Hard-codes Recon / Scanning phase entries (T1595, T1589, T1046, T1082)
    and pulls dynamic entries from exploit_results, privesc_results, and
    persistence_simulated.  Returns a deduplicated, phase-sorted list.
    """
    actions: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    def _add(phase: int, phase_name: str, mitre_id: str, ts: str = "") -> None:
        if mitre_id in seen_ids:
            return
        seen_ids.add(mitre_id)
        details = get_mitre_details(mitre_id)
        actions.append({
            "phase": phase,
            "phase_name": phase_name,
            "technique_name": details["name"],
            "mitre_id": mitre_id,
            "tactic": details["tactic"],
            "timestamp": ts,
        })

    # Phase 1 — Recon (always present)
    _add(1, "Reconnaissance", "T1595")
    _add(1, "Reconnaissance", "T1589")
    _add(1, "Reconnaissance", "T1596")

    # Phase 2 — Scanning (always present)
    _add(2, "Scanning", "T1046")
    _add(2, "Scanning", "T1082")
    _add(2, "Scanning", "T1016")

    # Phase 4 — Exploitation
    for item in state.get("exploit_results", []):
        mid = item.get("mitre_id", "")
        if mid:
            _add(4, "Exploitation", mid, item.get("timestamp", ""))

    # Phase 5 — Privilege Escalation
    privesc = state.get("privesc_results", {})
    if isinstance(privesc, dict):
        suid = privesc.get("suid_binaries", [])
        if suid:
            _add(5, "Privilege Escalation", "T1548.001")
        sudo = privesc.get("sudo_misconfig", [])
        if sudo:
            _add(5, "Privilege Escalation", "T1574.009")
        cron = privesc.get("cron_jobs", [])
        if cron:
            _add(5, "Privilege Escalation", "T1053.003")

    # Phase 6 — Persistence
    for item in state.get("persistence_simulated", []):
        mid = item.get("mitre_id", "")
        if mid:
            _add(6, "Persistence", mid, item.get("timestamp", ""))

    actions.sort(key=lambda a: a["phase"])
    return actions


# ═══════════════════════════════════════════════════════════════════════════
# Part 2 — Attack Graph Generator
# ═══════════════════════════════════════════════════════════════════════════

def generate_attack_graph() -> str:
    """Build a directed attack-path graph and save it as a PNG.

    Returns the file path to the saved image.
    """
    exploit_results: list[dict[str, Any]] = state.get("exploit_results", [])
    session_info: dict[str, Any] = state.get("session_info", {})
    target: str = state.get("target", "unknown")
    attacker_ip: str = "10.0.0.1 (Attacker)"

    privesc_results = state.get("privesc_results", {})
    has_root: bool = False
    if isinstance(privesc_results, dict):
        suid = privesc_results.get("suid_binaries", [])
        has_root = any(s.get("is_exploitable") for s in suid)

    G = nx.DiGraph()

    # Core nodes
    node_colors: dict[str, str] = {}
    node_sizes: dict[str, int] = {}

    G.add_node(attacker_ip)
    node_colors[attacker_ip] = "#FF4444"
    node_sizes[attacker_ip] = 3000

    G.add_node(target)
    node_colors[target] = "#FFA500"
    node_sizes[target] = 2000

    G.add_edge(attacker_ip, target, label="Initial Access")

    # Service nodes for successful exploits
    for item in exploit_results:
        if not item.get("success"):
            continue
        technique: str = item.get("technique", "unknown")
        port: int = item.get("port", 0)
        service: str = technique.upper().split("_")[0]
        node_label: str = f"{service}:{port}"

        color = "#4CAF50" if has_root else "#FFD700"
        G.add_node(node_label)
        node_colors[node_label] = color
        node_sizes[node_label] = 1500
        G.add_edge(target, node_label, label=technique)

    # Draw
    fig = plt.figure(figsize=(14, 10))
    pos = nx.spring_layout(G, seed=42, k=2)

    for node in G.nodes():
        nx.draw_networkx_nodes(
            G, pos,
            nodelist=[node],
            node_color=node_colors.get(node, "#CCCCCC"),
            node_size=node_sizes.get(node, 1200),
            edgecolors="black",
            linewidths=1.5,
        )

    nx.draw_networkx_edges(
        G, pos,
        edge_color="#555555",
        arrows=True,
        arrowsize=20,
        width=2,
        connectionstyle="arc3,rad=0.1",
    )

    nx.draw_networkx_labels(G, pos, font_size=9, font_weight="bold")

    edge_labels = nx.get_edge_attributes(G, "label")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)

    legend_elements = [
        Patch(facecolor="#FF4444", edgecolor="black", label="Attacker"),
        Patch(facecolor="#FFA500", edgecolor="black", label="Target"),
        Patch(facecolor="#FFD700", edgecolor="black", label="User Access"),
        Patch(facecolor="#4CAF50", edgecolor="black", label="Root Access"),
    ]
    plt.legend(handles=legend_elements, loc="upper left", fontsize=10)
    plt.title(
        "Attack Path Graph — AI Red Team Framework",
        fontsize=14,
        fontweight="bold",
    )
    plt.axis("off")

    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(str(GRAPHS_DIR), exist_ok=True)
    graph_path: str = f"{GRAPHS_DIR}/attack_graph_{timestamp}.png"
    plt.savefig(graph_path, dpi=150, bbox_inches="tight", facecolor="white")
    plt.close(fig)

    console.print(f"[green]✔  Attack graph saved: {graph_path}[/green]")
    return graph_path


# ═══════════════════════════════════════════════════════════════════════════
# Part 3 — AI Executive Summary
# ═══════════════════════════════════════════════════════════════════════════

_DEFAULT_SUMMARY: str = (
    "This penetration test was conducted against the designated target using "
    "an automated AI-driven framework.  The assessment followed a structured "
    "five-phase methodology: reconnaissance, scanning, exploitation, privilege "
    "escalation, and persistence simulation.\n\n"
    "Key findings include potential service-level vulnerabilities, weak or "
    "default credentials, and possible privilege-escalation vectors.  Each "
    "finding has been mapped to the MITRE ATT&CK framework for consistency "
    "with industry-standard reporting.\n\n"
    "Overall risk is rated as MEDIUM.  It is recommended that the organisation "
    "(1) enforce strong credential policies and disable default accounts, "
    "(2) patch all services to the latest stable versions, and (3) restrict "
    "network exposure of administrative interfaces."
)


def generate_executive_summary(state_data: dict[str, Any]) -> str:
    """Use Groq (LLaMA 3.3 70B) to write a three-paragraph executive summary.

    Falls back to ``_DEFAULT_SUMMARY`` if the API is unavailable.
    """
    exploit_results = state_data.get("exploit_results", [])
    successes = [e for e in exploit_results if e.get("success")]
    privesc = state_data.get("privesc_results", {})

    prompt = (
        "You are a senior penetration tester writing an executive summary for "
        "a client report.\n\n"
        f"Phases executed: Reconnaissance, Scanning, Exploitation, Privilege "
        f"Escalation, Persistence Simulation.\n"
        f"Successful exploits ({len(successes)}): "
        f"{json.dumps(successes, default=str)}\n"
        f"Privilege escalation findings: {json.dumps(privesc, default=str)}\n\n"
        "Write exactly 3 paragraphs:\n"
        "Paragraph 1: Overview of what was tested and methodology.\n"
        "Paragraph 2: Key findings and vulnerabilities discovered.\n"
        "Paragraph 3: Risk rating (High/Medium/Low) with justification "
        "and your top 3 remediation steps.\n"
        "Be concise and professional. No bullet points, no headings."
    )

    try:
        client = groq.Groq(api_key=GROQ_API_KEY)
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            temperature=0.4,
            max_tokens=600,
            messages=[{"role": "user", "content": prompt}],
        )
        text: str = response.choices[0].message.content or ""
        if len(text.strip()) > 50:
            return text.strip()
    except Exception as exc:
        console.print(f"[yellow]⚠  AI summary generation failed: {exc}[/yellow]")

    return _DEFAULT_SUMMARY


# ═══════════════════════════════════════════════════════════════════════════
# Part 4 — PDF Report
# ═══════════════════════════════════════════════════════════════════════════

# Shared table style
_HEADER_BG = colors.HexColor("#1E3A5F")
_ALT_ROW = colors.HexColor("#EBF5FB")

_TABLE_STYLE = TableStyle([
    ("BACKGROUND",   (0, 0), (-1, 0), _HEADER_BG),
    ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
    ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE",     (0, 0), (-1, -1), 9),
    ("BOTTOMPADDING",(0, 0), (-1, 0), 8),
    ("TOPPADDING",   (0, 0), (-1, -1), 6),
    ("BOTTOMPADDING",(0, 1), (-1, -1), 6),
    ("LEFTPADDING",  (0, 0), (-1, -1), 6),
    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ("GRID",         (0, 0), (-1, -1), 0.5, colors.grey),
    ("VALIGN",       (0, 0), (-1, -1), "TOP"),
])


def _alternating_style(row_count: int) -> TableStyle:
    """Return a TableStyle with alternating row shading."""
    commands: list = list(_TABLE_STYLE.getCommands())
    for i in range(1, row_count):
        bg = _ALT_ROW if i % 2 == 0 else colors.white
        commands.append(("BACKGROUND", (0, i), (-1, i), bg))
    return TableStyle(commands)


def _page_footer(canvas: Any, doc: Any) -> None:
    """Draw a centred page number at the bottom of every page."""
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(
        letter[0] / 2, 40, f"Page {doc.page}"
    )
    canvas.restoreState()


def generate_pdf_report() -> str:
    """Generate a full PDF assessment report and return the file path."""

    # ---- Gather data ----
    state_data: dict[str, Any] = {
        "target": state.get("target", "unknown"),
        "recon": state.get("recon", {}),
        "scan_results": state.get("scan_results", {}),
        "ai_decisions": state.get("ai_decisions", []),
        "exploit_results": state.get("exploit_results", []),
        "privesc_results": state.get("privesc_results", {}),
        "persistence_simulated": state.get("persistence_simulated", []),
        "session_info": state.get("session_info", {}),
    }

    target: str = state_data["target"]
    exploit_results: list[dict] = state_data["exploit_results"]
    scan_results: dict = state_data["scan_results"]
    any_success: bool = any(e.get("success") for e in exploit_results)
    risk_rating: str = "HIGH" if any_success else "MEDIUM"

    exec_summary: str = generate_executive_summary(state_data)
    graph_path: str = generate_attack_graph()
    mitre_actions: list[dict] = collect_all_mitre_actions()

    # ---- PDF setup ----
    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(str(REPORTS_DIR), exist_ok=True)
    pdf_path: str = f"{REPORTS_DIR}/report_{timestamp}.pdf"

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=72,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["Title"],
        fontSize=26,
        leading=32,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#1E3A5F"),
        spaceAfter=12,
    )
    subtitle_style = ParagraphStyle(
        "CoverSub",
        parent=styles["Normal"],
        fontSize=13,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#333333"),
        spaceAfter=6,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading1"],
        fontSize=16,
        textColor=colors.HexColor("#1E3A5F"),
        spaceBefore=18,
        spaceAfter=10,
    )
    body_style = ParagraphStyle(
        "BodyJustified",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        alignment=TA_JUSTIFY,
        spaceAfter=8,
    )
    bullet_style = ParagraphStyle(
        "Bullet",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        leftIndent=20,
        spaceAfter=4,
    )

    story: list = []

    # ================================================================
    # 1. Cover Page
    # ================================================================
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("AI RED TEAM<br/>ASSESSMENT REPORT", title_style))
    story.append(Spacer(1, 0.3 * inch))
    story.append(Paragraph(f"Target: {target}", subtitle_style))
    story.append(Paragraph(
        f"Date: {datetime.now().strftime('%d %B %Y')}", subtitle_style
    ))

    risk_color = "#FF4444" if risk_rating == "HIGH" else "#FFA500"
    story.append(Paragraph(
        f'Overall Risk Rating: <font color="{risk_color}"><b>{risk_rating}</b></font>',
        subtitle_style,
    ))
    story.append(Spacer(1, 0.4 * inch))
    story.append(HRFlowable(
        width="80%", thickness=2, color=colors.HexColor("#1E3A5F"),
    ))
    story.append(PageBreak())

    # ================================================================
    # 2. Executive Summary
    # ================================================================
    story.append(Paragraph("Executive Summary", heading_style))
    for para in exec_summary.strip().split("\n\n"):
        story.append(Paragraph(para.strip(), body_style))
    story.append(Spacer(1, 0.2 * inch))

    # ================================================================
    # 3. Attack Timeline Table
    # ================================================================
    story.append(Paragraph("Attack Timeline", heading_style))

    timeline_data: list[list[str]] = [
        ["Phase", "Technique", "Result", "Timestamp", "MITRE ID"]
    ]
    for item in exploit_results:
        timeline_data.append([
            sanitize_cell("Exploitation"),
            sanitize_cell(item.get("technique", "")),
            sanitize_cell("Success" if item.get("success") else "Failed"),
            sanitize_cell(str(item.get("timestamp", ""))[:19]),
            sanitize_cell(item.get("mitre_id", "")),
        ])
    privesc = state_data.get("privesc_results", {})
    if isinstance(privesc, dict):
        for finding_type in ("suid_binaries", "sudo_misconfig", "cron_jobs", "writable_configs"):
            items = privesc.get(finding_type, [])
            if items:
                timeline_data.append([
                    sanitize_cell("Privilege Escalation"),
                    sanitize_cell(finding_type.replace("_", " ").title()),
                    sanitize_cell(f"{len(items)} finding(s)"),
                    sanitize_cell(""),
                    sanitize_cell(""),
                ])

    if len(timeline_data) > 1:
        t = Table(timeline_data, repeatRows=1, hAlign="LEFT")
        t.setStyle(_alternating_style(len(timeline_data)))
        story.append(t)
    else:
        story.append(Paragraph("No exploit results recorded.", body_style))
    story.append(Spacer(1, 0.2 * inch))

    # ================================================================
    # 4. MITRE ATT&CK Mapping Table
    # ================================================================
    story.append(Paragraph("MITRE ATT&CK Mapping", heading_style))

    mitre_data: list[list[str]] = [["Tactic", "Technique", "ID", "Phase"]]
    for action in mitre_actions:
        mitre_data.append([
            sanitize_cell(action.get("tactic", "")),
            sanitize_cell(action.get("technique_name", "")),
            sanitize_cell(action.get("mitre_id", "")),
            sanitize_cell(action.get("phase_name", "")),
        ])

    t = Table(mitre_data, repeatRows=1, hAlign="LEFT")
    t.setStyle(_alternating_style(len(mitre_data)))
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    # ================================================================
    # 5. Vulnerability Table
    # ================================================================
    story.append(Paragraph("Vulnerability Summary", heading_style))

    vuln_data: list[list[str]] = [["Port", "Service", "CVEs Found", "Risk"]]
    for port in sorted(scan_results.keys(), key=lambda p: int(p)):
        info = scan_results[port]
        cve_count = len(info.get("cves", []))
        risk = "High" if cve_count >= 3 else ("Medium" if cve_count >= 1 else "Low")
        vuln_data.append([
            sanitize_cell(port),
            sanitize_cell(info.get("service", "")),
            sanitize_cell(cve_count),
            sanitize_cell(risk),
        ])

    if len(vuln_data) > 1:
        t = Table(vuln_data, repeatRows=1, hAlign="LEFT")
        t.setStyle(_alternating_style(len(vuln_data)))
        story.append(t)
    else:
        story.append(Paragraph("No scan results available.", body_style))
    story.append(Spacer(1, 0.2 * inch))

    # ================================================================
    # 6. Remediation Recommendations
    # ================================================================
    story.append(Paragraph("Remediation Recommendations", heading_style))

    # Build service-aware recommendations
    services_found = {
        info.get("service", "")
        for info in scan_results.values()
        if info.get("service")
    }
    recommendations: list[str] = [
        "Enforce strong password policies and disable default credentials on all services.",
        "Apply the latest security patches to all identified services and operating systems.",
        "Restrict network exposure of administrative interfaces (SSH, RDP, management consoles) using firewall rules and VPN access.",
        "Implement multi-factor authentication (MFA) for all remote-access and privileged accounts.",
        "Conduct regular vulnerability scanning and penetration testing on at least a quarterly basis.",
    ]
    if "ssh" in services_found:
        recommendations.append(
            "Disable SSH password authentication; enforce key-based login and restrict root access."
        )
    if "http" in services_found or "https" in services_found:
        recommendations.append(
            "Deploy a Web Application Firewall (WAF) and enable HTTPS with HSTS on all web services."
        )

    for rec in recommendations[:7]:
        story.append(Paragraph(f"• {rec}", bullet_style))
    story.append(Spacer(1, 0.2 * inch))

    # ================================================================
    # 7. Attack Graph Image
    # ================================================================
    story.append(Paragraph("Attack Path Graph", heading_style))
    if os.path.isfile(graph_path):
        story.append(Image(graph_path, width=6 * inch, height=4 * inch))
    else:
        story.append(Paragraph("Attack graph image not available.", body_style))

    # ================================================================
    # Build PDF
    # ================================================================
    try:
        doc.build(story, onFirstPage=_page_footer, onLaterPages=_page_footer)
        console.print(f"[green]✔  PDF report saved: {pdf_path}[/green]")
    except Exception as exc:
        console.print(f"[red]✘  PDF generation failed: {exc}[/red]")
        traceback.print_exc()
        # Generate a minimal fallback PDF so the pipeline still produces a file
        try:
            fallback_doc = SimpleDocTemplate(pdf_path, pagesize=letter)
            fallback_styles = getSampleStyleSheet()
            fallback_story = [
                Spacer(1, 2 * inch),
                Paragraph(
                    "AI Red Team Report — Generation Error",
                    fallback_styles["Title"],
                ),
                Spacer(1, 0.5 * inch),
                Paragraph(
                    f"The full report could not be generated due to an error:<br/>"
                    f"<i>{str(exc)[:200]}</i><br/><br/>"
                    f"Please check the JSON report for complete data.",
                    fallback_styles["Normal"],
                ),
            ]
            fallback_doc.build(fallback_story)
            console.print(f"[yellow]⚠  Fallback PDF saved: {pdf_path}[/yellow]")
        except Exception as fallback_exc:
            console.print(f"[red]✘  Fallback PDF also failed: {fallback_exc}[/red]")
    return pdf_path


# ═══════════════════════════════════════════════════════════════════════════
# JSON Report
# ═══════════════════════════════════════════════════════════════════════════

def generate_json_report() -> str:
    """Dump the entire engagement state to a timestamped JSON file."""
    timestamp: str = datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(str(REPORTS_DIR), exist_ok=True)
    json_path: str = f"{REPORTS_DIR}/report_{timestamp}.json"

    full_state: dict[str, Any] = {
        "target": state.get("target", "unknown"),
        "recon": state.get("recon", {}),
        "scan_results": state.get("scan_results", {}),
        "ai_decisions": state.get("ai_decisions", []),
        "exploit_results": state.get("exploit_results", []),
        "privesc_results": state.get("privesc_results", {}),
        "persistence_simulated": state.get("persistence_simulated", []),
        "session_info": state.get("session_info", {}),
        "report_generated": datetime.now().isoformat(),
    }

    with open(json_path, "w") as f:
        json.dump(full_state, f, indent=2, default=str)

    console.print(f"[green]✔  JSON report saved: {json_path}[/green]")
    return json_path


# ═══════════════════════════════════════════════════════════════════════════
# Run Reporter Phase
# ═══════════════════════════════════════════════════════════════════════════

def run_reporter() -> dict[str, str]:
    """Generate PDF and JSON reports and display output paths."""
    console.rule("[bold cyan]Phase 7 — Report Generation[/bold cyan]")

    pdf_path: str = generate_pdf_report()
    json_path: str = generate_json_report()

    console.print(
        Panel(
            f"[bold green]Reports generated successfully![/bold green]\n\n"
            f"  PDF  → [cyan]{pdf_path}[/cyan]\n"
            f"  JSON → [cyan]{json_path}[/cyan]",
            title="[bold white]Report Output[/bold white]",
            border_style="green",
        )
    )

    return {"pdf": pdf_path, "json": json_path}


# ---------------------------------------------------------------------------
# Convenience alias used by core/engine.py
# ---------------------------------------------------------------------------

def run(target: str, **kwargs: Any) -> dict[str, str]:
    """Entry-point called by the pipeline orchestrator."""
    return run_reporter()


# ---------------------------------------------------------------------------
# Stand-alone execution
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_reporter()
