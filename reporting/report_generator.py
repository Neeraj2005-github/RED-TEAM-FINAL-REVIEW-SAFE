"""
reporting/report_generator.py — Comprehensive HTML + JSON report generator
for the AI Red Team Framework.

Generates:
  * Dark-themed HTML report (Jinja2 templates, Chart.js graphs) with
    collapsible sections and sortable tables.
  * Structured JSON export for API consumption / integration.

Sections:
  1. Executive Summary
  2. Methodology
  3. Reconnaissance
  4. Vulnerabilities
  5. Exploitation
  6. Post-Exploitation
  7. Impact & Risk
  8. Recommendations
  9. Appendix (raw logs, ATT&CK mapping)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

import groq
from jinja2 import BaseLoader, Environment
from rich.console import Console

from config.settings import GROQ_API_KEY, REPORTS_DIR
from core.plugin_loader import ExecutionContext, ExecutionResult
from core.state_manager import state

logger = logging.getLogger(__name__)
console = Console()

os.makedirs(str(REPORTS_DIR), exist_ok=True)


# ═══════════════════════════════════════════════════════════════════════════
# 1. Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Finding:
    """A single finding / vulnerability."""
    title: str = ""
    severity: str = "info"           # critical, high, medium, low, info
    cvss: float = 0.0
    cve_id: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    mitre_technique: str = ""
    host: str = ""
    port: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    """Full engagement report."""
    title: str = "AI Red Team Assessment Report"
    target: str = ""
    date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    duration: str = ""
    executive_summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    techniques: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    html_content: str = ""
    json_content: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "target": self.target,
            "date": self.date,
            "duration": self.duration,
            "executive_summary": self.executive_summary,
            "findings": [f.to_dict() for f in self.findings],
            "techniques": self.techniques,
            "metrics": self.metrics,
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2. ReportGenerator
# ═══════════════════════════════════════════════════════════════════════════

class ReportGenerator:
    """Build comprehensive HTML + JSON reports from engagement state."""

    def __init__(self) -> None:
        self._jinja = Environment(loader=BaseLoader(), autoescape=True)

    # ------------------------------------------------------------------
    # 2a. Collect data from state
    # ------------------------------------------------------------------

    def _collect_state(self) -> dict[str, Any]:
        """Pull every relevant key from the state manager."""
        return {
            "target":              state.get("target", "unknown"),
            "start_time":          state.get("start_time", ""),
            "end_time":            state.get("end_time", datetime.utcnow().isoformat()),
            "recon":               state.get("recon", {}),
            "scan_results":        state.get("scan_results", {}),
            "ai_decisions":        state.get("ai_decisions", []),
            "exploit_results":     state.get("exploit_results", []),
            "session_info":        state.get("session_info", {}),
            "privesc_results":     state.get("privesc_results", {}),
            "persistence_results": state.get("persistence_results", {}),
            "lateral_movement":    state.get("lateral_movement", {}),
            "credential_harvest":  state.get("credential_harvest", {}),
            "attack_matrix":       state.get("attack_matrix", {}),
            "os_info":             state.get("os_info", ""),
        }

    # ------------------------------------------------------------------
    # 2b. Build findings
    # ------------------------------------------------------------------

    def _build_findings(self, data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        target = data["target"]

        # From exploit results
        for item in data.get("exploit_results", []):
            if not item.get("success"):
                continue
            findings.append(Finding(
                title=f"Successful Exploitation: {item.get('technique', 'unknown')}",
                severity="critical" if item.get("technique") in ("ssh_brute", "smb_enum") else "high",
                cve_id=item.get("cve", ""),
                description=f"Exploitation succeeded via {item.get('technique')} on port {item.get('port', '?')}",
                evidence=json.dumps(item, default=str)[:300],
                remediation="Patch vulnerable services, enforce strong credentials, apply network segmentation.",
                mitre_technique=item.get("mitre_id", ""),
                host=target,
                port=item.get("port", 0),
            ))

        # From privesc
        privesc = data.get("privesc_results", {})
        if isinstance(privesc, dict):
            for path in privesc.get("paths", []):
                if isinstance(path, dict) and path.get("likelihood", 0) >= 0.7:
                    findings.append(Finding(
                        title=f"Privilege Escalation: {path.get('method', 'unknown')}",
                        severity="critical",
                        description=(
                            f"Privilege escalation via {path.get('method')} "
                            f"(likelihood {path.get('likelihood', 0):.0%})"
                        ),
                        remediation=f"Remove SUID bit, fix sudo config, patch kernel.",
                        mitre_technique=path.get("mitre_technique", ""),
                        host=target,
                    ))

        # From credential harvest
        creds = data.get("credential_harvest", {})
        if creds.get("total", 0) > 0:
            findings.append(Finding(
                title=f"Credentials Harvested: {creds['total']} found",
                severity="high",
                description=(
                    f"Recovered {creds.get('by_type', {}).get('hash', 0)} hashes, "
                    f"{creds.get('by_type', {}).get('private_key', 0)} keys, "
                    f"{creds.get('by_type', {}).get('plaintext', 0)} plaintext."
                ),
                remediation="Rotate credentials, enforce file permissions, use secret vaults.",
                host=target,
            ))

        # From lateral movement
        lat = data.get("lateral_movement", {})
        if lat.get("total_pivots", 0) > 0:
            findings.append(Finding(
                title=f"Lateral Movement: {lat['total_pivots']} pivot(s) achieved",
                severity="critical",
                description=f"Pivoted to {lat['total_pivots']} additional host(s) via credential reuse.",
                remediation="Segment networks, enforce unique credentials per host, deploy MFA.",
                host=target,
            ))

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.severity, 5))
        return findings

    # ------------------------------------------------------------------
    # 2c. Build metrics
    # ------------------------------------------------------------------

    def _build_metrics(self, data: dict[str, Any], findings: list[Finding]) -> dict[str, Any]:
        scan = data.get("scan_results", {})
        exploit_results = data.get("exploit_results", [])
        successes = [e for e in exploit_results if e.get("success")]
        lat = data.get("lateral_movement", {})
        matrix = data.get("attack_matrix", {})

        return {
            "total_hosts_discovered": lat.get("total_hosts", 1),
            "total_vulnerabilities": len(findings),
            "by_severity": {
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high":     sum(1 for f in findings if f.severity == "high"),
                "medium":   sum(1 for f in findings if f.severity == "medium"),
                "low":      sum(1 for f in findings if f.severity == "low"),
                "info":     sum(1 for f in findings if f.severity == "info"),
            },
            "exploitation_success_rate": (
                round(len(successes) / len(exploit_results) * 100, 1)
                if exploit_results else 0
            ),
            "exploits_attempted": len(exploit_results),
            "exploits_succeeded": len(successes),
            "lateral_pivots": lat.get("total_pivots", 0),
            "mitre_coverage": matrix.get("mitre_coverage", 0),
            "techniques_used": matrix.get("total_techniques", 0),
            "risk_rating": "CRITICAL" if any(
                f.severity == "critical" for f in findings
            ) else "HIGH" if any(
                f.severity == "high" for f in findings
            ) else "MEDIUM",
        }

    # ------------------------------------------------------------------
    # 2d. Executive summary (AI-generated)
    # ------------------------------------------------------------------

    def _generate_summary(self, data: dict[str, Any], metrics: dict[str, Any]) -> str:
        """Use Groq LLM for a 3-paragraph executive summary; fall back to template."""
        prompt = (
            "You are a senior penetration tester writing an executive summary.\n\n"
            f"Target: {data['target']}\n"
            f"Risk rating: {metrics['risk_rating']}\n"
            f"Findings: {metrics['total_vulnerabilities']} "
            f"({metrics['by_severity']['critical']} critical, "
            f"{metrics['by_severity']['high']} high)\n"
            f"Exploitation success rate: {metrics['exploitation_success_rate']}%\n"
            f"Lateral pivots: {metrics['lateral_pivots']}\n\n"
            "Write exactly 3 paragraphs: overview, key findings, risk + remediation.\n"
            "Be concise and professional."
        )
        try:
            client = groq.Groq(api_key=GROQ_API_KEY)
            resp = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                temperature=0.4,
                max_tokens=600,
                messages=[{"role": "user", "content": prompt}],
            )
            text = (resp.choices[0].message.content or "").strip()
            if len(text) > 50:
                return text
        except Exception as exc:
            logger.warning("AI summary failed: %s", exc)

        return (
            f"A penetration test was conducted against {data['target']} using the "
            f"AI Red Team Framework. The assessment identified {metrics['total_vulnerabilities']} "
            f"findings across reconnaissance, exploitation, and post-exploitation phases.\n\n"
            f"Key findings include {metrics['by_severity']['critical']} critical and "
            f"{metrics['by_severity']['high']} high-severity vulnerabilities. "
            f"The exploitation success rate was {metrics['exploitation_success_rate']}%. "
            f"Lateral movement achieved {metrics['lateral_pivots']} pivot(s).\n\n"
            f"Overall risk is rated {metrics['risk_rating']}. Recommendations: "
            "enforce strong credential policies, patch all services, and "
            "restrict network exposure of administrative interfaces."
        )

    # ------------------------------------------------------------------
    # 2e. HTML rendering
    # ------------------------------------------------------------------

    def _render_html(self, report: Report, data: dict[str, Any]) -> str:
        """Render a dark-themed HTML report."""
        template = self._jinja.from_string(_HTML_TEMPLATE)
        return template.render(
            report=report,
            data=data,
            metrics=report.metrics,
            findings=report.findings,
            techniques=report.techniques,
            now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
        )

    # ------------------------------------------------------------------
    # 2f. Main entry
    # ------------------------------------------------------------------

    def generate_full_report(
        self,
        context: ExecutionContext | None = None,
    ) -> Report:
        """Build and persist the full report."""
        data = self._collect_state()
        findings = self._build_findings(data)
        metrics = self._build_metrics(data, findings)
        summary = self._generate_summary(data, metrics)
        techniques = data.get("attack_matrix", {}).get("techniques_executed", [])

        report = Report(
            title=f"AI Red Team Assessment — {data['target']}",
            target=data["target"],
            executive_summary=summary,
            findings=findings,
            techniques=techniques,
            metrics=metrics,
        )

        # JSON
        report.json_content = report.to_dict()

        # HTML
        report.html_content = self._render_html(report, data)

        # Save files
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        target_slug = data["target"].replace(".", "_")

        html_path = str(REPORTS_DIR / f"{target_slug}_{ts}.html")
        json_path = str(REPORTS_DIR / f"{target_slug}_{ts}.json")

        with open(html_path, "w") as fh:
            fh.write(report.html_content)
        with open(json_path, "w") as fh:
            json.dump(report.json_content, fh, indent=2, default=str)

        console.print(f"[green]✔  HTML report: {html_path}[/green]")
        console.print(f"[green]✔  JSON report: {json_path}[/green]")

        state.set("report_paths", {"html": html_path, "json": json_path})
        return report


# ═══════════════════════════════════════════════════════════════════════════
# 3. Dark-themed HTML template
# ═══════════════════════════════════════════════════════════════════════════

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ report.title }}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root {
    --bg: #1a1a2e; --bg2: #16213e; --bg3: #0f3460;
    --fg: #e0e0e0; --fg2: #b0b0b0;
    --accent: #00bcd4; --critical: #f44336; --high: #ff9800;
    --medium: #ffeb3b; --low: #4caf50; --info: #2196f3;
    --border: #333;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--fg); line-height: 1.6; }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  h1 { color: var(--accent); font-size: 2rem; margin-bottom: 0.5rem; }
  h2 { color: var(--accent); font-size: 1.4rem; margin: 2rem 0 1rem; border-bottom: 2px solid var(--bg3); padding-bottom: 0.5rem; }
  h3 { color: var(--fg); font-size: 1.1rem; margin: 1rem 0 0.5rem; }
  .meta { color: var(--fg2); font-size: 0.9rem; margin-bottom: 2rem; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }
  .badge-critical { background: var(--critical); color: #fff; }
  .badge-high { background: var(--high); color: #000; }
  .badge-medium { background: var(--medium); color: #000; }
  .badge-low { background: var(--low); color: #fff; }
  .badge-info { background: var(--info); color: #fff; }
  .summary { background: var(--bg2); padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; border-left: 4px solid var(--accent); white-space: pre-line; }
  .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .metric-card { background: var(--bg2); padding: 1.2rem; border-radius: 8px; text-align: center; }
  .metric-card .value { font-size: 2rem; font-weight: bold; color: var(--accent); }
  .metric-card .label { font-size: 0.85rem; color: var(--fg2); margin-top: 0.25rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 1.5rem; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { background: var(--bg3); color: var(--accent); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.5px; cursor: pointer; }
  tr:hover { background: rgba(0,188,212,0.05); }
  .chart-container { background: var(--bg2); padding: 1.5rem; border-radius: 8px; margin-bottom: 2rem; max-width: 500px; }
  details { background: var(--bg2); border-radius: 8px; margin-bottom: 1rem; }
  details summary { cursor: pointer; padding: 1rem; font-weight: bold; color: var(--accent); }
  details .content { padding: 0 1rem 1rem; }
  pre { background: #0d0d1a; padding: 1rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; color: #aaa; }
  .risk-badge { font-size: 1.4rem; padding: 6px 20px; }
  @media (max-width: 768px) { .container { padding: 1rem; } .metrics-grid { grid-template-columns: 1fr 1fr; } }
</style>
</head>
<body>
<div class="container">

<h1>🛡️ {{ report.title }}</h1>
<p class="meta">Target: <strong>{{ report.target }}</strong> &nbsp;|&nbsp; Generated: {{ now }}</p>

<!-- Risk Rating -->
<p><span class="badge risk-badge badge-{{ 'critical' if metrics.risk_rating == 'CRITICAL' else 'high' if metrics.risk_rating == 'HIGH' else 'medium' }}">
  Risk: {{ metrics.risk_rating }}
</span></p>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<div class="summary">{{ report.executive_summary }}</div>

<!-- Metrics -->
<h2>Key Metrics</h2>
<div class="metrics-grid">
  <div class="metric-card"><div class="value">{{ metrics.total_hosts_discovered }}</div><div class="label">Hosts Discovered</div></div>
  <div class="metric-card"><div class="value">{{ metrics.total_vulnerabilities }}</div><div class="label">Findings</div></div>
  <div class="metric-card"><div class="value">{{ metrics.exploitation_success_rate }}%</div><div class="label">Exploit Success Rate</div></div>
  <div class="metric-card"><div class="value">{{ metrics.lateral_pivots }}</div><div class="label">Lateral Pivots</div></div>
  <div class="metric-card"><div class="value">{{ metrics.techniques_used }}</div><div class="label">ATT&CK Techniques</div></div>
  <div class="metric-card"><div class="value">{{ metrics.mitre_coverage }}%</div><div class="label">ATT&CK Coverage</div></div>
</div>

<!-- Severity chart -->
<div class="chart-container">
  <canvas id="sevChart" height="250"></canvas>
</div>

<!-- Findings -->
<h2>Findings</h2>
<table id="findingsTable">
  <thead>
    <tr><th onclick="sortTable(0)">Severity</th><th onclick="sortTable(1)">Title</th><th onclick="sortTable(2)">Host</th><th onclick="sortTable(3)">MITRE</th></tr>
  </thead>
  <tbody>
  {% for f in findings %}
    <tr>
      <td><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span></td>
      <td>{{ f.title }}</td>
      <td>{{ f.host }}{% if f.port %}:{{ f.port }}{% endif %}</td>
      <td>{{ f.mitre_technique }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>

{% for f in findings %}
<details>
  <summary><span class="badge badge-{{ f.severity }}">{{ f.severity }}</span> {{ f.title }}</summary>
  <div class="content">
    <p><strong>Description:</strong> {{ f.description }}</p>
    {% if f.evidence %}<p><strong>Evidence:</strong></p><pre>{{ f.evidence }}</pre>{% endif %}
    <p><strong>Remediation:</strong> {{ f.remediation }}</p>
  </div>
</details>
{% endfor %}

<!-- ATT&CK Techniques -->
{% if techniques %}
<h2>ATT&CK Technique Mapping</h2>
<table>
  <thead><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr></thead>
  <tbody>
  {% for t in techniques %}
    <tr>
      <td>{{ t.technique_id }}</td>
      <td>{{ t.technique_name }}</td>
      <td>{{ t.tactic }}</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endif %}

<!-- Methodology -->
<details>
  <summary>Methodology</summary>
  <div class="content">
    <p>This assessment followed a structured multi-phase approach:</p>
    <ol>
      <li><strong>Reconnaissance</strong> — Subdomain enumeration, DNS, WHOIS, OSINT</li>
      <li><strong>Scanning</strong> — Port scanning, service fingerprinting, vulnerability scanning</li>
      <li><strong>Exploitation</strong> — Brute force, CVE exploitation, web application attacks</li>
      <li><strong>Post-Exploitation</strong> — Privilege escalation, credential harvesting, lateral movement</li>
      <li><strong>Reporting</strong> — ATT&CK mapping, graph visualisation, this report</li>
    </ol>
  </div>
</details>

<!-- Recommendations -->
<h2>Recommendations</h2>
<ol>
  <li>Enforce strong password policies and multi-factor authentication.</li>
  <li>Patch all services to the latest stable versions.</li>
  <li>Restrict network exposure of administrative interfaces.</li>
  <li>Implement network segmentation to limit lateral movement.</li>
  <li>Deploy endpoint detection &amp; response (EDR) solutions.</li>
  <li>Conduct regular penetration tests and red team assessments.</li>
</ol>

</div><!-- /.container -->

<script>
// Severity chart
const ctx = document.getElementById('sevChart').getContext('2d');
new Chart(ctx, {
  type: 'doughnut',
  data: {
    labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
    datasets: [{
      data: [{{ metrics.by_severity.critical }}, {{ metrics.by_severity.high }},
             {{ metrics.by_severity.medium }}, {{ metrics.by_severity.low }},
             {{ metrics.by_severity.info }}],
      backgroundColor: ['#f44336','#ff9800','#ffeb3b','#4caf50','#2196f3'],
      borderWidth: 0
    }]
  },
  options: {
    plugins: { legend: { labels: { color: '#e0e0e0' } },
               title: { display: true, text: 'Findings by Severity', color: '#e0e0e0' } },
    responsive: true
  }
});

// Sortable table
function sortTable(col) {
  const table = document.getElementById("findingsTable");
  const rows = Array.from(table.tBodies[0].rows);
  const asc = table.dataset.sortDir !== 'asc';
  table.dataset.sortDir = asc ? 'asc' : 'desc';
  rows.sort((a, b) => {
    const va = a.cells[col].textContent.trim();
    const vb = b.cells[col].textContent.trim();
    return asc ? va.localeCompare(vb) : vb.localeCompare(va);
  });
  rows.forEach(r => table.tBodies[0].appendChild(r));
}
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════
# 4. Plugin interface
# ═══════════════════════════════════════════════════════════════════════════

def metadata() -> dict[str, Any]:
    return {
        "name": "report_generator",
        "version": "1.0.0",
        "category": "reporting",
        "description": (
            "Generate dark-themed HTML + JSON reports with Chart.js graphs, "
            "collapsible sections, and sorted finding tables"
        ),
        "dependencies": ["jinja2", "groq"],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Plugin entry-point — generate and save HTML + JSON reports."""
    gen = ReportGenerator()
    report = gen.generate_full_report(context)

    return ExecutionResult(
        success=True,
        output={
            "html_path": state.get("report_paths", {}).get("html", ""),
            "json_path": state.get("report_paths", {}).get("json", ""),
            "risk_rating": report.metrics.get("risk_rating", ""),
            "findings_count": len(report.findings),
            "metrics": report.metrics,
        },
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
    print(json.dumps(res.output, indent=2, default=str))
