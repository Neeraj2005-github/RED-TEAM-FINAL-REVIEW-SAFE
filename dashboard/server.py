"""
dashboard/server.py — Flask + SocketIO real-time monitoring dashboard for the
AI Red Team Framework.

Features:
  * WebSocket-powered live event stream (plugged into core/event_bus.py)
  * REST API for querying targets, vulnerabilities, execution log
  * Simple token-based authentication
  * Dark-themed interactive dashboard pages

Run::

    python3 -m dashboard.server          # default port 5001
    DASHBOARD_TOKEN=secret python3 -m dashboard.server

Endpoints::

    GET  /                    Dashboard overview
    GET  /targets             Discovered hosts page
    GET  /vulnerabilities     Vulnerability list page
    GET  /exploitation        Exploitation timeline
    GET  /post-exploit        Post-exploit overview
    GET  /logs                Searchable event log

API::

    GET  /api/targets
    GET  /api/vulnerabilities?severity=critical
    GET  /api/execution_log
    GET  /api/metrics
    WS   /ws                  Live event stream (SocketIO)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime
from functools import wraps
from typing import Any

from flask import Flask, Response, jsonify, render_template_string, request

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.event_bus import Event, bus
from core.state_manager import state

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("DASHBOARD_SECRET", "redteam-dashboard-dev")

# Simple SocketIO support — try flask-socketio, fall back to SSE
_SOCKETIO_AVAILABLE = False
try:
    from flask_socketio import SocketIO, emit
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")
    _SOCKETIO_AVAILABLE = True
except ImportError:
    socketio = None  # type: ignore[assignment]

# Token auth
DASHBOARD_TOKEN = os.environ.get("DASHBOARD_TOKEN", "")

# In-memory event log (last N events)
_MAX_EVENT_LOG = 500
_event_log: list[dict[str, Any]] = []


# ---------------------------------------------------------------------------
# Auth middleware
# ---------------------------------------------------------------------------

def _auth_required(fn):  # type: ignore[type-arg]
    """Skip auth if DASHBOARD_TOKEN is empty (dev mode)."""
    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        if DASHBOARD_TOKEN:
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                token = request.args.get("token", "")
            if token != DASHBOARD_TOKEN:
                return jsonify({"error": "Unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Event bus → dashboard bridge
# ---------------------------------------------------------------------------

def _on_any_event(event: Event) -> None:
    """Catch every event from the bus and forward to connected clients."""
    entry = {
        "event_type": event.event_type,
        "payload": event.payload,
        "source": event.source,
        "timestamp": event.timestamp,
    }
    _event_log.append(entry)
    if len(_event_log) > _MAX_EVENT_LOG:
        _event_log.pop(0)

    if _SOCKETIO_AVAILABLE and socketio is not None:
        socketio.emit("event", entry, namespace="/ws")   # type: ignore[union-attr]


# Subscribe to common event types
_EVENT_TYPES = [
    "recon.complete", "recon.subdomains_found",
    "scan.complete", "scan.ports_open",
    "exploit.complete", "exploit.credentials_found", "exploit.rce_gained",
    "privesc.success", "privesc.failed",
    "persistence.documented",
    "lateral_movement.pivot_success",
    "credential_harvest.complete",
    "phase.transition", "phase.error",
    "report.complete",
]
for _evt in _EVENT_TYPES:
    bus.subscribe(_evt, _on_any_event)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api/targets")
@_auth_required
def api_targets() -> Response:
    """Return discovered hosts."""
    lat = state.get("lateral_movement", {})
    hosts = lat.get("hosts_discovered", [])
    target = state.get("target", "")
    if target and not any(h.get("ip") == target for h in hosts):
        hosts.insert(0, {"ip": target, "hostname": target, "target_value": "primary"})
    return jsonify({"targets": hosts})


@app.route("/api/vulnerabilities")
@_auth_required
def api_vulnerabilities() -> Response:
    """Return vulnerability / exploit findings, optionally filtered by severity."""
    severity = request.args.get("severity", "").lower()
    exploits = state.get("exploit_results", [])
    findings: list[dict[str, Any]] = []

    for item in exploits:
        sev = "critical" if item.get("success") else "info"
        if severity and sev != severity:
            continue
        findings.append({**item, "severity": sev})

    return jsonify({"vulnerabilities": findings, "total": len(findings)})


@app.route("/api/execution_log")
@_auth_required
def api_execution_log() -> Response:
    """Return the in-memory event log."""
    limit = int(request.args.get("limit", _MAX_EVENT_LOG))
    return jsonify({"events": _event_log[-limit:], "total": len(_event_log)})


@app.route("/api/metrics")
@_auth_required
def api_metrics() -> Response:
    """Return aggregated engagement metrics."""
    exploits = state.get("exploit_results", [])
    successes = [e for e in exploits if e.get("success")]
    lat = state.get("lateral_movement", {})
    matrix = state.get("attack_matrix", {})

    return jsonify({
        "target": state.get("target", ""),
        "hosts_discovered": lat.get("total_hosts", 0),
        "exploits_attempted": len(exploits),
        "exploits_succeeded": len(successes),
        "lateral_pivots": lat.get("total_pivots", 0),
        "mitre_coverage": matrix.get("mitre_coverage", 0),
        "techniques_used": matrix.get("total_techniques", 0),
        "events_logged": len(_event_log),
    })


@app.route("/api/state/<key>")
@_auth_required
def api_state_key(key: str) -> Response:
    """Get arbitrary state key (for debugging)."""
    data = state.get(key)
    if data is None:
        return jsonify({"error": f"Key '{key}' not found"}), 404
    return jsonify({key: data})


# ---------------------------------------------------------------------------
# SocketIO events (if available)
# ---------------------------------------------------------------------------

if _SOCKETIO_AVAILABLE and socketio is not None:
    @socketio.on("connect", namespace="/ws")  # type: ignore[misc]
    def _ws_connect() -> None:
        emit("connected", {"status": "ok", "events_buffered": len(_event_log)})

    @socketio.on("request_replay", namespace="/ws")  # type: ignore[misc]
    def _ws_replay(data: dict[str, Any]) -> None:
        """Replay the last N events to a newly connected client."""
        n = int(data.get("last", 50))
        for entry in _event_log[-n:]:
            emit("event", entry)


# ---------------------------------------------------------------------------
# Dashboard pages
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard_overview() -> str:
    return render_template_string(_DASHBOARD_HTML, page="overview")


@app.route("/targets")
def dashboard_targets() -> str:
    return render_template_string(_DASHBOARD_HTML, page="targets")


@app.route("/vulnerabilities")
def dashboard_vulnerabilities() -> str:
    return render_template_string(_DASHBOARD_HTML, page="vulnerabilities")


@app.route("/exploitation")
def dashboard_exploitation() -> str:
    return render_template_string(_DASHBOARD_HTML, page="exploitation")


@app.route("/post-exploit")
def dashboard_post_exploit() -> str:
    return render_template_string(_DASHBOARD_HTML, page="post_exploit")


@app.route("/logs")
def dashboard_logs() -> str:
    return render_template_string(_DASHBOARD_HTML, page="logs")


# ---------------------------------------------------------------------------
# HTML template (SPA-style, fetches data from API via JS)
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Red Team Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
  :root { --bg:#0f0f23; --bg2:#1a1a2e; --bg3:#16213e; --fg:#e0e0e0; --fg2:#888; --accent:#00bcd4; --red:#f44336; --green:#4caf50; --orange:#ff9800; --yellow:#ffeb3b; --purple:#9c27b0; --border:#333; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--fg); display:flex; min-height:100vh; }
  nav { width:220px; background:var(--bg2); padding:1rem 0; border-right:1px solid var(--border); position:fixed; height:100vh; overflow-y:auto; }
  nav h2 { color:var(--accent); font-size:1rem; padding:0.5rem 1rem; margin-bottom:1rem; }
  nav a { display:block; padding:0.7rem 1.2rem; color:var(--fg2); text-decoration:none; font-size:0.9rem; border-left:3px solid transparent; }
  nav a:hover, nav a.active { color:var(--accent); background:rgba(0,188,212,0.08); border-left-color:var(--accent); }
  main { margin-left:220px; flex:1; padding:2rem; }
  h1 { color:var(--accent); font-size:1.6rem; margin-bottom:1rem; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem; }
  .card { background:var(--bg2); border-radius:8px; padding:1.2rem; text-align:center; }
  .card .val { font-size:2rem; font-weight:bold; color:var(--accent); }
  .card .lbl { font-size:0.8rem; color:var(--fg2); }
  table { width:100%; border-collapse:collapse; margin-bottom:1.5rem; }
  th,td { padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); font-size:0.9rem; }
  th { background:var(--bg3); color:var(--accent); text-transform:uppercase; font-size:0.8rem; }
  tr:hover { background:rgba(0,188,212,0.04); }
  .badge { display:inline-block; padding:2px 8px; border-radius:3px; font-size:0.75rem; font-weight:bold; }
  .b-red { background:var(--red); color:#fff; } .b-orange { background:var(--orange); color:#000; }
  .b-green { background:var(--green); color:#fff; } .b-blue { background:var(--accent); color:#000; }
  #eventLog { background:var(--bg2); border-radius:8px; padding:1rem; max-height:500px; overflow-y:auto; font-family:monospace; font-size:0.85rem; }
  #eventLog .evt { padding:4px 0; border-bottom:1px solid var(--border); }
  .evt .ts { color:var(--fg2); font-size:0.75rem; }
  .evt .type { color:var(--accent); font-weight:bold; }
  .status-dot { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }
  .dot-green { background:var(--green); } .dot-red { background:var(--red); } .dot-orange { background:var(--orange); }
  .chart-box { background:var(--bg2); border-radius:8px; padding:1rem; margin-bottom:2rem; max-width:450px; }
  #searchLog { width:100%; padding:8px 12px; margin-bottom:1rem; background:var(--bg2); border:1px solid var(--border); color:var(--fg); border-radius:6px; font-size:0.9rem; }
  @media(max-width:768px){ nav{display:none;} main{margin-left:0;} }
</style>
</head>
<body>

<nav>
  <h2>🛡️ Red Team</h2>
  <a href="/" class="{{ 'active' if page=='overview' }}">Overview</a>
  <a href="/targets" class="{{ 'active' if page=='targets' }}">Targets</a>
  <a href="/vulnerabilities" class="{{ 'active' if page=='vulnerabilities' }}">Vulnerabilities</a>
  <a href="/exploitation" class="{{ 'active' if page=='exploitation' }}">Exploitation</a>
  <a href="/post-exploit" class="{{ 'active' if page=='post_exploit' }}">Post-Exploit</a>
  <a href="/logs" class="{{ 'active' if page=='logs' }}">Event Log</a>
</nav>

<main id="app">
  <h1 id="pageTitle">Loading…</h1>
  <div id="content"></div>
</main>

<script>
const PAGE = "{{ page }}";
const API = "";  // same origin
let metricsData = {};

async function api(path) {
  const r = await fetch(API + path);
  return r.json();
}

async function loadOverview() {
  document.getElementById("pageTitle").textContent = "Dashboard Overview";
  const m = await api("/api/metrics");
  metricsData = m;
  document.getElementById("content").innerHTML = `
    <div class="cards">
      <div class="card"><div class="val">${m.target||'—'}</div><div class="lbl">Target</div></div>
      <div class="card"><div class="val">${m.hosts_discovered}</div><div class="lbl">Hosts</div></div>
      <div class="card"><div class="val">${m.exploits_succeeded}/${m.exploits_attempted}</div><div class="lbl">Exploits</div></div>
      <div class="card"><div class="val">${m.lateral_pivots}</div><div class="lbl">Pivots</div></div>
      <div class="card"><div class="val">${m.techniques_used}</div><div class="lbl">ATT&CK Techniques</div></div>
      <div class="card"><div class="val">${m.mitre_coverage}%</div><div class="lbl">Coverage</div></div>
      <div class="card"><div class="val">${m.events_logged}</div><div class="lbl">Events</div></div>
    </div>
    <div class="chart-box"><canvas id="exploitChart" height="220"></canvas></div>
    <h2 style="color:var(--accent);margin-bottom:1rem">Live Events</h2>
    <div id="eventLog"></div>
  `;
  new Chart(document.getElementById("exploitChart"),{type:'doughnut',data:{labels:['Success','Failed'],datasets:[{data:[m.exploits_succeeded, m.exploits_attempted - m.exploits_succeeded],backgroundColor:['#4caf50','#f44336'],borderWidth:0}]},options:{plugins:{legend:{labels:{color:'#e0e0e0'}},title:{display:true,text:'Exploitation Results',color:'#e0e0e0'}},responsive:true}});
  startEventStream();
}

async function loadTargets() {
  document.getElementById("pageTitle").textContent = "Discovered Targets";
  const d = await api("/api/targets");
  let rows = d.targets.map(t => `<tr><td>${t.ip||''}</td><td>${t.hostname||'—'}</td><td>${(t.open_ports||[]).join(', ')||'—'}</td><td>${t.target_value||'—'}</td><td>${t.is_compromised?'<span class="badge b-red">YES</span>':'<span class="badge b-green">No</span>'}</td></tr>`).join('');
  document.getElementById("content").innerHTML = `<table><thead><tr><th>IP</th><th>Hostname</th><th>Ports</th><th>Value</th><th>Compromised</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadVulns() {
  document.getElementById("pageTitle").textContent = "Vulnerabilities";
  const d = await api("/api/vulnerabilities");
  let rows = d.vulnerabilities.map(v => `<tr><td><span class="badge ${v.success?'b-red':'b-blue'}">${v.severity}</span></td><td>${v.technique||''}</td><td>${v.port||''}</td><td>${v.success?'✔':'✘'}</td></tr>`).join('');
  document.getElementById("content").innerHTML = `<table><thead><tr><th>Severity</th><th>Technique</th><th>Port</th><th>Success</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadExploit() {
  document.getElementById("pageTitle").textContent = "Exploitation Timeline";
  const d = await api("/api/vulnerabilities");
  let rows = d.vulnerabilities.map(v => `<tr><td>${v.timestamp||'—'}</td><td>${v.technique||''}</td><td>${v.port||''}</td><td>${v.success?'<span class="badge b-green">Success</span>':'<span class="badge b-red">Failed</span>'}</td></tr>`).join('');
  document.getElementById("content").innerHTML = `<table><thead><tr><th>Time</th><th>Technique</th><th>Port</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function loadPostExploit() {
  document.getElementById("pageTitle").textContent = "Post-Exploitation";
  const m = await api("/api/metrics");
  const pe = await api("/api/state/privesc_results").catch(()=>({}));
  const lat = await api("/api/state/lateral_movement").catch(()=>({}));
  document.getElementById("content").innerHTML = `
    <div class="cards">
      <div class="card"><div class="val">${m.lateral_pivots}</div><div class="lbl">Pivots</div></div>
      <div class="card"><div class="val">${m.techniques_used}</div><div class="lbl">Techniques</div></div>
    </div>
    <h3 style="color:var(--accent);margin:1rem 0">Privesc Results</h3>
    <pre style="background:#0d0d1a;padding:1rem;border-radius:6px;color:#aaa;overflow-x:auto;max-height:300px">${JSON.stringify(pe,null,2)}</pre>
    <h3 style="color:var(--accent);margin:1rem 0">Lateral Movement</h3>
    <pre style="background:#0d0d1a;padding:1rem;border-radius:6px;color:#aaa;overflow-x:auto;max-height:300px">${JSON.stringify(lat,null,2)}</pre>
  `;
}

async function loadLogs() {
  document.getElementById("pageTitle").textContent = "Event Log";
  const d = await api("/api/execution_log?limit=200");
  let rows = d.events.map(e => `<div class="evt"><span class="ts">${e.timestamp}</span> <span class="type">${e.event_type}</span> <span style="color:#888">${e.source||''}</span> ${JSON.stringify(e.payload||{}).substring(0,120)}</div>`).reverse().join('');
  document.getElementById("content").innerHTML = `<input id="searchLog" placeholder="Filter events…" oninput="filterLogs()"><div id="eventLog">${rows}</div>`;
}

function filterLogs() {
  const q = document.getElementById("searchLog").value.toLowerCase();
  document.querySelectorAll("#eventLog .evt").forEach(el => {
    el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}

function startEventStream() {
  // Attempt SocketIO, fall back to polling
  if (typeof io !== 'undefined') {
    const sock = io("/ws");
    sock.on("event", (data) => appendEvent(data));
  } else {
    setInterval(async () => {
      const d = await api("/api/execution_log?limit=5");
      d.events.forEach(e => appendEvent(e));
    }, 3000);
  }
}

function appendEvent(e) {
  const log = document.getElementById("eventLog");
  if (!log) return;
  const div = document.createElement("div");
  div.className = "evt";
  div.innerHTML = `<span class="ts">${e.timestamp||''}</span> <span class="type">${e.event_type}</span> ${JSON.stringify(e.payload||{}).substring(0,100)}`;
  log.prepend(div);
  while (log.children.length > 200) log.lastChild.remove();
}

// Route
const routes = {overview:loadOverview,targets:loadTargets,vulnerabilities:loadVulns,exploitation:loadExploit,post_exploit:loadPostExploit,logs:loadLogs};
(routes[PAGE]||loadOverview)();
</script>
<!-- Optional: include socket.io client for WebSocket support -->
<script src="https://cdn.socket.io/4.7.4/socket.io.min.js" onerror="console.log('SocketIO client not loaded, using polling')"></script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Server runner
# ---------------------------------------------------------------------------

def run_dashboard(host: str = "0.0.0.0", port: int = 5001, debug: bool = False) -> None:
    """Start the dashboard server."""
    console_msg = f"Dashboard running at http://{host}:{port}"
    if DASHBOARD_TOKEN:
        console_msg += f"  (token auth enabled)"
    print(console_msg)

    if _SOCKETIO_AVAILABLE and socketio is not None:
        socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
    else:
        app.run(host=host, port=port, debug=debug)


# ---------------------------------------------------------------------------
# Stand-alone
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AI Red Team Dashboard")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()
    run_dashboard(args.host, args.port, args.debug)
