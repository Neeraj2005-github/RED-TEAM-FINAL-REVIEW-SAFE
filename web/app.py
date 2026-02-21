"""
web/app.py - AI Red Team Framework Web Dashboard
Run with: python3 web/app.py
Access at: http://localhost:5000
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template_string, request, jsonify, send_file, abort
import ipaddress
import threading
import json
import glob
from datetime import datetime

app = Flask(__name__)

# ── Allowed private IP ranges (RFC1918 only) ─────────────────────────────────
ALLOWED_RANGES = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
]

# ── Global scan status ────────────────────────────────────────────────────────
scan_status = {
    "running": False,
    "current_phase": "",
    "phases_done": [],
    "error": None,
    "target": None,
    "start_time": None,
    "completed": False,
    "latest_report": None
}

# ── IP Validation ─────────────────────────────────────────────────────────────
def validate_ip(target: str) -> tuple[bool, str]:
    """Returns (is_valid, error_message)"""
    target = target.strip()

    if not target:
        return False, "IP address cannot be empty."

    # Block obvious bad inputs
    if any(c in target for c in [';', '&', '|', '$', '`', '>', '<', ' ']):
        return False, "Invalid characters in IP address."

    try:
        # Parse IP (handle CIDR like 192.168.1.0/24)
        ip_str = target.split('/')[0]
        ip = ipaddress.ip_address(ip_str)

        # Check if private
        in_range = any(ip in net for net in ALLOWED_RANGES)
        if not in_range:
            return False, f"❌ IP {target} is a PUBLIC address. This tool only works on private lab IPs (192.168.x.x, 10.x.x.x, 172.16-31.x.x). Scanning public IPs without permission is ILLEGAL."

        return True, ""

    except ValueError:
        return False, f"'{target}' is not a valid IP address. Use format: 192.168.56.102"


# ── Background scan runner ────────────────────────────────────────────────────
def run_scan_background(target: str):
    global scan_status
    scan_status["running"] = True
    scan_status["target"] = target
    scan_status["start_time"] = datetime.now().isoformat()
    scan_status["phases_done"] = []
    scan_status["error"] = None
    scan_status["completed"] = False

    try:
        from core.state_manager import state
        state.set('target', target)

        phases = [
            ("Phase 1: Reconnaissance", "modules.recon", "run_recon", [target]),
            ("Phase 2: Port Scanning",  "modules.scanner", "run_scanner", [target]),
            ("Phase 3a: AI Decision",   "modules.ai_decision", "run_ai_decision", []),
            ("Phase 3b: Exploitation",  "modules.exploit", "run_exploits", []),
            ("Phase 4a: Privilege Escalation", "modules.privesc", "run_privesc", []),
            ("Phase 4b: Persistence",   "modules.persistence", "run_persistence", []),
            ("Phase 5: Report Generation", "modules.reporter", "run_reporter", []),
        ]

        for phase_name, module_path, func_name, args in phases:
            scan_status["current_phase"] = phase_name
            import importlib
            mod = importlib.import_module(module_path)
            func = getattr(mod, func_name)
            result = func(*args)
            scan_status["phases_done"].append(phase_name)

            if phase_name == "Phase 5: Report Generation" and isinstance(result, dict):
                pdf_path = result.get("pdf")
                if pdf_path and os.path.exists(pdf_path):
                    scan_status["latest_report"] = os.path.basename(pdf_path)

        scan_status["completed"] = True

    except Exception as e:
        scan_status["error"] = str(e)
    finally:
        scan_status["running"] = False
        scan_status["current_phase"] = ""


# ── HTML Template ─────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AI Red Team Framework</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #080c10;
    --surface: #0d1117;
    --surface2: #161b22;
    --border: #21262d;
    --red: #ff3333;
    --red-dim: #cc0000;
    --green: #00ff88;
    --green-dim: #00cc66;
    --blue: #58a6ff;
    --yellow: #ffd700;
    --orange: #ff8c00;
    --text: #c9d1d9;
    --text-dim: #6e7681;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Rajdhani', sans-serif;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    background-image:
      radial-gradient(ellipse at 20% 10%, rgba(255,51,51,0.04) 0%, transparent 50%),
      radial-gradient(ellipse at 80% 90%, rgba(88,166,255,0.04) 0%, transparent 50%);
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg, transparent, transparent 2px,
      rgba(0,0,0,0.05) 2px, rgba(0,0,0,0.05) 4px
    );
    pointer-events: none;
    z-index: 1000;
  }

  header {
    border-bottom: 1px solid var(--border);
    padding: 20px 40px;
    display: flex;
    align-items: center;
    gap: 20px;
    background: rgba(13,17,23,0.95);
    backdrop-filter: blur(10px);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    width: 40px; height: 40px;
    border: 2px solid var(--red);
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
    animation: pulse-border 2s infinite;
  }

  @keyframes pulse-border {
    0%, 100% { box-shadow: 0 0 0 0 rgba(255,51,51,0.4); }
    50% { box-shadow: 0 0 0 8px rgba(255,51,51,0); }
  }

  .header-text h1 {
    font-size: 22px; font-weight: 700; letter-spacing: 3px;
    color: #fff; text-transform: uppercase;
  }

  .header-text p {
    font-family: var(--mono); font-size: 11px; color: var(--text-dim);
    letter-spacing: 1px;
  }

  .status-indicator {
    margin-left: auto;
    display: flex; align-items: center; gap: 8px;
    font-family: var(--mono); font-size: 12px;
  }

  .dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--text-dim);
  }
  .dot.active { background: var(--green); animation: blink 1s infinite; }
  .dot.error { background: var(--red); }

  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

  main { max-width: 1100px; margin: 0 auto; padding: 40px 20px; }

  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .card-header {
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 10px;
    background: var(--surface2);
  }

  .card-header h2 {
    font-size: 13px; font-weight: 600; letter-spacing: 2px;
    text-transform: uppercase; color: var(--text-dim);
  }

  .card-header .icon { font-size: 16px; }

  .card-body { padding: 24px; }

  /* ── IP Input Form ── */
  .ip-form { display: flex; flex-direction: column; gap: 16px; }

  .input-group { display: flex; flex-direction: column; gap: 6px; }

  .input-group label {
    font-family: var(--mono); font-size: 11px;
    color: var(--text-dim); letter-spacing: 1px; text-transform: uppercase;
  }

  .ip-input-wrap { position: relative; }

  .ip-input {
    width: 100%;
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px 16px 12px 44px;
    color: var(--green);
    font-family: var(--mono);
    font-size: 16px;
    letter-spacing: 2px;
    outline: none;
    transition: border-color 0.2s, box-shadow 0.2s;
  }

  .ip-input:focus {
    border-color: var(--blue);
    box-shadow: 0 0 0 3px rgba(88,166,255,0.1);
  }

  .ip-input.valid { border-color: var(--green); }
  .ip-input.invalid { border-color: var(--red); }

  .ip-prefix {
    position: absolute; left: 14px; top: 50%; transform: translateY(-50%);
    font-family: var(--mono); font-size: 14px; color: var(--text-dim);
  }

  .validation-msg {
    font-family: var(--mono); font-size: 11px;
    padding: 8px 12px; border-radius: 4px;
    display: none;
  }

  .validation-msg.error {
    display: block;
    background: rgba(255,51,51,0.1);
    border: 1px solid rgba(255,51,51,0.3);
    color: var(--red);
  }

  .validation-msg.success {
    display: block;
    background: rgba(0,255,136,0.08);
    border: 1px solid rgba(0,255,136,0.3);
    color: var(--green);
  }

  .examples {
    display: flex; gap: 8px; flex-wrap: wrap;
  }

  .example-chip {
    font-family: var(--mono); font-size: 11px;
    padding: 4px 10px; border-radius: 4px;
    background: var(--surface2); border: 1px solid var(--border);
    color: var(--text-dim); cursor: pointer;
    transition: all 0.15s;
  }

  .example-chip:hover {
    border-color: var(--blue); color: var(--blue);
  }

  .launch-btn {
    width: 100%;
    padding: 14px;
    background: var(--red);
    border: none; border-radius: 6px;
    color: #fff;
    font-family: var(--sans); font-size: 15px; font-weight: 700;
    letter-spacing: 3px; text-transform: uppercase;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
    overflow: hidden;
  }

  .launch-btn:hover:not(:disabled) {
    background: var(--red-dim);
    box-shadow: 0 0 20px rgba(255,51,51,0.4);
    transform: translateY(-1px);
  }

  .launch-btn:disabled {
    opacity: 0.5; cursor: not-allowed; transform: none;
  }

  .launch-btn .btn-spinner {
    display: none;
    width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
    margin: 0 auto;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  /* ── Status Panel ── */
  .phase-list { display: flex; flex-direction: column; gap: 8px; }

  .phase-item {
    display: flex; align-items: center; gap: 12px;
    padding: 10px 14px; border-radius: 6px;
    background: var(--surface2);
    border: 1px solid var(--border);
    font-family: var(--mono); font-size: 12px;
    transition: all 0.3s;
  }

  .phase-item.done {
    border-color: rgba(0,255,136,0.3);
    background: rgba(0,255,136,0.05);
    color: var(--green);
  }

  .phase-item.active {
    border-color: rgba(88,166,255,0.5);
    background: rgba(88,166,255,0.08);
    color: var(--blue);
    box-shadow: 0 0 12px rgba(88,166,255,0.1);
  }

  .phase-item.error-phase {
    border-color: rgba(255,51,51,0.4);
    color: var(--red);
  }

  .phase-icon { width: 20px; text-align: center; font-size: 14px; }

  .target-display {
    font-family: var(--mono); font-size: 12px;
    color: var(--text-dim); margin-bottom: 16px;
    padding: 8px 14px; background: var(--surface2);
    border-radius: 6px; border: 1px solid var(--border);
  }

  .target-display span { color: var(--yellow); }

  /* ── Reports ── */
  .reports-list { display: flex; flex-direction: column; gap: 8px; }

  .report-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px; border-radius: 6px;
    background: var(--surface2); border: 1px solid var(--border);
    transition: border-color 0.2s;
  }

  .report-item:hover { border-color: var(--blue); }

  .report-name {
    font-family: var(--mono); font-size: 11px; color: var(--text-dim);
  }

  .report-name strong { color: var(--text); font-size: 12px; }

  .download-btn {
    padding: 6px 14px; border-radius: 4px;
    background: transparent; border: 1px solid var(--blue);
    color: var(--blue); font-family: var(--mono); font-size: 11px;
    cursor: pointer; text-decoration: none;
    transition: all 0.2s; display: inline-block;
  }

  .download-btn:hover {
    background: var(--blue); color: var(--bg);
  }

  .empty-state {
    text-align: center; padding: 30px;
    font-family: var(--mono); font-size: 12px; color: var(--text-dim);
  }

  /* ── Error box ── */
  .error-box {
    display: none;
    margin-top: 12px; padding: 12px 16px;
    background: rgba(255,51,51,0.08);
    border: 1px solid rgba(255,51,51,0.3);
    border-radius: 6px;
    font-family: var(--mono); font-size: 12px; color: var(--red);
  }

  /* ── Full width card ── */
  .full-width { grid-column: 1 / -1; }

  .security-notice {
    padding: 14px 20px;
    background: rgba(255,140,0,0.08);
    border: 1px solid rgba(255,140,0,0.25);
    border-radius: 6px;
    font-family: var(--mono); font-size: 11px;
    color: var(--orange); line-height: 1.8;
    margin-bottom: 24px;
  }

  .security-notice strong { color: var(--yellow); }

  /* ── Progress bar ── */
  .progress-wrap {
    height: 3px; background: var(--border);
    border-radius: 2px; overflow: hidden; margin-top: 16px;
  }

  .progress-bar {
    height: 100%; background: var(--blue);
    border-radius: 2px; width: 0%;
    transition: width 0.5s ease;
    box-shadow: 0 0 8px var(--blue);
  }

  .elapsed { font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-top: 6px; }

  .complete-banner {
    display: none;
    margin-top: 16px; padding: 14px;
    background: rgba(0,255,136,0.08);
    border: 1px solid rgba(0,255,136,0.3);
    border-radius: 6px;
    text-align: center;
    font-family: var(--mono); font-size: 13px; color: var(--green);
  }
</style>
</head>
<body>

<header>
  <div class="logo">🔴</div>
  <div class="header-text">
    <h1>AI Red Team Framework</h1>
    <p>AUTOMATED PENETRATION TESTING PLATFORM · AUTHORIZED LAB USE ONLY</p>
  </div>
  <div class="status-indicator">
    <div class="dot" id="statusDot"></div>
    <span id="statusText">IDLE</span>
  </div>
</header>

<main>

  <div class="security-notice">
    <strong>⚠ SECURITY NOTICE:</strong>
    This tool only accepts <strong>private RFC1918 IP addresses</strong>
    (192.168.x.x · 10.x.x.x · 172.16-31.x.x).
    Scanning public IPs without written authorization is <strong>illegal</strong>.
    Use only on lab VMs you own or have explicit permission to test.
  </div>

  <div class="grid">

    <!-- ── Scan Input Card ── -->
    <div class="card">
      <div class="card-header">
        <span class="icon">🎯</span>
        <h2>Target Configuration</h2>
      </div>
      <div class="card-body">
        <div class="ip-form">

          <div class="input-group">
            <label>Target IP Address</label>
            <div class="ip-input-wrap">
              <span class="ip-prefix">⬡</span>
              <input
                type="text"
                class="ip-input"
                id="targetInput"
                placeholder="192.168.56.102"
                maxlength="18"
                autocomplete="off"
                spellcheck="false"
              >
            </div>
            <div class="validation-msg" id="validationMsg"></div>
          </div>

          <div class="input-group">
            <label>Quick Select (Lab IPs)</label>
            <div class="examples">
              <span class="example-chip" onclick="setIP('192.168.56.101')">192.168.56.101</span>
              <span class="example-chip" onclick="setIP('192.168.56.102')">192.168.56.102</span>
              <span class="example-chip" onclick="setIP('10.0.2.4')">10.0.2.4</span>
              <span class="example-chip" onclick="setIP('172.16.0.1')">172.16.0.1</span>
            </div>
          </div>

          <button class="launch-btn" id="launchBtn" onclick="launchScan()">
            <span id="btnText">⚡ LAUNCH SCAN</span>
            <div class="btn-spinner" id="btnSpinner"></div>
          </button>

          <div class="error-box" id="errorBox"></div>
        </div>
      </div>
    </div>

    <!-- ── Live Status Card ── -->
    <div class="card">
      <div class="card-header">
        <span class="icon">📡</span>
        <h2>Live Status</h2>
      </div>
      <div class="card-body">

        <div class="target-display" id="targetDisplay">
          TARGET: <span id="currentTarget">—</span>
        </div>

        <div class="phase-list" id="phaseList">
          <div class="phase-item" data-phase="Phase 1: Reconnaissance">
            <span class="phase-icon">⬜</span> Phase 1: Reconnaissance
          </div>
          <div class="phase-item" data-phase="Phase 2: Port Scanning">
            <span class="phase-icon">⬜</span> Phase 2: Port Scanning
          </div>
          <div class="phase-item" data-phase="Phase 3a: AI Decision">
            <span class="phase-icon">⬜</span> Phase 3a: AI Decision Engine
          </div>
          <div class="phase-item" data-phase="Phase 3b: Exploitation">
            <span class="phase-icon">⬜</span> Phase 3b: Exploitation
          </div>
          <div class="phase-item" data-phase="Phase 4a: Privilege Escalation">
            <span class="phase-icon">⬜</span> Phase 4a: Privilege Escalation
          </div>
          <div class="phase-item" data-phase="Phase 4b: Persistence">
            <span class="phase-icon">⬜</span> Phase 4b: Persistence
          </div>
          <div class="phase-item" data-phase="Phase 5: Report Generation">
            <span class="phase-icon">⬜</span> Phase 5: Report Generation
          </div>
        </div>

        <div class="progress-wrap">
          <div class="progress-bar" id="progressBar"></div>
        </div>
        <div class="elapsed" id="elapsed"></div>

        <div class="complete-banner" id="completeBanner">
          ✅ SCAN COMPLETE — Download your report below
        </div>
      </div>
    </div>

    <!-- ── Download Card ── -->
    <div class="card full-width" id="downloadCard" style="display:none;">
      <div class="card-header">
        <span class="icon">📄</span>
        <h2>Report Ready</h2>
      </div>
      <div class="card-body" style="display:flex; align-items:center; justify-content:space-between; gap:16px;">
        <div>
          <div style="font-family:var(--mono); font-size:13px; color:var(--green); margin-bottom:4px;">✅ Scan complete — your report is ready</div>
          <div style="font-family:var(--mono); font-size:11px; color:var(--text-dim);" id="reportFilename">—</div>
        </div>
        <a id="downloadBtn" href="#" download
          style="padding:14px 32px; background:var(--green); border-radius:6px;
                 color:#000; font-family:var(--sans); font-size:15px; font-weight:700;
                 letter-spacing:2px; text-transform:uppercase; text-decoration:none;">
          ⬇ DOWNLOAD PDF
        </a>
      </div>
    </div>

  </div>
</main>

<script>
  const PHASES = [
    "Phase 1: Reconnaissance",
    "Phase 2: Port Scanning",
    "Phase 3a: AI Decision",
    "Phase 3b: Exploitation",
    "Phase 4a: Privilege Escalation",
    "Phase 4b: Persistence",
    "Phase 5: Report Generation"
  ];

  let pollInterval = null;
  let startTime = null;
  let elapsedInterval = null;

  // ── IP Validation (client-side) ──────────────────────────────────────────
  function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    const [a, b] = parts;
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168)
    );
  }

  function validateInput(ip) {
    ip = ip.trim();
    const msg = document.getElementById('validationMsg');
    const input = document.getElementById('targetInput');
    const btn = document.getElementById('launchBtn');

    if (!ip) {
      msg.className = 'validation-msg';
      input.className = 'ip-input';
      btn.disabled = true;
      return false;
    }

    // Check for shell injection
    if (/[;&|$`<> ]/.test(ip)) {
      msg.className = 'validation-msg error';
      msg.textContent = '❌ Invalid characters detected.';
      input.className = 'ip-input invalid';
      btn.disabled = true;
      return false;
    }

    const ipOnly = ip.split('/')[0];
    const parts = ipOnly.split('.');

    if (parts.length !== 4 || !parts.every(p => /^\d+$/.test(p) && +p >= 0 && +p <= 255)) {
      msg.className = 'validation-msg error';
      msg.textContent = '❌ Not a valid IP. Use format: 192.168.56.102';
      input.className = 'ip-input invalid';
      btn.disabled = true;
      return false;
    }

    if (!isPrivateIP(ipOnly)) {
      msg.className = 'validation-msg error';
      msg.textContent = '🚫 PUBLIC IP BLOCKED. Only private lab IPs allowed (192.168.x.x, 10.x.x.x, 172.16-31.x.x).';
      input.className = 'ip-input invalid';
      btn.disabled = true;
      return false;
    }

    msg.className = 'validation-msg success';
    msg.textContent = '✓ Valid private IP — ready to scan';
    input.className = 'ip-input valid';
    btn.disabled = false;
    return true;
  }

  document.getElementById('targetInput').addEventListener('input', e => {
    validateInput(e.target.value);
  });

  function setIP(ip) {
    document.getElementById('targetInput').value = ip;
    validateInput(ip);
  }

  // ── Launch Scan ───────────────────────────────────────────────────────────
  async function launchScan() {
    const target = document.getElementById('targetInput').value.trim();
    if (!validateInput(target)) return;

    // Reset UI
    resetPhases();
    document.getElementById('errorBox').style.display = 'none';
    document.getElementById('completeBanner').style.display = 'none';
    document.getElementById('downloadCard').style.display = 'none';
    document.getElementById('currentTarget').textContent = target;

    // Button loading state
    const btn = document.getElementById('launchBtn');
    btn.disabled = true;
    document.getElementById('btnText').style.display = 'none';
    document.getElementById('btnSpinner').style.display = 'block';

    // Status dot
    document.getElementById('statusDot').className = 'dot active';
    document.getElementById('statusText').textContent = 'SCANNING';

    startTime = Date.now();
    elapsedInterval = setInterval(updateElapsed, 1000);

    try {
      const res = await fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target })
      });
      const data = await res.json();

      if (!res.ok || data.error) {
        showError(data.error || 'Server rejected the request.');
        resetBtn();
        return;
      }

      // Start polling
      pollInterval = setInterval(pollStatus, 2000);

    } catch (err) {
      showError('Failed to connect to server: ' + err.message);
      resetBtn();
    }
  }

  // ── Poll Status ───────────────────────────────────────────────────────────
  async function pollStatus() {
    try {
      const res = await fetch('/status');
      const data = await res.json();

      updatePhaseUI(data);

      if (!data.running && data.completed) {
        clearInterval(pollInterval);
        clearInterval(elapsedInterval);
        resetBtn();
        document.getElementById('statusDot').className = 'dot';
        document.getElementById('statusDot').style.background = 'var(--green)';
        document.getElementById('statusText').textContent = 'COMPLETE';
        document.getElementById('completeBanner').style.display = 'block';
        showDownloadButton(data.latest_report);
      }

      if (data.error) {
        clearInterval(pollInterval);
        clearInterval(elapsedInterval);
        showError('Scan error: ' + data.error);
        resetBtn();
        document.getElementById('statusDot').className = 'dot error';
        document.getElementById('statusText').textContent = 'ERROR';
      }

    } catch (e) { /* ignore network blip */ }
  }

  // ── Update Phase UI ───────────────────────────────────────────────────────
  function updatePhaseUI(data) {
    const items = document.querySelectorAll('.phase-item');
    const done = data.phases_done || [];
    const current = data.current_phase || '';

    let doneCount = 0;

    items.forEach(item => {
      const phase = item.dataset.phase;
      const isDone = done.some(d => d.startsWith(phase.split(':')[0]));
      const isActive = current.startsWith(phase.split(':')[0]);

      item.className = 'phase-item';
      if (isDone) {
        item.className = 'phase-item done';
        item.querySelector('.phase-icon').textContent = '✅';
        doneCount++;
      } else if (isActive) {
        item.className = 'phase-item active';
        item.querySelector('.phase-icon').textContent = '⚡';
      } else {
        item.querySelector('.phase-icon').textContent = '⬜';
      }
    });

    const pct = Math.round((doneCount / PHASES.length) * 100);
    document.getElementById('progressBar').style.width = pct + '%';
  }

  // ── Download Button ────────────────────────────────────────────────────────
  function showDownloadButton(filename) {
    if (!filename) return;
    document.getElementById('downloadCard').style.display = 'block';
    document.getElementById('downloadBtn').href = '/report/' + filename;
    document.getElementById('downloadBtn').setAttribute('download', filename);
    document.getElementById('reportFilename').textContent = filename;
  }

  // ── Helpers ───────────────────────────────────────────────────────────────
  function resetPhases() {
    document.querySelectorAll('.phase-item').forEach(item => {
      item.className = 'phase-item';
      item.querySelector('.phase-icon').textContent = '⬜';
    });
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('elapsed').textContent = '';
  }

  function resetBtn() {
    const btn = document.getElementById('launchBtn');
    btn.disabled = false;
    document.getElementById('btnText').style.display = 'block';
    document.getElementById('btnSpinner').style.display = 'none';
  }

  function showError(msg) {
    const box = document.getElementById('errorBox');
    box.textContent = '⚠ ' + msg;
    box.style.display = 'block';
  }

  function updateElapsed() {
    const sec = Math.floor((Date.now() - startTime) / 1000);
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    document.getElementById('elapsed').textContent =
      `Elapsed: ${m}m ${s.toString().padStart(2,'0')}s`;
  }

  // ── Init ──────────────────────────────────────────────────────────────────
  document.getElementById('launchBtn').disabled = true;
</script>
</body>
</html>"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template_string(HTML)


@app.route('/scan', methods=['POST'])
def start_scan():
    global scan_status

    if scan_status["running"]:
        return jsonify({"error": "A scan is already running. Wait for it to finish."}), 400

    data = request.get_json()
    if not data or 'target' not in data:
        return jsonify({"error": "No target IP provided."}), 400

    target = str(data['target']).strip()

    # Server-side validation (never trust client alone)
    valid, error_msg = validate_ip(target)
    if not valid:
        return jsonify({"error": error_msg}), 400

    # Start scan in background thread
    thread = threading.Thread(target=run_scan_background, args=(target,), daemon=True)
    thread.start()

    return jsonify({"status": "started", "message": f"Scan started for {target}"})


@app.route('/status')
def get_status():
    return jsonify(scan_status)


@app.route('/report/<filename>')
def download_report(filename):
    if not filename.endswith('.pdf') or '/' in filename or '..' in filename:
        abort(400)

    reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
    file_path = os.path.join(reports_dir, filename)

    if not os.path.exists(file_path):
        abort(404)

    # Read into memory then delete from server
    with open(file_path, 'rb') as f:
        pdf_data = f.read()
    try:
        os.remove(file_path)
        scan_status["latest_report"] = None
    except Exception:
        pass

    from flask import Response
    return Response(
        pdf_data,
        mimetype='application/pdf',
        headers={
            'Content-Disposition': f'attachment; filename="{filename}"',
            'Content-Length': str(len(pdf_data))
        }
    )


if __name__ == '__main__':
    print("\n🔴 AI Red Team Framework — Web Dashboard")
    print("━" * 45)
    print("📡 Starting server at: http://localhost:5000")
    print("⚠  Lab use only. RFC1918 IPs enforced.")
    print("━" * 45 + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False)
