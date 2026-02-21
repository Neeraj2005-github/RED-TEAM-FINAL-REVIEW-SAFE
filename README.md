# 🔴 AI-Driven Red Team Framework

An AI-powered automated penetration testing pipeline that combines traditional offensive security tools with LLM-driven decision making. Runs reconnaissance, scanning, exploitation, privilege escalation, and persistence simulation — then generates a MITRE ATT&CK-mapped PDF report with an AI-written executive summary.

---

## Architecture

```
TARGET IP
    │
    ▼
┌──────────────────────┐
│  Phase 1: Recon      │  DNS · WHOIS · Subfinder · Shodan
│  T1595 / T1589       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 2: Scanning   │  masscan · nmap -sV -O · NVD CVE lookup
│  T1046 / T1082       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 3a: AI Engine │  Groq LLaMA 3.3 70B → attack decisions
│  (LLM Decision)      │  Ollama Mistral fallback
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 3b: Exploit   │  SSH brute · SMB enum · HTTP creds · FTP anon
│  T1110 / T1190       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 4a: PrivEsc   │  SUID · sudo -l · cron · writable configs
│  T1548 / T1574       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 4b: Persist   │  Simulated only — cron, rc.local, registry
│  T1053 / T1547       │
└──────────┬───────────┘
           ▼
┌──────────────────────┐
│  Phase 5: Reporting  │  PDF + JSON + Attack Graph PNG
│  AI Executive Summary│
└──────────────────────┘
```

---

## vs Existing Tools

| Capability            | This Framework   | Metasploit        |
|-----------------------|------------------|-------------------|
| Automation            | Fully automated  | Manual / scripted |
| AI-Driven Decisions   | ✅ LLM-powered   | ❌ No AI           |
| Report Quality        | PDF + AI summary | Basic text/XML    |
| MITRE ATT&CK Mapping | ✅ 16 techniques  | Partial           |
| Attack Graph          | ✅ Auto-generated | ❌ Manual           |
| Cost                  | Free (Groq tier) | Free / Pro $$$    |

---

## Quick Setup (Kali Linux)

```bash
# 1. System dependencies
sudo apt update && sudo apt install -y python3-pip nmap masscan golang-go

# 2. Install subfinder (Go)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin

# 3. Clone & install Python deps
git clone <repo-url> ai-redteam-framework
cd ai-redteam-framework
pip3 install -r requirements.txt

# 4. Configure API keys
#    Get a free key at https://console.groq.com
cat > .env <<EOF
GROQ_API_KEY=gsk_your_key_here
SHODAN_API_KEY=your_shodan_key_here
EOF

# 5. Run
python3 -m core.engine --target 192.168.1.10
```

---

## Usage

```bash
# Basic scan against a single host
python3 -m core.engine --target 192.168.1.10

# Scan a CIDR range
python3 -m core.engine --target 192.168.1.0/24

# Skip reconnaissance phase
python3 -m core.engine --target 192.168.1.10 --skip-recon

# Verbose output with custom wordlist
python3 -m core.engine --target 192.168.1.10 --verbose --wordlist wordlists/passwords_common.txt

# Start the web dashboard
python3 web/app.py        # open http://localhost:5000

# Run tests
pytest tests/ -v
```

---

## Module Reference

| Module        | File                    | Purpose                                      | MITRE Techniques             |
|---------------|-------------------------|----------------------------------------------|------------------------------|
| Recon         | `modules/recon.py`      | DNS, WHOIS, subdomain enum, Shodan           | T1595, T1589, T1596         |
| Scanner       | `modules/scanner.py`    | Port discovery, service detection, CVE lookup | T1046, T1082, T1016         |
| AI Decision   | `modules/ai_decision.py`| LLM-driven attack technique selection         | —                            |
| Exploit       | `modules/exploit.py`    | SSH brute, SMB enum, HTTP creds, FTP anon    | T1110.001, T1190, T1078     |
| PrivEsc       | `modules/privesc.py`    | SUID, sudo, cron, writable config checks     | T1548.001, T1574.009        |
| Persistence   | `modules/persistence.py`| Simulated persistence documentation           | T1053.003, T1547.001, T1037.004 |
| Reporter      | `modules/reporter.py`   | PDF report, JSON export, attack graph         | —                            |
| Engine        | `core/engine.py`        | Pipeline orchestrator with scope enforcement  | —                            |
| State Manager | `core/state_manager.py` | Thread-safe JSON state persistence            | —                            |
| Web Dashboard | `web/app.py`            | Flask UI for launching scans & viewing reports| —                            |

---

## MITRE ATT&CK Coverage

| ID         | Tactic                  | Technique Name                                  | Phase          |
|------------|-------------------------|-------------------------------------------------|----------------|
| T1595      | Reconnaissance          | Active Scanning                                 | Phase 1: Recon |
| T1589      | Reconnaissance          | Gather Victim Identity Information              | Phase 1: Recon |
| T1596      | Reconnaissance          | Search Open Technical Databases                 | Phase 1: Recon |
| T1046      | Discovery               | Network Service Discovery                       | Phase 2: Scan  |
| T1082      | Discovery               | System Information Discovery                    | Phase 2: Scan  |
| T1016      | Discovery               | System Network Configuration Discovery          | Phase 2: Scan  |
| T1110.001  | Credential Access       | Brute Force: Password Guessing                  | Phase 3: Exploit |
| T1190      | Initial Access          | Exploit Public-Facing Application               | Phase 3: Exploit |
| T1078      | Initial Access          | Valid Accounts                                  | Phase 3: Exploit |
| T1021.002  | Lateral Movement        | Remote Services: SMB/Windows Admin Shares       | Phase 3: Exploit |
| T1548.001  | Privilege Escalation    | Abuse Elevation Control: Setuid/Setgid          | Phase 4: PrivEsc |
| T1574.009  | Privilege Escalation    | Hijack Execution Flow: Path Hijacking           | Phase 4: PrivEsc |
| T1053.003  | Persistence             | Scheduled Task/Job: Cron                        | Phase 4: Persist |
| T1547.001  | Persistence             | Boot or Logon Autostart: Registry Run Keys      | Phase 4: Persist |
| T1037.004  | Persistence             | Boot or Logon Initialization Scripts: RC Scripts | Phase 4: Persist |
| T1005      | Collection              | Data from Local System                          | Phase 5: Report |

---

## Lab Setup

### Recommended Environment

1. **VirtualBox** (or VMware) with two VMs on a host-only network:
   - **Kali Linux** (attacker) — latest rolling release
   - **Metasploitable 2** (target) — intentionally vulnerable Ubuntu

2. **Network configuration:**
   ```
   Host-only adapter: 192.168.56.0/24
   Kali:              192.168.56.101
   Metasploitable 2:  192.168.56.102
   ```

3. **Quick test:**
   ```bash
   # From Kali
   ping 192.168.56.102
   python3 -m core.engine --target 192.168.56.102 --verbose
   ```

### Getting Metasploitable 2

```bash
# Download from SourceForge
wget https://sourceforge.net/projects/metasploitable/files/Metasploitable2/metasploitable-linux-2.0.0.zip
unzip metasploitable-linux-2.0.0.zip
# Import the .vmdk into VirtualBox as a new VM
# Default credentials: msfadmin / msfadmin
```

---

## Ethical Disclaimer

> **⚠️ This tool is for authorised testing only.**
>
> The scope-enforcement code in `core/engine.py` **blocks all non-RFC 1918 targets**
> (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8).
>
> **Use this tool only on systems you own or have explicit written permission to test.**
> Unauthorised access to computer systems is illegal under the Computer Fraud and Abuse
> Act (CFAA), the UK Computer Misuse Act, and equivalent laws worldwide.
>
> The persistence module is **simulation-only** — no actual backdoors are deployed.

---

## License & Academic Context

**MIT License** — see `LICENSE` for details.

Created as a credit-waiver submission demonstrating knowledge of offensive security,
AI/LLM integration, MITRE ATT&CK methodology, and automated penetration testing
pipeline design.
