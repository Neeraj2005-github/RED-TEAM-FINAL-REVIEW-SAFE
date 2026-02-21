"""
mitre/attack_map.py — MITRE ATT&CK technique database and action mapper.

Provides:
* ``AttackTechnique`` dataclass with id, name, tactic, mitigations, detections.
* ``ATTACK_DB`` — ~200 techniques commonly used in red-team engagements.
* ``TechniqueMapper`` — maps free-text actions (e.g. "port scan") to
  matching techniques.
* ``AttackMatrix`` — aggregates techniques executed in an engagement and
  computes coverage metrics.

Usage::

    from mitre.attack_map import ATTACK_DB, TechniqueMapper, AttackMatrix

    mapper = TechniqueMapper()
    techs  = mapper.map_action_to_techniques("SSH brute force")
    matrix = AttackMatrix()
    matrix.add_technique(techs[0])
    print(matrix.mitre_coverage)
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from core.plugin_loader import ExecutionContext, ExecutionResult


# ═══════════════════════════════════════════════════════════════════════════
# 1. Data structures
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class AttackTechnique:
    """One MITRE ATT&CK (sub-)technique."""

    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    description: str = ""
    mitigations: list[str] = field(default_factory=list)
    detection: list[str] = field(default_factory=list)
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url and self.technique_id:
            tid = self.technique_id.replace(".", "/")
            self.url = f"https://attack.mitre.org/techniques/{tid}/"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackMatrix:
    """Tracks every technique observed during an engagement."""

    techniques_executed: list[AttackTechnique] = field(default_factory=list)
    _seen_ids: set[str] = field(default_factory=set, repr=False)

    # ── mutators ──────────────────────────────────────────────────────
    def add_technique(self, tech: AttackTechnique) -> None:
        if tech.technique_id not in self._seen_ids:
            self._seen_ids.add(tech.technique_id)
            self.techniques_executed.append(tech)

    def add_techniques(self, techs: list[AttackTechnique]) -> None:
        for t in techs:
            self.add_technique(t)

    # ── queries ───────────────────────────────────────────────────────
    @property
    def tactics_covered(self) -> list[str]:
        return sorted({t.tactic for t in self.techniques_executed})

    @property
    def mitre_coverage(self) -> float:
        """Percentage of known red-team techniques in the DB that were executed."""
        if not ATTACK_DB:
            return 0.0
        return round(len(self._seen_ids) / len(ATTACK_DB) * 100, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques_executed": [t.to_dict() for t in self.techniques_executed],
            "tactics_covered": self.tactics_covered,
            "mitre_coverage": self.mitre_coverage,
            "total_techniques": len(self.techniques_executed),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2. ATT&CK Database (~200 techniques)
# ═══════════════════════════════════════════════════════════════════════════
#
# Organised by tactic (kill-chain phase).  Each entry is a tuple:
#   (technique_id, technique_name, tactic, description,
#    [mitigations], [detection])
#

def _t(
    tid: str, name: str, tactic: str,
    desc: str = "",
    mitigations: list[str] | None = None,
    detection: list[str] | None = None,
) -> AttackTechnique:
    return AttackTechnique(
        technique_id=tid,
        technique_name=name,
        tactic=tactic,
        description=desc,
        mitigations=mitigations or [],
        detection=detection or [],
    )


# fmt: off
ATTACK_DB: dict[str, AttackTechnique] = {}

_RAW: list[AttackTechnique] = [
    # ── Reconnaissance ────────────────────────────────────────────────
    _t("T1595",     "Active Scanning",                        "Reconnaissance",
        "Adversaries scan victim IP ranges to gather information.",
        ["Pre-compromise monitoring", "Firewall rules"],
        ["Network IDS", "Web server logs"]),
    _t("T1595.001", "Active Scanning: Scanning IP Blocks",    "Reconnaissance",
        "Scan IP blocks to identify live hosts.",
        ["Rate limiting", "Firewall ingress rules"],
        ["Netflow analysis", "IDS signatures"]),
    _t("T1595.002", "Active Scanning: Vulnerability Scanning","Reconnaissance",
        "Run vulnerability scanners against targets.",
        ["Patch management", "WAF"],
        ["IDS", "SIEM correlation"]),
    _t("T1595.003", "Active Scanning: Wordlist Scanning",     "Reconnaissance",
        "Brute-force discover hidden web resources.",
        ["Rate limiting", "WAF"],
        ["Web access logs", "Anomaly detection"]),
    _t("T1590",     "Gather Victim Network Information",      "Reconnaissance",
        "Collect network topology, ranges, DNS details.",
        ["Limit public exposure"],
        ["DNS query logs"]),
    _t("T1590.001", "Gather Victim Network Info: Domain Properties", "Reconnaissance"),
    _t("T1590.002", "Gather Victim Network Info: DNS",        "Reconnaissance"),
    _t("T1590.004", "Gather Victim Network Info: Network Topology", "Reconnaissance"),
    _t("T1590.005", "Gather Victim Network Info: IP Addresses","Reconnaissance"),
    _t("T1591",     "Gather Victim Org Information",          "Reconnaissance",
        "Collect org structure, business relationships.",
        ["Limit public info"],
        ["OSINT monitoring"]),
    _t("T1592",     "Gather Victim Host Information",         "Reconnaissance",
        "Collect host hardware, software, config.",
        ["Limit public exposure"],
        ["Honeypots"]),
    _t("T1592.001", "Gather Victim Host Info: Hardware",      "Reconnaissance"),
    _t("T1592.002", "Gather Victim Host Info: Software",      "Reconnaissance"),
    _t("T1592.004", "Gather Victim Host Info: Client Configs","Reconnaissance"),
    _t("T1593",     "Search Open Websites/Domains",           "Reconnaissance",
        "Use search engines, social media for target info.",
        ["Limit public info"],
        ["OSINT monitoring"]),
    _t("T1593.001", "Search Open Websites: Social Media",     "Reconnaissance"),
    _t("T1593.002", "Search Open Websites: Search Engines",   "Reconnaissance"),
    _t("T1594",     "Search Victim-Owned Websites",           "Reconnaissance"),
    _t("T1596",     "Search Open Technical Databases",        "Reconnaissance",
        "Use Shodan, Censys, or similar to find exposed services.",
        ["Reduce public footprint"],
        ["Monitor for queries about own assets"]),
    _t("T1596.001", "Search Open Technical DBs: DNS/Passive DNS","Reconnaissance"),
    _t("T1596.005", "Search Open Technical DBs: Scan Databases","Reconnaissance"),
    _t("T1589",     "Gather Victim Identity Information",     "Reconnaissance",
        "Collect usernames, emails, credentials from breaches.",
        ["Credential rotation", "MFA"],
        ["Breach monitoring services"]),
    _t("T1589.001", "Gather Victim Identity: Credentials",    "Reconnaissance"),
    _t("T1589.002", "Gather Victim Identity: Email Addresses","Reconnaissance"),
    _t("T1597",     "Search Closed Sources",                  "Reconnaissance"),
    _t("T1598",     "Phishing for Information",               "Reconnaissance",
        "Send phishing to gather credentials or information.",
        ["Security awareness training", "Email filtering"],
        ["Email gateway logs", "User reporting"]),

    # ── Resource Development ──────────────────────────────────────────
    _t("T1583",     "Acquire Infrastructure",                 "Resource Development"),
    _t("T1583.001", "Acquire Infrastructure: Domains",        "Resource Development"),
    _t("T1583.003", "Acquire Infrastructure: Virtual Private Server","Resource Development"),
    _t("T1584",     "Compromise Infrastructure",              "Resource Development"),
    _t("T1587",     "Develop Capabilities",                   "Resource Development"),
    _t("T1587.001", "Develop Capabilities: Malware",          "Resource Development"),
    _t("T1587.003", "Develop Capabilities: Digital Certificates","Resource Development"),
    _t("T1588",     "Obtain Capabilities",                    "Resource Development"),
    _t("T1588.001", "Obtain Capabilities: Malware",           "Resource Development"),
    _t("T1588.002", "Obtain Capabilities: Tool",              "Resource Development"),
    _t("T1588.005", "Obtain Capabilities: Exploits",          "Resource Development"),
    _t("T1585",     "Establish Accounts",                     "Resource Development"),
    _t("T1586",     "Compromise Accounts",                    "Resource Development"),
    _t("T1608",     "Stage Capabilities",                     "Resource Development"),

    # ── Initial Access ────────────────────────────────────────────────
    _t("T1189",     "Drive-by Compromise",                    "Initial Access",
        "Compromise via watering-hole or malicious ad.",
        ["Restrict web browsing", "Browser sandboxing"],
        ["Web proxy logs", "Endpoint detection"]),
    _t("T1190",     "Exploit Public-Facing Application",      "Initial Access",
        "Exploit a vulnerability in a public web app or service.",
        ["Patch management", "WAF", "Network segmentation"],
        ["Application logs", "IDS", "WAF alerts"]),
    _t("T1133",     "External Remote Services",               "Initial Access",
        "Leverage VPN, RDP, SSH, or Citrix for access.",
        ["MFA", "Network segmentation", "VPN hardening"],
        ["Authentication logs", "VPN logs"]),
    _t("T1200",     "Hardware Additions",                     "Initial Access"),
    _t("T1566",     "Phishing",                               "Initial Access",
        "Send phishing emails with malicious attachments or links.",
        ["Email filtering", "User training", "MFA"],
        ["Email gateway", "Endpoint detection"]),
    _t("T1566.001", "Phishing: Spearphishing Attachment",     "Initial Access"),
    _t("T1566.002", "Phishing: Spearphishing Link",           "Initial Access"),
    _t("T1566.003", "Phishing: Spearphishing via Service",    "Initial Access"),
    _t("T1078",     "Valid Accounts",                         "Initial Access",
        "Use legitimate credentials (stolen, default, or purchased).",
        ["MFA", "Credential rotation", "Account lockout"],
        ["Anomalous logins", "Impossible travel alerts"]),
    _t("T1078.001", "Valid Accounts: Default Accounts",       "Initial Access"),
    _t("T1078.002", "Valid Accounts: Domain Accounts",        "Initial Access"),
    _t("T1078.003", "Valid Accounts: Local Accounts",         "Initial Access"),
    _t("T1078.004", "Valid Accounts: Cloud Accounts",         "Initial Access"),
    _t("T1091",     "Replication Through Removable Media",    "Initial Access"),
    _t("T1195",     "Supply Chain Compromise",                "Initial Access"),
    _t("T1195.001", "Supply Chain: Compromise Software Dependencies","Initial Access"),
    _t("T1195.002", "Supply Chain: Compromise Software Supply Chain","Initial Access"),
    _t("T1199",     "Trusted Relationship",                   "Initial Access"),

    # ── Execution ─────────────────────────────────────────────────────
    _t("T1059",     "Command and Scripting Interpreter",      "Execution",
        "Execute commands via shell, PowerShell, Python, etc.",
        ["Disable unnecessary scripting", "AppLocker"],
        ["Process monitoring", "Script block logging"]),
    _t("T1059.001", "Command & Scripting: PowerShell",        "Execution",
        "Execute PowerShell scripts or commands.",
        ["Constrained Language Mode", "Script signing"],
        ["PowerShell logging (4104)", "AMSI"]),
    _t("T1059.003", "Command & Scripting: Windows Command Shell","Execution"),
    _t("T1059.004", "Command & Scripting: Unix Shell",        "Execution"),
    _t("T1059.006", "Command & Scripting: Python",            "Execution"),
    _t("T1059.007", "Command & Scripting: JavaScript",        "Execution"),
    _t("T1203",     "Exploitation for Client Execution",      "Execution"),
    _t("T1047",     "Windows Management Instrumentation",     "Execution"),
    _t("T1053",     "Scheduled Task/Job",                     "Execution"),
    _t("T1053.003", "Scheduled Task/Job: Cron",               "Execution",
        "Create cron job for persistent execution.",
        ["Restrict cron access", "Audit cron jobs"],
        ["File monitoring on /etc/crontab", "auditd"]),
    _t("T1053.005", "Scheduled Task/Job: Scheduled Task",     "Execution",
        "Create Windows scheduled task.",
        ["Restrict task creation", "GPO"],
        ["Event 4698", "Sysmon Event 1"]),
    _t("T1053.006", "Scheduled Task/Job: Systemd Timers",     "Execution"),
    _t("T1569",     "System Services",                        "Execution"),
    _t("T1569.002", "System Services: Service Execution",     "Execution"),
    _t("T1609",     "Container Administration Command",       "Execution"),
    _t("T1610",     "Deploy Container",                       "Execution"),
    _t("T1106",     "Native API",                             "Execution"),
    _t("T1129",     "Shared Modules",                         "Execution"),
    _t("T1204",     "User Execution",                         "Execution"),
    _t("T1204.001", "User Execution: Malicious Link",         "Execution"),
    _t("T1204.002", "User Execution: Malicious File",         "Execution"),
    _t("T1559",     "Inter-Process Communication",            "Execution"),

    # ── Persistence ───────────────────────────────────────────────────
    _t("T1098",     "Account Manipulation",                   "Persistence",
        "Modify accounts to maintain access.",
        ["MFA", "Privileged account monitoring"],
        ["Account audit events", "Directory service logs"]),
    _t("T1098.004", "Account Manipulation: SSH Authorized Keys","Persistence",
        "Add SSH public key for persistent access.",
        ["Monitor authorized_keys", "Restrict SSH"],
        ["File integrity monitoring", "auditd"]),
    _t("T1197",     "BITS Jobs",                              "Persistence"),
    _t("T1547",     "Boot or Logon Autostart Execution",      "Persistence",
        "Configure system to execute code during boot/logon.",
        ["Restrict registry/startup modifications"],
        ["Sysmon Event 13", "Autoruns"]),
    _t("T1547.001", "Boot or Logon Autostart: Registry Run Keys","Persistence",
        "Add registry Run key for persistence.",
        ["Restrict registry writes", "AppLocker"],
        ["Sysmon Event 13", "Autoruns"]),
    _t("T1547.004", "Boot or Logon Autostart: Winlogon Helper DLL","Persistence"),
    _t("T1547.009", "Boot or Logon Autostart: Shortcut Modification","Persistence"),
    _t("T1136",     "Create Account",                         "Persistence",
        "Create new accounts for persistent access.",
        ["Restrict account creation", "MFA"],
        ["Event 4720 (Windows)", "useradd audit"]),
    _t("T1136.001", "Create Account: Local Account",          "Persistence"),
    _t("T1136.002", "Create Account: Domain Account",         "Persistence"),
    _t("T1543",     "Create or Modify System Process",        "Persistence"),
    _t("T1543.003", "Create or Modify System Process: Windows Service","Persistence",
        "Install malicious Windows service.",
        ["Restrict service creation"],
        ["Event 7045", "Sysmon Event 6"]),
    _t("T1037",     "Boot or Logon Initialization Scripts",   "Persistence"),
    _t("T1037.004", "Boot or Logon Init Scripts: RC Scripts",  "Persistence"),
    _t("T1505",     "Server Software Component",              "Persistence"),
    _t("T1505.003", "Server Software Component: Web Shell",   "Persistence",
        "Deploy web shell for persistent access.",
        ["File integrity monitoring", "WAF"],
        ["Web access logs", "YARA rules"]),
    _t("T1546",     "Event Triggered Execution",              "Persistence"),
    _t("T1546.003", "Event Triggered Execution: WMI Event Subscription","Persistence"),
    _t("T1546.008", "Event Triggered Execution: Accessibility Features","Persistence"),
    _t("T1574",     "Hijack Execution Flow",                  "Persistence"),
    _t("T1574.001", "Hijack Execution Flow: DLL Search Order Hijacking","Persistence"),
    _t("T1574.009", "Hijack Execution Flow: Path Interception by Unquoted Path","Persistence"),

    # ── Privilege Escalation ──────────────────────────────────────────
    _t("T1134",     "Access Token Manipulation",              "Privilege Escalation",
        "Manipulate access tokens to escalate privileges.",
        ["Least privilege", "Enable token filtering"],
        ["Token audit events", "Sysmon"]),
    _t("T1134.001", "Token Manipulation: Token Impersonation/Theft","Privilege Escalation",
        "Steal or impersonate another user's token.",
        ["Restrict SeImpersonatePrivilege"],
        ["Sysmon", "Token audit"]),
    _t("T1134.002", "Token Manipulation: Create Process with Token","Privilege Escalation"),
    _t("T1134.003", "Token Manipulation: Make and Impersonate Token","Privilege Escalation"),
    _t("T1548",     "Abuse Elevation Control Mechanism",      "Privilege Escalation",
        "Bypass OS elevation controls (UAC, sudo).",
        ["Enforce UAC", "Restrict sudo"],
        ["Process monitoring", "Sysmon"]),
    _t("T1548.001", "Abuse Elevation: Setuid and Setgid",     "Privilege Escalation",
        "Exploit SUID/SGID binaries for privilege escalation.",
        ["Audit SUID files", "Remove unnecessary SUID"],
        ["File monitoring", "Execution logs"]),
    _t("T1548.002", "Abuse Elevation: Bypass User Account Control","Privilege Escalation",
        "Bypass UAC to execute with elevated privileges.",
        ["Set UAC to Always Notify"],
        ["Sysmon", "Windows Event 4688"]),
    _t("T1548.003", "Abuse Elevation: Sudo and Sudo Caching", "Privilege Escalation",
        "Exploit sudo misconfigurations.",
        ["Restrict sudo", "Require password"],
        ["auth.log", "sudo log monitoring"]),
    _t("T1068",     "Exploitation for Privilege Escalation",  "Privilege Escalation",
        "Exploit kernel or application vulnerability for privesc.",
        ["Patch management", "Kernel hardening"],
        ["Kernel logs", "Endpoint detection"]),
    _t("T1055",     "Process Injection",                      "Privilege Escalation",
        "Inject code into running processes.",
        ["Endpoint protection", "Process isolation"],
        ["Sysmon Event 8/10", "API monitoring"]),
    _t("T1055.001", "Process Injection: DLL Injection",       "Privilege Escalation"),
    _t("T1055.012", "Process Injection: Process Hollowing",   "Privilege Escalation"),
    _t("T1611",     "Escape to Host",                         "Privilege Escalation",
        "Break out of container to host.",
        ["Container hardening", "seccomp"],
        ["Container runtime monitoring"]),

    # ── Defense Evasion ───────────────────────────────────────────────
    _t("T1140",     "Deobfuscate/Decode Files or Information","Defense Evasion"),
    _t("T1070",     "Indicator Removal",                      "Defense Evasion",
        "Remove artifacts (logs, files) to hide activity.",
        ["Centralized logging", "Log integrity"],
        ["Log gap detection", "File monitoring"]),
    _t("T1070.001", "Indicator Removal: Clear Windows Event Logs","Defense Evasion"),
    _t("T1070.002", "Indicator Removal: Clear Linux or Mac System Logs","Defense Evasion"),
    _t("T1070.003", "Indicator Removal: Clear Command History","Defense Evasion"),
    _t("T1070.004", "Indicator Removal: File Deletion",       "Defense Evasion"),
    _t("T1562",     "Impair Defenses",                        "Defense Evasion",
        "Disable or tamper with security tools.",
        ["Tamper protection", "Restricted permissions"],
        ["Service monitoring", "Health checks"]),
    _t("T1562.001", "Impair Defenses: Disable or Modify Tools","Defense Evasion"),
    _t("T1562.002", "Impair Defenses: Disable Windows Event Logging","Defense Evasion"),
    _t("T1562.004", "Impair Defenses: Disable or Modify System Firewall","Defense Evasion"),
    _t("T1564",     "Hide Artifacts",                         "Defense Evasion",
        "Hide files, accounts, or processes.",
        ["File integrity monitoring"],
        ["Show hidden files/dirs", "Process monitoring"]),
    _t("T1564.001", "Hide Artifacts: Hidden Files and Directories","Defense Evasion"),
    _t("T1564.003", "Hide Artifacts: Hidden Window",          "Defense Evasion"),
    _t("T1556",     "Modify Authentication Process",          "Defense Evasion",
        "Alter authentication to enable access.",
        ["MFA", "Authentication monitoring"],
        ["Authentication logs", "PAM audit"]),
    _t("T1556.003", "Modify Auth Process: Pluggable Auth Modules","Defense Evasion"),
    _t("T1027",     "Obfuscated Files or Information",        "Defense Evasion"),
    _t("T1027.001", "Obfuscated Files: Binary Padding",       "Defense Evasion"),
    _t("T1027.010", "Obfuscated Files: Command Obfuscation",  "Defense Evasion"),
    _t("T1036",     "Masquerading",                           "Defense Evasion"),
    _t("T1036.005", "Masquerading: Match Legitimate Name",    "Defense Evasion"),
    _t("T1218",     "System Binary Proxy Execution",          "Defense Evasion"),
    _t("T1218.011", "System Binary Proxy Execution: Rundll32","Defense Evasion"),
    _t("T1550",     "Use Alternate Authentication Material",  "Defense Evasion"),
    _t("T1550.002", "Use Alternate Auth Material: Pass the Hash","Defense Evasion"),
    _t("T1550.003", "Use Alternate Auth Material: Pass the Ticket","Defense Evasion"),
    _t("T1112",     "Modify Registry",                        "Defense Evasion"),
    _t("T1202",     "Indirect Command Execution",             "Defense Evasion"),
    _t("T1497",     "Virtualization/Sandbox Evasion",         "Defense Evasion"),

    # ── Credential Access ─────────────────────────────────────────────
    _t("T1110",     "Brute Force",                            "Credential Access",
        "Systematically guess passwords.",
        ["Account lockout", "MFA", "Rate limiting"],
        ["Authentication logs", "Anomaly detection"]),
    _t("T1110.001", "Brute Force: Password Guessing",         "Credential Access",
        "Guess passwords against a service.",
        ["Account lockout", "MFA"],
        ["Failed login monitoring"]),
    _t("T1110.002", "Brute Force: Password Cracking",         "Credential Access",
        "Offline crack of captured hashes.",
        ["Strong password policy"],
        ["Detect hash extraction"]),
    _t("T1110.003", "Brute Force: Password Spraying",         "Credential Access",
        "Try common passwords across many accounts.",
        ["Account lockout", "MFA"],
        ["Multiple-account failed logins"]),
    _t("T1110.004", "Brute Force: Credential Stuffing",       "Credential Access"),
    _t("T1003",     "OS Credential Dumping",                  "Credential Access",
        "Dump credentials from the OS.",
        ["Credential Guard", "LSA protection"],
        ["Sysmon", "LSASS access monitoring"]),
    _t("T1003.001", "OS Credential Dumping: LSASS Memory",    "Credential Access",
        "Dump LSASS process memory for credentials.",
        ["Credential Guard", "PPL"],
        ["Sysmon Event 10", "LSASS protection"]),
    _t("T1003.002", "OS Credential Dumping: SAM",             "Credential Access",
        "Extract hashes from SAM registry hive.",
        ["Restrict registry access"],
        ["Registry access monitoring"]),
    _t("T1003.003", "OS Credential Dumping: NTDS",            "Credential Access",
        "Extract AD hashes from ntds.dit.",
        ["Restrict DC access"],
        ["Volume Shadow Copy monitoring"]),
    _t("T1003.004", "OS Credential Dumping: LSA Secrets",     "Credential Access"),
    _t("T1003.006", "OS Credential Dumping: DCSync",          "Credential Access",
        "Replicate AD to get credentials.",
        ["Restrict replication rights"],
        ["Replication traffic monitoring"]),
    _t("T1003.007", "OS Credential Dumping: Proc Filesystem", "Credential Access"),
    _t("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow","Credential Access",
        "Read /etc/shadow for password hashes.",
        ["Restrict file permissions"],
        ["File access monitoring"]),
    _t("T1552",     "Unsecured Credentials",                  "Credential Access",
        "Find credentials in files, registries, etc.",
        ["Credential management", "Secret vaults"],
        ["File access monitoring"]),
    _t("T1552.001", "Unsecured Credentials: Credentials In Files","Credential Access",
        "Search filesystem for stored credentials.",
        ["Use credential vaults", "File permissions"],
        ["File access monitoring", "Content scanning"]),
    _t("T1552.004", "Unsecured Credentials: Private Keys",    "Credential Access",
        "Steal SSH/TLS private keys.",
        ["Protect key files", "Use HSMs"],
        ["File access on .ssh/", "Key usage monitoring"]),
    _t("T1555",     "Credentials from Password Stores",       "Credential Access"),
    _t("T1555.003", "Credentials from Password Stores: Web Browsers","Credential Access",
        "Extract saved passwords from browser databases.",
        ["Use password managers", "Encrypt profiles"],
        ["File access on browser dirs"]),
    _t("T1557",     "Adversary-in-the-Middle",                "Credential Access"),
    _t("T1557.001", "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning","Credential Access"),
    _t("T1558",     "Steal or Forge Kerberos Tickets",        "Credential Access"),
    _t("T1558.003", "Steal/Forge Kerberos: Kerberoasting",    "Credential Access",
        "Request TGS tickets and crack offline.",
        ["Strong service account passwords"],
        ["Kerberos ticket request monitoring"]),
    _t("T1187",     "Forced Authentication",                  "Credential Access"),
    _t("T1040",     "Network Sniffing",                       "Credential Access"),
    _t("T1528",     "Steal Application Access Token",         "Credential Access"),
    _t("T1539",     "Steal Web Session Cookie",               "Credential Access"),
    _t("T1111",     "Multi-Factor Authentication Interception","Credential Access"),

    # ── Discovery ─────────────────────────────────────────────────────
    _t("T1046",     "Network Service Scanning",               "Discovery",
        "Scan for open ports and services.",
        ["Network segmentation", "Firewall"],
        ["Internal IDS", "Netflow"]),
    _t("T1082",     "System Information Discovery",           "Discovery",
        "Collect OS, hostname, architecture.",
        ["Restrict user enumeration"],
        ["Process monitoring"]),
    _t("T1016",     "System Network Configuration Discovery", "Discovery",
        "Enumerate network config (ifconfig, ip addr).",
        [],
        ["Process execution logs"]),
    _t("T1016.001", "System Network Config Discovery: Internet Connection Discovery", "Discovery"),
    _t("T1018",     "Remote System Discovery",                "Discovery",
        "Enumerate remote systems (ping, arp, net view).",
        ["Network segmentation"],
        ["Network traffic analysis"]),
    _t("T1033",     "System Owner/User Discovery",            "Discovery"),
    _t("T1049",     "System Network Connections Discovery",   "Discovery"),
    _t("T1057",     "Process Discovery",                      "Discovery"),
    _t("T1069",     "Permission Groups Discovery",            "Discovery"),
    _t("T1069.001", "Permission Groups Discovery: Local Groups","Discovery"),
    _t("T1069.002", "Permission Groups Discovery: Domain Groups","Discovery"),
    _t("T1083",     "File and Directory Discovery",           "Discovery"),
    _t("T1087",     "Account Discovery",                      "Discovery"),
    _t("T1087.001", "Account Discovery: Local Account",       "Discovery"),
    _t("T1087.002", "Account Discovery: Domain Account",      "Discovery"),
    _t("T1135",     "Network Share Discovery",                "Discovery"),
    _t("T1201",     "Password Policy Discovery",              "Discovery"),
    _t("T1518",     "Software Discovery",                     "Discovery"),
    _t("T1518.001", "Software Discovery: Security Software Discovery","Discovery"),
    _t("T1580",     "Cloud Infrastructure Discovery",         "Discovery"),
    _t("T1526",     "Cloud Service Discovery",                "Discovery"),
    _t("T1538",     "Cloud Service Dashboard",                "Discovery"),
    _t("T1007",     "System Service Discovery",               "Discovery"),
    _t("T1010",     "Application Window Discovery",           "Discovery"),
    _t("T1012",     "Query Registry",                         "Discovery"),
    _t("T1063",     "Security Software Discovery",            "Discovery"),
    _t("T1124",     "System Time Discovery",                  "Discovery"),
    _t("T1217",     "Browser Bookmark Discovery",             "Discovery"),
    _t("T1482",     "Domain Trust Discovery",                 "Discovery"),
    _t("T1614",     "System Location Discovery",              "Discovery"),

    # ── Lateral Movement ──────────────────────────────────────────────
    _t("T1210",     "Exploitation of Remote Services",        "Lateral Movement",
        "Exploit remote services to move laterally.",
        ["Patch management", "Segmentation"],
        ["IDS", "Endpoint detection"]),
    _t("T1021",     "Remote Services",                        "Lateral Movement",
        "Use remote services for lateral movement.",
        ["MFA", "Network segmentation"],
        ["Authentication logs"]),
    _t("T1021.001", "Remote Services: Remote Desktop Protocol","Lateral Movement"),
    _t("T1021.002", "Remote Services: SMB/Windows Admin Shares","Lateral Movement",
        "Move laterally via SMB shares.",
        ["Restrict admin shares", "Firewalls"],
        ["SMB session logs", "Sysmon Event 3"]),
    _t("T1021.004", "Remote Services: SSH",                   "Lateral Movement",
        "Use SSH for lateral movement.",
        ["Key-based auth only", "MFA"],
        ["SSH auth logs"]),
    _t("T1021.006", "Remote Services: Windows Remote Management","Lateral Movement"),
    _t("T1534",     "Internal Spearphishing",                 "Lateral Movement"),
    _t("T1570",     "Lateral Tool Transfer",                  "Lateral Movement",
        "Transfer tools between compromised systems.",
        ["Network segmentation"],
        ["File transfer monitoring"]),
    _t("T1080",     "Taint Shared Content",                   "Lateral Movement"),
    _t("T1563",     "Remote Service Session Hijacking",       "Lateral Movement"),
    _t("T1563.001", "Remote Service Session Hijacking: SSH Hijacking","Lateral Movement"),

    # ── Collection ────────────────────────────────────────────────────
    _t("T1005",     "Data from Local System",                 "Collection",
        "Collect data from the local filesystem.",
        ["Data classification", "DLP"],
        ["File access monitoring"]),
    _t("T1025",     "Data from Removable Media",              "Collection"),
    _t("T1039",     "Data from Network Shared Drive",         "Collection"),
    _t("T1074",     "Data Staged",                            "Collection"),
    _t("T1074.001", "Data Staged: Local Data Staging",        "Collection"),
    _t("T1113",     "Screen Capture",                         "Collection"),
    _t("T1115",     "Clipboard Data",                         "Collection"),
    _t("T1119",     "Automated Collection",                   "Collection"),
    _t("T1123",     "Audio Capture",                          "Collection"),
    _t("T1125",     "Video Capture",                          "Collection"),
    _t("T1213",     "Data from Information Repositories",     "Collection"),
    _t("T1560",     "Archive Collected Data",                 "Collection"),
    _t("T1560.001", "Archive Collected Data: Archive via Utility","Collection"),

    # ── Command and Control ───────────────────────────────────────────
    _t("T1071",     "Application Layer Protocol",             "Command and Control"),
    _t("T1071.001", "Application Layer Protocol: Web Protocols","Command and Control"),
    _t("T1071.004", "Application Layer Protocol: DNS",        "Command and Control"),
    _t("T1090",     "Proxy",                                  "Command and Control"),
    _t("T1090.001", "Proxy: Internal Proxy",                  "Command and Control"),
    _t("T1090.002", "Proxy: External Proxy",                  "Command and Control"),
    _t("T1095",     "Non-Application Layer Protocol",         "Command and Control"),
    _t("T1102",     "Web Service",                            "Command and Control"),
    _t("T1105",     "Ingress Tool Transfer",                  "Command and Control"),
    _t("T1132",     "Data Encoding",                          "Command and Control"),
    _t("T1219",     "Remote Access Software",                 "Command and Control"),
    _t("T1571",     "Non-Standard Port",                      "Command and Control"),
    _t("T1572",     "Protocol Tunneling",                     "Command and Control"),
    _t("T1573",     "Encrypted Channel",                      "Command and Control"),

    # ── Exfiltration ──────────────────────────────────────────────────
    _t("T1020",     "Automated Exfiltration",                 "Exfiltration",
        "Automatically exfiltrate collected data.",
        ["DLP", "Network monitoring"],
        ["Outbound traffic analysis"]),
    _t("T1030",     "Data Transfer Size Limits",              "Exfiltration"),
    _t("T1041",     "Exfiltration Over C2 Channel",           "Exfiltration"),
    _t("T1048",     "Exfiltration Over Alternative Protocol", "Exfiltration"),
    _t("T1048.002", "Exfiltration Over Alt Protocol: Asymmetric Encrypted","Exfiltration"),
    _t("T1048.003", "Exfiltration Over Alt Protocol: Unencrypted/Obfuscated","Exfiltration"),
    _t("T1567",     "Exfiltration Over Web Service",          "Exfiltration"),
    _t("T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage","Exfiltration"),
    _t("T1537",     "Transfer Data to Cloud Account",         "Exfiltration"),

    # ── Impact ────────────────────────────────────────────────────────
    _t("T1485",     "Data Destruction",                       "Impact"),
    _t("T1486",     "Data Encrypted for Impact",              "Impact"),
    _t("T1489",     "Service Stop",                           "Impact"),
    _t("T1490",     "Inhibit System Recovery",                "Impact"),
    _t("T1491",     "Defacement",                             "Impact"),
    _t("T1491.001", "Defacement: Internal Defacement",        "Impact"),
    _t("T1491.002", "Defacement: External Defacement",        "Impact"),
    _t("T1496",     "Resource Hijacking",                     "Impact"),
    _t("T1498",     "Network Denial of Service",              "Impact"),
    _t("T1499",     "Endpoint Denial of Service",             "Impact"),
    _t("T1529",     "System Shutdown/Reboot",                 "Impact"),
    _t("T1531",     "Account Access Removal",                 "Impact"),
    _t("T1561",     "Disk Wipe",                              "Impact"),
]
# fmt: on

# Build lookup dict
for _tech in _RAW:
    ATTACK_DB[_tech.technique_id] = _tech
del _RAW  # free list


def get_technique(technique_id: str) -> AttackTechnique | None:
    """Look up a single technique by ID (e.g. ``'T1046'``)."""
    return ATTACK_DB.get(technique_id)


def get_techniques_by_tactic(tactic: str) -> list[AttackTechnique]:
    """Return all techniques belonging to *tactic*."""
    tactic_lower = tactic.lower()
    return [t for t in ATTACK_DB.values() if t.tactic.lower() == tactic_lower]


def list_tactics() -> list[str]:
    """Return sorted unique tactic names."""
    return sorted({t.tactic for t in ATTACK_DB.values()})


# ═══════════════════════════════════════════════════════════════════════════
# 3. TechniqueMapper — action text → techniques
# ═══════════════════════════════════════════════════════════════════════════

# Keyword / regex → list of technique IDs
_ACTION_RULES: list[tuple[re.Pattern[str], list[str]]] = [
    # Recon / scanning
    (re.compile(r"port\s*scan|nmap|masscan|service\s*scan", re.I),
     ["T1046", "T1595.001"]),
    (re.compile(r"vuln(erability)?\s*scan|nessus|openvas|nikto", re.I),
     ["T1595.002"]),
    (re.compile(r"subdomain|dns\s*(enum|brute|recon)|amass|subfinder", re.I),
     ["T1590.002", "T1595.003"]),
    (re.compile(r"whois|dns\s*lookup|dig\s|nslookup", re.I),
     ["T1590", "T1590.001"]),
    (re.compile(r"shodan|censys|zoomeye", re.I),
     ["T1596.005"]),
    (re.compile(r"osint|recon-ng|the\s*harvester|email\s*enum", re.I),
     ["T1589.002", "T1593.002"]),
    (re.compile(r"os\s*fingerprint|banner\s*grab|version\s*detect", re.I),
     ["T1082", "T1592.002"]),
    (re.compile(r"web.*recon|spider|crawl|dirb|gobuster|ffuf", re.I),
     ["T1595.003", "T1594"]),

    # Credential access
    (re.compile(r"brute\s*force.*ssh|ssh\s*brute|hydra.*ssh", re.I),
     ["T1110.001", "T1021.004"]),
    (re.compile(r"brute\s*force.*ftp|ftp\s*brute|hydra.*ftp", re.I),
     ["T1110.001"]),
    (re.compile(r"brute\s*force.*http|http\s*brute|hydra.*http", re.I),
     ["T1110.001", "T1078.001"]),
    (re.compile(r"brute\s*force|password\s*guess|credential\s*stuff", re.I),
     ["T1110", "T1110.001"]),
    (re.compile(r"password\s*spray", re.I),
     ["T1110.003"]),
    (re.compile(r"crack|hashcat|john|hash\s*crack", re.I),
     ["T1110.002"]),
    (re.compile(r"kerberoast|tgs|spn", re.I),
     ["T1558.003"]),
    (re.compile(r"mimikatz|lsass|sekurlsa|credential\s*dump", re.I),
     ["T1003.001"]),
    (re.compile(r"sam\s*dump|sam\s*hive|reg\s+save.*sam", re.I),
     ["T1003.002"]),
    (re.compile(r"ntds|dcsync|secretsdump", re.I),
     ["T1003.003", "T1003.006"]),
    (re.compile(r"/etc/shadow|shadow\s*file", re.I),
     ["T1003.008"]),
    (re.compile(r"ssh\s*(private\s*)?key|id_rsa|id_ed25519", re.I),
     ["T1552.004"]),
    (re.compile(r"credential.*file|\.env|config.*password|unsecured\s*cred", re.I),
     ["T1552.001"]),
    (re.compile(r"browser.*password|chrome.*login|firefox.*password", re.I),
     ["T1555.003"]),
    (re.compile(r"sniff|tcpdump|wireshark|responder", re.I),
     ["T1040", "T1557.001"]),

    # Initial access / exploitation
    (re.compile(r"sql\s*inject|sqli|sqlmap", re.I),
     ["T1190"]),
    (re.compile(r"xss|cross\-?\s*site\s*script", re.I),
     ["T1190"]),
    (re.compile(r"command\s*inject|os\s*inject|rce", re.I),
     ["T1190", "T1059.004"]),
    (re.compile(r"lfi|local\s*file\s*inclus|path\s*travers", re.I),
     ["T1190"]),
    (re.compile(r"eternalblue|ms17[_-]010|smb.*exploit", re.I),
     ["T1210", "T1190"]),
    (re.compile(r"log4shell|log4j|cve[_-]2021[_-]44228", re.I),
     ["T1190", "T1059.006"]),
    (re.compile(r"shellshock|cve[_-]2014[_-]6271", re.I),
     ["T1190", "T1059.004"]),
    (re.compile(r"phish", re.I),
     ["T1566", "T1566.001"]),
    (re.compile(r"default\s*cred|anonymous.*ftp|valid.*account", re.I),
     ["T1078.001"]),
    (re.compile(r"drive\s*by", re.I),
     ["T1189"]),

    # Execution
    (re.compile(r"powershell", re.I),
     ["T1059.001"]),
    (re.compile(r"bash|sh\s|/bin/sh|unix\s*shell", re.I),
     ["T1059.004"]),
    (re.compile(r"python.*exec|python.*script", re.I),
     ["T1059.006"]),
    (re.compile(r"wmi|wmic", re.I),
     ["T1047"]),
    (re.compile(r"container.*exec|docker.*exec|kubectl.*exec", re.I),
     ["T1609"]),

    # Privilege escalation
    (re.compile(r"suid|setuid|sgid", re.I),
     ["T1548.001"]),
    (re.compile(r"sudo|sudo\s*misconfig|nopasswd", re.I),
     ["T1548.003"]),
    (re.compile(r"kernel\s*exploit|dirty\s*cow|dirty\s*pipe|pwnkit", re.I),
     ["T1068"]),
    (re.compile(r"uac\s*bypass|user\s*account\s*control", re.I),
     ["T1548.002"]),
    (re.compile(r"token\s*impersonat|seimpersonate|potato", re.I),
     ["T1134.001"]),
    (re.compile(r"unquoted\s*(service\s*)?path", re.I),
     ["T1574.009"]),
    (re.compile(r"dll\s*(search\s*order\s*)?hijack", re.I),
     ["T1574.001"]),
    (re.compile(r"process\s*inject", re.I),
     ["T1055"]),

    # Persistence
    (re.compile(r"cron\s*(job\s*)?persist|cron.*backdoor|crontab", re.I),
     ["T1053.003"]),
    (re.compile(r"scheduled\s*task|schtask", re.I),
     ["T1053.005"]),
    (re.compile(r"authorized_keys|ssh.*backdoor|ssh.*persist", re.I),
     ["T1098.004"]),
    (re.compile(r"web\s*shell", re.I),
     ["T1505.003"]),
    (re.compile(r"registry\s*run\s*key|reg.*run|autostart", re.I),
     ["T1547.001"]),
    (re.compile(r"service\s*persist|install\s*service|malicious\s*service", re.I),
     ["T1543.003"]),
    (re.compile(r"startup\s*folder|startup\s*script", re.I),
     ["T1547.009"]),
    (re.compile(r"rc\.local|boot\s*script", re.I),
     ["T1037.004"]),
    (re.compile(r"create\s*account|add\s*user", re.I),
     ["T1136.001"]),
    (re.compile(r"bits\s*job", re.I),
     ["T1197"]),

    # Lateral movement
    (re.compile(r"lateral.*move|pivot|credential\s*reuse", re.I),
     ["T1210", "T1078"]),
    (re.compile(r"smb.*share|admin.*share|psexec|wmiexec", re.I),
     ["T1021.002"]),
    (re.compile(r"ssh\s*pivot|ssh\s*tunnel", re.I),
     ["T1021.004"]),
    (re.compile(r"rdp|remote\s*desktop", re.I),
     ["T1021.001"]),
    (re.compile(r"pass\s*the\s*hash|pth", re.I),
     ["T1550.002"]),
    (re.compile(r"pass\s*the\s*ticket|ptt|golden\s*ticket", re.I),
     ["T1550.003"]),
    (re.compile(r"tool\s*transfer|upload.*tool|scp.*tool", re.I),
     ["T1570"]),

    # Defense evasion
    (re.compile(r"clear.*log|log\s*wipe|indicator\s*remov", re.I),
     ["T1070"]),
    (re.compile(r"clear.*history|bash.*history|history.*-c", re.I),
     ["T1070.003"]),
    (re.compile(r"disable.*firewall|iptables\s*flush", re.I),
     ["T1562.004"]),
    (re.compile(r"obfuscat|encode|base64.*payload", re.I),
     ["T1027"]),

    # Collection / exfiltration
    (re.compile(r"data\s*exfil|exfiltrat", re.I),
     ["T1041", "T1020"]),
    (re.compile(r"screen\s*capture|screenshot", re.I),
     ["T1113"]),
    (re.compile(r"keylog", re.I),
     ["T1056.001"] if "T1056.001" in ATTACK_DB else ["T1005"]),
    (re.compile(r"clipboard", re.I),
     ["T1115"]),
]


class TechniqueMapper:
    """Map free-text action descriptions to ATT&CK techniques."""

    def map_action_to_techniques(self, action: str) -> list[AttackTechnique]:
        """Return ATT&CK techniques matching *action* text."""
        matches: list[AttackTechnique] = []
        seen: set[str] = set()
        for pattern, technique_ids in _ACTION_RULES:
            if pattern.search(action):
                for tid in technique_ids:
                    if tid not in seen:
                        seen.add(tid)
                        tech = ATTACK_DB.get(tid)
                        if tech:
                            matches.append(tech)
        return matches

    def map_technique_id(self, technique_id: str) -> AttackTechnique | None:
        """Direct lookup by technique ID."""
        return ATTACK_DB.get(technique_id)

    def map_technique_ids(self, ids: list[str]) -> list[AttackTechnique]:
        """Return AttackTechnique objects for a list of IDs."""
        return [t for tid in ids if (t := ATTACK_DB.get(tid))]


# ═══════════════════════════════════════════════════════════════════════════
# 4. Plugin interface
# ═══════════════════════════════════════════════════════════════════════════

def metadata() -> dict[str, Any]:
    return {
        "name": "attack_map",
        "version": "1.0.0",
        "category": "mitre",
        "description": (
            "MITRE ATT&CK technique database (~200 techniques) "
            "and action-to-technique mapper"
        ),
        "dependencies": [],
    }


def execute(context: ExecutionContext) -> ExecutionResult:
    """Build an AttackMatrix from the current engagement state.

    Reads event logs and state keys to determine which techniques
    were exercised, then writes the matrix to state.
    """
    from core.state_manager import state

    matrix = AttackMatrix()
    mapper = TechniqueMapper()

    # Events logged as (action_text, ...) tuples in state.execution_log
    execution_log: list[dict[str, Any]] = state.get("execution_log", [])
    for entry in execution_log:
        action = entry.get("action", "")
        techs = mapper.map_action_to_techniques(action)
        matrix.add_techniques(techs)

    # Also pull directly-tagged technique IDs from phase results
    for key in (
        "recon_results", "scan_results", "exploit_results",
        "privesc_results", "persistence_results",
        "lateral_movement", "credential_harvest",
    ):
        data = state.get(key, {})
        if isinstance(data, dict):
            _extract_technique_ids(data, matrix, mapper)
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    _extract_technique_ids(item, matrix, mapper)

    state.set("attack_matrix", matrix.to_dict())

    return ExecutionResult(success=True, output=matrix.to_dict())


def _extract_technique_ids(
    data: dict[str, Any],
    matrix: AttackMatrix,
    mapper: TechniqueMapper,
) -> None:
    """Recursively extract ``mitre_technique`` or ``mitre_id`` fields."""
    for key in ("mitre_technique", "mitre_id", "technique_id"):
        val = data.get(key)
        if isinstance(val, str) and val:
            tech = mapper.map_technique_id(val)
            if tech:
                matrix.add_technique(tech)
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    tech = mapper.map_technique_id(v)
                    if tech:
                        matrix.add_technique(tech)

    # Recurse into nested dicts/lists
    for v in data.values():
        if isinstance(v, dict):
            _extract_technique_ids(v, matrix, mapper)
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    _extract_technique_ids(item, matrix, mapper)
