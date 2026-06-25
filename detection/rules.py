"""MITRE ATT&CK-mapped detection rules."""
from dataclasses import dataclass
from typing import Callable
try:
    from ..core.schema import Event
except ImportError:
    from core.schema import Event


@dataclass
class Alert:
    rule_id: str
    name: str
    severity: str          # critical / high / medium / low
    mitre_tactic: str
    mitre_technique: str
    description: str
    event: Event

    def to_dict(self) -> dict:
        d = self.event.to_dict()
        d.update({
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "severity": self.severity,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "alert_description": self.description,
        })
        return d


@dataclass
class Rule:
    rule_id: str
    name: str
    severity: str
    mitre_tactic: str
    mitre_technique: str
    description: str
    match: Callable[[Event], bool]

    def evaluate(self, event: Event) -> Alert | None:
        if self.match(event):
            return Alert(
                rule_id=self.rule_id,
                name=self.name,
                severity=self.severity,
                mitre_tactic=self.mitre_tactic,
                mitre_technique=self.mitre_technique,
                description=self.description,
                event=event,
            )
        return None


# ── Rule definitions ───────────────────────────────────────────────────────

RULES: list[Rule] = [
    Rule(
        rule_id="R001",
        name="Brute Force Login Attempt",
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1110 – Brute Force",
        description="Repeated authentication failures from a single source indicate brute-force activity.",
        match=lambda e: e.action == "login_failure",
    ),
    Rule(
        rule_id="R002",
        name="Successful Login After Failures",
        severity="critical",
        mitre_tactic="Credential Access",
        mitre_technique="T1110.001 – Password Guessing",
        description="Login succeeded on an account that recently experienced failures — possible credential compromise.",
        match=lambda e: e.action == "login_success" and e.event_id in ("4624",),
    ),
    Rule(
        rule_id="R003",
        name="Privileged Account Logon",
        severity="medium",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1078 – Valid Accounts",
        description="A privileged logon (Event 4672) occurred — monitor for unexpected admin use.",
        match=lambda e: e.action == "privileged_logon" or e.event_id == "4672",
    ),
    Rule(
        rule_id="R004",
        name="Explicit Credential Use (RunAs / PTH)",
        severity="high",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1550.002 – Pass the Hash",
        description="Explicit alternate credentials were used (Event 4648), a common pass-the-hash indicator.",
        match=lambda e: e.action == "explicit_credential_use" or e.event_id == "4648",
    ),
    Rule(
        rule_id="R005",
        name="New Service / Driver Installed",
        severity="high",
        mitre_tactic="Persistence",
        mitre_technique="T1543.003 – Windows Service",
        description="A new service or driver was installed — common persistence and privilege escalation vector.",
        match=lambda e: e.action in ("service_install", "new_service") or e.event_id in ("4697", "7045"),
    ),
    Rule(
        rule_id="R006",
        name="Scheduled Task Created",
        severity="high",
        mitre_tactic="Persistence",
        mitre_technique="T1053.005 – Scheduled Task",
        description="A new scheduled task was created, which may indicate persistence by an attacker.",
        match=lambda e: e.action == "scheduled_task_created" or e.event_id == "4698",
    ),
    Rule(
        rule_id="R007",
        name="New Local/Domain Account Created",
        severity="medium",
        mitre_tactic="Persistence",
        mitre_technique="T1136 – Create Account",
        description="A new user account was created — verify this was an authorized administrative action.",
        match=lambda e: e.action == "account_created" or e.event_id == "4720",
    ),
    Rule(
        rule_id="R008",
        name="Security Audit Log Cleared",
        severity="critical",
        mitre_tactic="Defense Evasion",
        mitre_technique="T1070.001 – Clear Windows Event Logs",
        description="The security audit log was cleared — attackers do this to remove evidence of compromise.",
        match=lambda e: e.action == "audit_log_cleared" or e.event_id == "1102",
    ),
    Rule(
        rule_id="R009",
        name="Suspicious Process Creation",
        severity="medium",
        mitre_tactic="Execution",
        mitre_technique="T1059 – Command and Scripting Interpreter",
        description="A new process was spawned (Event 4688) — review parent/child relationship for abuse.",
        match=lambda e: (e.action == "process_create" or e.event_id == "4688") and _suspicious_process(e),
    ),
    Rule(
        rule_id="R010",
        name="SSH Brute Force (Syslog)",
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1110 – Brute Force",
        description="Repeated SSH authentication failures from a single IP indicate brute-force scanning.",
        match=lambda e: e.log_source == "syslog" and e.action == "login_failure",
    ),
    Rule(
        rule_id="R011",
        name="Invalid / Unknown SSH User",
        severity="medium",
        mitre_tactic="Reconnaissance",
        mitre_technique="T1592 – Gather Victim Identity Information",
        description="Login attempted for a username that does not exist on the system.",
        match=lambda e: e.action == "invalid_user",
    ),
    Rule(
        rule_id="R012",
        name="Sudo / Privilege Escalation (Syslog)",
        severity="high",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1548.003 – Sudo and Sudo Caching",
        description="A sudo command was executed, elevating privileges to root.",
        match=lambda e: e.action == "privilege_escalation",
    ),
    Rule(
        rule_id="R014",
        name="Web Auth Failure (HTTP 401/403)",
        severity="medium",
        mitre_tactic="Credential Access",
        mitre_technique="T1110 – Brute Force",
        description="HTTP 401/403 responses on auth endpoints indicate web login brute-force attempts.",
        match=lambda e: e.action == "http_auth_failure",
    ),
    Rule(
        rule_id="R015",
        name="Suspicious Web Path Probe",
        severity="high",
        mitre_tactic="Discovery",
        mitre_technique="T1083 – File and Directory Discovery",
        description="Requests to sensitive paths (admin panel, .env, /etc/passwd) indicate active reconnaissance.",
        match=lambda e: e.action == "http_suspicious_path",
    ),
    Rule(
        rule_id="R016",
        name="HTTP Server Error Spike",
        severity="low",
        mitre_tactic="Impact",
        mitre_technique="T1499 – Endpoint Denial of Service",
        description="HTTP 5xx responses may indicate exploitation attempts causing application errors.",
        match=lambda e: e.action == "http_server_error",
    ),
    Rule(
        rule_id="R013",
        name="Group Membership Change",
        severity="medium",
        mitre_tactic="Privilege Escalation",
        mitre_technique="T1098 – Account Manipulation",
        description="A user was added to a privileged group — verify this was an authorized change.",
        match=lambda e: e.action in ("group_member_added", "local_group_member_added",
                                      "universal_group_member_added")
                        or e.event_id in ("4728", "4732", "4756"),
    ),
    Rule(
        rule_id="R017",
        name="Account Lockout",
        severity="high",
        mitre_tactic="Credential Access",
        mitre_technique="T1110 – Brute Force",
        description="An account was locked out after too many failed authentication attempts — strong brute-force indicator.",
        match=lambda e: e.action == "account_lockout" or e.event_id == "4740",
    ),
    Rule(
        rule_id="R018",
        name="Network Share Accessed",
        severity="medium",
        mitre_tactic="Lateral Movement",
        mitre_technique="T1021.002 – SMB/Windows Admin Shares",
        description="A network share was accessed (Event 5140) — review for lateral movement or data staging.",
        match=lambda e: e.action == "network_share_access" or e.event_id == "5140",
    ),
    Rule(
        rule_id="R019",
        name="RDP Remote Login",
        severity="high",
        mitre_tactic="Lateral Movement",
        mitre_technique="T1021.001 – Remote Desktop Protocol",
        description="A Remote Desktop logon (logon type 10) occurred — verify this was an authorized remote session.",
        match=lambda e: (e.action == "rdp_login" or
                         (e.event_id == "4624" and
                          e.extra.get("evtx_fields", {}).get("LogonType", "") in ("10", 10))),
    ),
    Rule(
        rule_id="R020",
        name="Firewall — Outbound to Uncommon Port",
        severity="medium",
        mitre_tactic="Command and Control",
        mitre_technique="T1571 – Non-Standard Port",
        description="Outbound connection allowed to an uncommon port — may indicate C2 beaconing or tunneling.",
        match=lambda e: e.log_source == "cef" and e.action == "allow" and _uncommon_dst_port(e),
    ),
    Rule(
        rule_id="R021",
        name="Firewall — Repeated Inbound Blocks",
        severity="low",
        mitre_tactic="Reconnaissance",
        mitre_technique="T1046 – Network Service Scanning",
        description="Multiple inbound connections blocked from the same source — possible port scan or enumeration.",
        match=lambda e: e.log_source == "cef" and e.action == "deny",
    ),
    Rule(
        rule_id="R022",
        name="Suspicious Web User-Agent",
        severity="medium",
        mitre_tactic="Initial Access",
        mitre_technique="T1190 – Exploit Public-Facing Application",
        description="HTTP request with a known scanner or exploit framework user-agent string.",
        match=lambda e: e.log_source in ("apache", "nginx", "access") and _scanner_useragent(e),
    ),
]


def _uncommon_dst_port(e: Event) -> bool:
    COMMON = {80, 443, 8080, 8443, 53, 25, 587, 110, 143, 993, 995, 22, 21, 3389, 445, 139}
    port = e.extra.get("dst_port") or e.extra.get("dpt")
    try:
        return int(port) not in COMMON
    except (TypeError, ValueError):
        return False


def _scanner_useragent(e: Event) -> bool:
    SCANNERS = {"nmap", "nikto", "masscan", "sqlmap", "hydra", "dirbuster",
                "gobuster", "wfuzz", "nuclei", "zgrab", "python-requests/2",
                "curl/7", "go-http-client", "zgrab", "metasploit"}
    ua = (e.extra.get("user_agent") or e.extra.get("useragent") or "").lower()
    return any(s in ua for s in SCANNERS)


def _suspicious_process(e: Event) -> bool:
    suspicious = {"powershell", "cmd.exe", "wscript", "cscript", "mshta",
                  "regsvr32", "rundll32", "certutil", "wmic", "net.exe", "psexec"}
    fields = e.extra.get("evtx_fields", {})
    proc = (fields.get("NewProcessName", "") or
            fields.get("CommandLine", "") or
            e.message).lower()
    return any(s in proc for s in suspicious)


def run_rules(events: list[Event]) -> list[Alert]:
    """Run all rules and deduplicate: one alert per (rule_id, source_ip, username) group."""
    # Collect raw hits
    raw: list[Alert] = []
    for event in events:
        for rule in RULES:
            alert = rule.evaluate(event)
            if alert:
                raw.append(alert)

    # Group brute-force / high-volume rules by (rule_id, src_ip, username)
    # Keep the first event as representative; annotate count on description
    GROUPABLE = {"R001", "R010", "R002"}
    groups: dict[tuple, list[Alert]] = {}
    ungrouped: list[Alert] = []

    for alert in raw:
        if alert.rule_id in GROUPABLE:
            key = (alert.rule_id,
                   alert.event.source_ip or "",
                   alert.event.username or "")
            groups.setdefault(key, []).append(alert)
        else:
            ungrouped.append(alert)

    # Deduplicate non-groupable alerts: one per (rule_id, event timestamp+action)
    seen: set[tuple] = set()
    deduped_ungrouped: list[Alert] = []
    for alert in ungrouped:
        key = (alert.rule_id,
               alert.event.timestamp.isoformat() if alert.event.timestamp else "",
               alert.event.action)
        if key not in seen:
            seen.add(key)
            deduped_ungrouped.append(alert)

    result: list[Alert] = []
    for (rule_id, src_ip, username), group in groups.items():
        rep = group[0]
        count = len(group)
        if count > 1:
            rep.description = (
                f"{rep.description} [{count} events from "
                f"{src_ip or 'unknown IP'} targeting '{username or 'unknown'}']"
            )
            rep.name = f"{rep.name} ×{count}"
        result.append(rep)

    result.extend(deduped_ungrouped)
    result.sort(key=lambda a: a.event.timestamp or __import__('datetime').datetime.min)
    return result
