# SecLog Analyzer

[![Live Demo](https://img.shields.io/badge/Live%20Demo-seclog--analyzer.onrender.com-blue?style=flat-square)](https://seclog-analyzer.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.11+-green?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-22%20Rules-red?style=flat-square)](https://attack.mitre.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

**Live demo: [seclog-analyzer.onrender.com](https://seclog-analyzer.onrender.com)**

A security log analysis platform that ingests logs from **6 different formats**, maps findings to **MITRE ATT&CK**, scores statistical anomalies, and presents everything in an interactive web dashboard with PDF/CSV export — deployable in under 5 minutes with no paid tools.

> Built as an MSc Cybersecurity portfolio project (University of Hertfordshire) demonstrating detection engineering principles applicable to real-world SOC environments.

---

## What it does

- **Parses 6 log formats** — Windows EVTX, Linux syslog, CSV, JSON, Apache/Nginx access logs, and CEF (firewall/SIEM exports) — normalizing everything into a common event schema
- **22 MITRE ATT&CK-mapped detection rules** covering brute force (T1110), privilege escalation (T1078, T1548), persistence (T1053, T1543, T1136), defense evasion (T1070), pass-the-hash (T1550), lateral movement (T1021), firewall C2/recon (T1571, T1046), and web recon (T1083, T1190)
- **Statistical anomaly scorer** — baselines per-user/per-action hourly frequency, flags deviations >2σ, and detects new-IP logins after prior failures (post-brute-force compromise signal)
- **Alert deduplication** — groups repeated events (e.g. 48 brute-force attempts → 1 grouped alert with count) instead of flooding the table
- **Web dashboard** — drag-and-drop upload, stat cards, MITRE ATT&CK tactic breakdown, severity/timeline charts, top attacker IPs, filterable+searchable alert table, click-to-detail modal
- **CLI mode** — same engine, runs headless for automation; outputs terminal / JSON / CSV / PDF
- **PDF report export** — 4-page structured report suitable for incident response documentation

---

## Demo

Click **⚡ Load Demo Data** to run a simulated attack chain across all 5 log formats:

1. **Reconnaissance** — attacker probes SSH with unknown usernames (`root`, `ubuntu`, `oracle`)
2. **Credential Access** — 48 brute-force attempts against `jsmith` from `185.220.101.47`
3. **Initial Access** — successful SSH login after brute force (flagged as CRITICAL)
4. **Privilege Escalation** — `sudo` to root; Windows privileged logon (4672)
5. **Persistence** — scheduled task created (`\Microsoft\Windows\svchost32`), new backdoor account
6. **Defense Evasion** — audit log cleared (Event 1102)
7. **Web layer** — parallel HTTP brute force on `/login`, admin panel probing, server errors

Result: **65 alerts** (26 critical, 10 high, 25 medium) + **70 anomalies** across **271 events** from 5 files.

---

## Quick start

```bash
pip install -r requirements.txt

# Web dashboard
python3 web/app.py
# → open http://localhost:5050

# CLI
python3 cli.py sample_data/sample_auth.log sample_data/sample_windows.csv
python3 cli.py sample_data/ --output pdf --out-file report.pdf
```

---

## Project structure

```
log-analyzer/
├── core/
│   ├── parsers.py      # EVTX, syslog, CSV, JSON, access log, CEF parsers
│   ├── schema.py       # Common Event dataclass
│   └── exporter.py     # PDF (ReportLab) and CSV export
├── detection/
│   ├── rules.py        # 22 MITRE ATT&CK-mapped detection rules
│   └── anomaly.py      # Statistical baseline anomaly scorer
├── web/
│   ├── app.py          # Flask dashboard (upload, demo, export endpoints)
│   └── templates/
│       └── index.html  # Single-page dashboard UI
├── sample_data/
│   ├── generate.py         # Synthetic log generator
│   ├── sample_auth.log     # Linux syslog — SSH brute force + escalation
│   ├── sample_windows.csv  # Windows Event Log export — lateral movement
│   ├── sample_webapp.json  # Web app auth events — pass-the-hash
│   ├── sample_access.log   # Apache access log — web recon + brute force
│   └── sample_firewall.cef # Firewall CEF — blocked/allowed connections
├── cli.py              # Headless CLI entry point
└── requirements.txt
```

---

## Detection rules

| Rule | Name | Tactic | Technique | Severity |
|------|------|--------|-----------|----------|
| R001 | Brute Force Login Attempt | Credential Access | T1110 | High |
| R002 | Successful Login After Failures | Credential Access | T1110.001 | **Critical** |
| R003 | Privileged Account Logon | Privilege Escalation | T1078 | Medium |
| R004 | Explicit Credential Use (RunAs/PTH) | Privilege Escalation | T1550.002 | High |
| R005 | New Service / Driver Installed | Persistence | T1543.003 | High |
| R006 | Scheduled Task Created | Persistence | T1053.005 | High |
| R007 | New Account Created | Persistence | T1136 | Medium |
| R008 | Security Audit Log Cleared | Defense Evasion | T1070.001 | **Critical** |
| R009 | Suspicious Process Creation | Execution | T1059 | Medium |
| R010 | SSH Brute Force (Syslog) | Credential Access | T1110 | High |
| R011 | Invalid / Unknown SSH User | Reconnaissance | T1592 | Medium |
| R012 | Sudo / Privilege Escalation | Privilege Escalation | T1548.003 | High |
| R013 | Group Membership Change | Privilege Escalation | T1098 | Medium |
| R014 | Web Auth Failure (HTTP 401/403) | Credential Access | T1110 | Medium |
| R015 | Suspicious Web Path Probe | Discovery | T1083 | High |
| R016 | HTTP Server Error Spike | Impact | T1499 | Low |
| R017 | Account Lockout | Credential Access | T1110 | High |
| R018 | Network Share Accessed | Lateral Movement | T1021.002 | Medium |
| R019 | RDP Remote Login | Lateral Movement | T1021.001 | High |
| R020 | Firewall — Outbound to Uncommon Port | Command and Control | T1571 | Medium |
| R021 | Firewall — Repeated Inbound Blocks | Reconnaissance | T1046 | Low |
| R022 | Suspicious Web User-Agent | Initial Access | T1190 | Medium |

---

## Tech stack

Python 3.11+ · Flask · pandas · NumPy · ReportLab · python-evtx
