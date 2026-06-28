"""Generate realistic synthetic log files for demo purposes."""
import csv
import json
import os
import random
from datetime import datetime, timedelta, timezone

random.seed(42)

USERS = ["jsmith", "agarcia", "bwilliams", "mchen", "kpatel", "SYSTEM", "Administrator"]
HOSTS = ["WS-001", "WS-042", "SRV-DC01", "SRV-WEB02", "LAPTOP-HR"]
ATTACKER_IP = "185.220.101.47"   # known Tor exit node range (fake but realistic)
INTERNAL_IPS = [f"10.0.1.{i}" for i in range(5, 30)]

BASE_TIME = datetime(2025, 6, 15, 8, 0, 0, tzinfo=timezone.utc)


def rand_time(offset_hours: float = 0, jitter_min: int = 30) -> datetime:
    jitter = timedelta(minutes=random.randint(0, jitter_min))
    return BASE_TIME + timedelta(hours=offset_hours) + jitter


# ── Syslog ─────────────────────────────────────────────────────────────────

def generate_syslog(path: str) -> None:
    lines = []

    def syslog_line(ts: datetime, host: str, proc: str, msg: str) -> str:
        return ts.strftime(f"%b %d %H:%M:%S") + f" {host} {proc}: {msg}"

    # Normal SSH logins
    for i in range(20):
        ts = rand_time(i * 0.4)
        user = random.choice(USERS[:4])
        ip = random.choice(INTERNAL_IPS)
        lines.append((ts, syslog_line(ts, "srv-ssh", "sshd",
            f"Accepted password for {user} from {ip} port {random.randint(30000,65000)} ssh2")))

    # Brute force burst — attacker hammering jsmith
    for i in range(48):
        ts = rand_time(3.0, jitter_min=5) + timedelta(seconds=i * 12)
        lines.append((ts, syslog_line(ts, "srv-ssh", "sshd",
            f"Failed password for jsmith from {ATTACKER_IP} port {random.randint(30000,65000)} ssh2")))

    # Attacker succeeds after brute force
    ts = rand_time(3.2)
    lines.append((ts, syslog_line(ts, "srv-ssh", "sshd",
        f"Accepted password for jsmith from {ATTACKER_IP} port 44123 ssh2")))

    # Attacker tries unknown users
    for user in ["admin", "root", "ubuntu", "oracle", "test"]:
        ts = rand_time(2.9, jitter_min=10)
        lines.append((ts, syslog_line(ts, "srv-ssh", "sshd",
            f"Invalid user {user} from {ATTACKER_IP} port {random.randint(30000,65000)}")))

    # Sudo escalation post-compromise
    ts = rand_time(3.5)
    lines.append((ts, syslog_line(ts, "srv-ssh", "sudo",
        f"jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash")))

    # Off-hours login
    ts = BASE_TIME + timedelta(hours=23, minutes=14)
    lines.append((ts, syslog_line(ts, "WS-001", "sshd",
        f"Accepted password for agarcia from 10.0.1.9 port 52100 ssh2")))

    lines.sort(key=lambda x: x[0])
    with open(path, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    print(f"  [+] {path}: {len(lines)} syslog lines")


# ── CSV ────────────────────────────────────────────────────────────────────

def generate_csv(path: str) -> None:
    rows = []

    # Normal activity
    for i in range(30):
        ts = rand_time(i * 0.25)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": random.choice(HOSTS),
            "username": random.choice(USERS[:4]),
            "source_ip": random.choice(INTERNAL_IPS),
            "event_id": "4624",
            "action": "login_success",
            "message": "User logged on successfully",
        })

    # Brute force from attacker
    for i in range(35):
        ts = rand_time(4.0) + timedelta(seconds=i * 8)
        rows.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": "SRV-DC01",
            "username": "Administrator",
            "source_ip": ATTACKER_IP,
            "event_id": "4625",
            "action": "login_failure",
            "message": f"Logon failure - unknown username or bad password. Status: 0xC000006D",
        })

    # Privilege escalation
    ts = rand_time(5.0)
    rows.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": "SRV-DC01",
        "username": "Administrator",
        "source_ip": ATTACKER_IP,
        "event_id": "4672",
        "action": "privileged_logon",
        "message": "Special privileges assigned to new logon. Privileges: SeDebugPrivilege SeImpersonatePrivilege",
    })

    # Scheduled task persistence
    ts = rand_time(5.2)
    rows.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": "SRV-DC01",
        "username": "Administrator",
        "source_ip": ATTACKER_IP,
        "event_id": "4698",
        "action": "scheduled_task_created",
        "message": "A scheduled task was created. Task: \\Microsoft\\Windows\\svchost32",
    })

    # Audit log cleared
    ts = rand_time(5.8)
    rows.append({
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": "SRV-DC01",
        "username": "Administrator",
        "source_ip": ATTACKER_IP,
        "event_id": "1102",
        "action": "audit_log_cleared",
        "message": "The audit log was cleared. Subject: Administrator",
    })

    rows.sort(key=lambda r: r["timestamp"])
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"  [+] {path}: {len(rows)} CSV rows")


# ── JSON ───────────────────────────────────────────────────────────────────

def generate_json(path: str) -> None:
    records = []

    # Normal web-app auth events
    for i in range(20):
        ts = rand_time(i * 0.3)
        records.append({
            "timestamp": ts.isoformat(),
            "host": random.choice(HOSTS),
            "username": random.choice(USERS[:5]),
            "source_ip": random.choice(INTERNAL_IPS),
            "event_type": "login_success",
            "message": "User authenticated via web portal",
            "session_id": f"sess_{random.randint(100000,999999)}",
        })

    # Pass-the-hash style: explicit credential use from attacker IP
    for _ in range(6):
        ts = rand_time(6.5, jitter_min=15)
        records.append({
            "timestamp": ts.isoformat(),
            "host": "WS-042",
            "username": "mchen",
            "source_ip": ATTACKER_IP,
            "event_type": "explicit_credential_use",
            "event_id": "4648",
            "message": "A logon was attempted using explicit credentials. Target: SRV-DC01",
        })

    # New account created
    ts = rand_time(7.0)
    records.append({
        "timestamp": ts.isoformat(),
        "host": "SRV-DC01",
        "username": "Administrator",
        "source_ip": ATTACKER_IP,
        "event_type": "account_created",
        "event_id": "4720",
        "message": "A user account was created. New Account: svc_backup$ (possible backdoor)",
    })

    # New service installed (persistence)
    ts = rand_time(7.3)
    records.append({
        "timestamp": ts.isoformat(),
        "host": "SRV-DC01",
        "username": "SYSTEM",
        "source_ip": None,
        "event_type": "service_install",
        "event_id": "4697",
        "message": "A service was installed: DisplayName=WindowsUpdateHelper, ImagePath=C:\\Windows\\Temp\\wupd.exe",
    })

    records.sort(key=lambda r: r["timestamp"])
    with open(path, "w") as f:
        json.dump(records, f, indent=2)

    print(f"  [+] {path}: {len(records)} JSON records")


def generate_accesslog(path: str) -> None:
    lines = []

    def access_line(ts: datetime, ip: str, method: str, url: str,
                    status: int, size: int = 512) -> str:
        ts_str = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
        return f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size}'

    # Normal browsing
    pages = ["/", "/index.html", "/about", "/contact", "/products", "/api/items"]
    for i in range(40):
        ts = rand_time(i * 0.15)
        lines.append(access_line(ts, random.choice(INTERNAL_IPS),
                                 "GET", random.choice(pages), 200,
                                 random.randint(512, 8192)))

    # Attacker probing sensitive paths
    probes = ["/admin", "/wp-admin/", "/.env", "/phpinfo.php",
              "/etc/passwd", "/.git/config", "/backup.zip", "/config.php"]
    for probe in probes:
        ts = rand_time(2.0, jitter_min=10)
        lines.append(access_line(ts, ATTACKER_IP, "GET", probe, 404))

    # Auth brute force via web
    for i in range(20):
        ts = rand_time(2.5) + timedelta(seconds=i * 15)
        lines.append(access_line(ts, ATTACKER_IP, "POST", "/login", 401, 128))

    # Successful web login after brute force
    ts = rand_time(2.6)
    lines.append(access_line(ts, ATTACKER_IP, "POST", "/login", 200, 256))

    # Server errors (exploitation attempts)
    for i in range(5):
        ts = rand_time(3.0, jitter_min=5)
        lines.append(access_line(ts, ATTACKER_IP, "GET",
                                 f"/api/exec?cmd=whoami&id={i}", 500, 64))

    lines.sort(key=lambda l: l[5:30])  # sort by timestamp portion
    with open(path, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"  [+] {path}: {len(lines)} access log lines")


def generate_cef(path: str) -> None:
    """Simulate firewall CEF logs."""
    lines = []

    def cef_line(ts: datetime, sig: str, name: str, sev: int,
                 src: str, dst: str, dpt: int, act: str) -> str:
        epoch_ms = int(ts.timestamp() * 1000)
        return (f"<14>1 {ts.strftime('%Y-%m-%dT%H:%M:%SZ')} fw01 FW 1.0 - - "
                f"CEF:0|Acme|Firewall|1.0|{sig}|{name}|{sev}|"
                f"src={src} dst={dst} dpt={dpt} act={act} rt={epoch_ms}")

    # Normal outbound
    for i in range(15):
        ts = rand_time(i * 0.3)
        lines.append(cef_line(ts, "ALLOW-OUT", "Outbound Connection", 3,
                              random.choice(INTERNAL_IPS), "8.8.8.8",
                              443, "allow"))

    # Attacker inbound blocked then allowed (firewall bypass)
    for i in range(8):
        ts = rand_time(1.5) + timedelta(minutes=i * 3)
        lines.append(cef_line(ts, "BLOCK-IN", "Inbound Connection Blocked", 7,
                              ATTACKER_IP, "10.0.1.5", 22, "block"))

    # Eventually gets through (port knocking / rule change)
    ts = rand_time(2.0)
    lines.append(cef_line(ts, "ALLOW-IN", "Inbound Connection Allowed", 8,
                          ATTACKER_IP, "10.0.1.5", 22, "allow"))

    # Data exfiltration — large outbound transfer
    ts = rand_time(6.0)
    epoch_ms = int(ts.timestamp() * 1000)
    lines.append(
        f"<14>1 {ts.strftime('%Y-%m-%dT%H:%M:%SZ')} fw01 FW 1.0 - - "
        f"CEF:0|Acme|Firewall|1.0|EXFIL|Large Data Transfer|9|"
        f"src=10.0.1.5 dst={ATTACKER_IP} dpt=443 act=allow "
        f"bytesOut=52428800 rt={epoch_ms}"
    )

    with open(path, "w") as f:
        for line in lines:
            f.write(line + "\n")

    print(f"  [+] {path}: {len(lines)} CEF log lines")


if __name__ == "__main__":
    out = os.path.dirname(__file__)
    print("[*] Generating synthetic sample logs...")
    generate_syslog(os.path.join(out, "sample_auth.log"))
    generate_csv(os.path.join(out, "sample_windows.csv"))
    generate_json(os.path.join(out, "sample_webapp.json"))
    generate_accesslog(os.path.join(out, "sample_access.log"))
    generate_cef(os.path.join(out, "sample_firewall.cef"))
    print("[*] Done.")
