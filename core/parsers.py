"""Multi-format log parsers: EVTX, syslog, CSV, JSON."""
import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from .schema import Event

# ── helpers ────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USER_RE = re.compile(
    r"(?:user(?:name)?[=:\s]+|for\s+)([a-zA-Z0-9_.\-@$]+)(?:\s+from|\s+port|\s*$|[,;])",
    re.I,
)

def _extract_ip(text: str) -> list[str]:
    return _IP_RE.findall(text or "")

def _extract_user(text: str) -> str | None:
    m = _USER_RE.search(text or "")
    return m.group(1) if m else None

def _now() -> datetime:
    return datetime.now(timezone.utc)

# ── EVTX ───────────────────────────────────────────────────────────────────

def parse_evtx(path: str) -> Iterator[Event]:
    try:
        from Evtx.Evtx import Evtx
        import xml.etree.ElementTree as ET
    except ImportError:
        raise RuntimeError("python-evtx not installed")

    NS = "http://schemas.microsoft.com/win/2004/08/events/event"

    def _tag(name: str) -> str:
        return f"{{{NS}}}{name}"

    with Evtx(path) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)

                sys_el = root.find(_tag("System"))
                event_id = sys_el.findtext(f"{{{NS}}}EventID") if sys_el else None
                ts_str = (sys_el.find(_tag("TimeCreated")).get("SystemTime")
                          if sys_el is not None else None)
                try:
                    ts = datetime.fromisoformat(ts_str.rstrip("Z")).replace(
                        tzinfo=timezone.utc)
                except Exception:
                    ts = _now()

                data_el = root.find(f".//{_tag('EventData')}")
                fields: dict[str, str] = {}
                if data_el is not None:
                    for d in data_el:
                        name = d.get("Name", "")
                        fields[name] = d.text or ""

                username = (fields.get("TargetUserName") or
                            fields.get("SubjectUserName") or
                            _extract_user(xml_str))
                ips = _extract_ip(xml_str)
                src_ip = fields.get("IpAddress") or (ips[0] if ips else None)
                hostname = (sys_el.findtext(f"{{{NS}}}Computer") if sys_el else None)
                action = _evtx_action(event_id, fields)

                yield Event(
                    timestamp=ts,
                    source_ip=src_ip,
                    dest_ip=None,
                    username=username,
                    hostname=hostname,
                    event_id=event_id,
                    action=action,
                    message=fields.get("Message", xml_str[:120]),
                    raw=xml_str,
                    log_source="evtx",
                    extra={"evtx_fields": fields},
                )
            except Exception:
                continue


def _evtx_action(event_id: str | None, fields: dict) -> str:
    mapping = {
        "4624": "login_success",
        "4625": "login_failure",
        "4648": "explicit_credential_use",
        "4672": "privileged_logon",
        "4688": "process_create",
        "4697": "service_install",
        "4698": "scheduled_task_created",
        "4720": "account_created",
        "4728": "group_member_added",
        "4732": "local_group_member_added",
        "4756": "universal_group_member_added",
        "4776": "credential_validation",
        "7045": "new_service",
        "1102": "audit_log_cleared",
    }
    return mapping.get(str(event_id), f"event_{event_id}")


# ── Syslog ─────────────────────────────────────────────────────────────────

# RFC 3164 / 5424 hybrid regex
_SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:\[]+)(?:\[\d+\])?:\s*(?P<msg>.+)$"
)
_SYSLOG5424_RE = re.compile(
    r"^<\d+>1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<msg>.+)$"
)


def parse_syslog(path: str) -> Iterator[Event]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            event = _parse_syslog_line(line)
            if event:
                yield event


def _parse_syslog_line(line: str) -> Event | None:
    ts = _now()
    host = None
    msg = line

    m = _SYSLOG5424_RE.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m.group("ts").rstrip("Z")).replace(
                tzinfo=timezone.utc)
        except Exception:
            pass
        host = m.group("host")
        msg = m.group("msg")
    else:
        m = _SYSLOG_RE.match(line)
        if m:
            host = m.group("host")
            msg = m.group("msg")
            try:
                year = datetime.now().year
                ts = datetime.strptime(
                    f"{year} {m.group('month')} {m.group('day')} {m.group('time')}",
                    "%Y %b %d %H:%M:%S",
                ).replace(tzinfo=timezone.utc)
            except Exception:
                pass

    ips = _extract_ip(msg)
    action = _syslog_action(msg)

    return Event(
        timestamp=ts,
        source_ip=ips[0] if ips else None,
        dest_ip=ips[1] if len(ips) > 1 else None,
        username=_extract_user(msg),
        hostname=host,
        event_id=None,
        action=action,
        message=msg[:300],
        raw=line,
        log_source="syslog",
    )


def _syslog_action(msg: str) -> str:
    ml = msg.lower()
    if "failed password" in ml or "authentication failure" in ml:
        return "login_failure"
    if "accepted password" in ml or "session opened" in ml:
        return "login_success"
    if "sudo" in ml:
        return "privilege_escalation"
    if "segfault" in ml or "kernel" in ml:
        return "kernel_event"
    if "connection" in ml:
        return "network_connection"
    if "invalid user" in ml or "illegal user" in ml:
        return "invalid_user"
    return "syslog_event"


# ── CSV ────────────────────────────────────────────────────────────────────

_TIMESTAMP_COLS = ["timestamp", "time", "datetime", "date", "ts", "@timestamp"]
_USER_COLS = ["username", "user", "account", "logon_id"]
_SRC_COLS = ["source_ip", "src_ip", "src", "client_ip", "ip_address", "ip"]
_DST_COLS = ["dest_ip", "dst_ip", "dst", "destination_ip"]
_ACTION_COLS = ["action", "event_type", "type", "activity"]
_MSG_COLS = ["message", "msg", "description", "details"]
_HOST_COLS = ["hostname", "host", "computer", "workstation"]
_EID_COLS = ["event_id", "eventid", "event_code"]


def _first(row: dict, keys: list[str]) -> str | None:
    for k in keys:
        for col in row:
            if col.lower() == k:
                return row[col] or None
    return None


def _parse_ts(val: str) -> datetime:
    if not val:
        return _now()
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(val.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return _now()


def parse_csv(path: str) -> Iterator[Event]:
    with open(path, "r", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ts_raw = _first(row, _TIMESTAMP_COLS) or ""
            msg = _first(row, _MSG_COLS) or str(dict(row))[:200]
            action = _first(row, _ACTION_COLS) or _syslog_action(msg)
            ips = _extract_ip(msg)
            yield Event(
                timestamp=_parse_ts(ts_raw),
                source_ip=_first(row, _SRC_COLS) or (ips[0] if ips else None),
                dest_ip=_first(row, _DST_COLS) or (ips[1] if len(ips) > 1 else None),
                username=_first(row, _USER_COLS) or _extract_user(msg),
                hostname=_first(row, _HOST_COLS),
                event_id=_first(row, _EID_COLS),
                action=action,
                message=msg,
                raw=str(dict(row)),
                log_source="csv",
                extra={k: v for k, v in row.items()},
            )


# ── JSON ───────────────────────────────────────────────────────────────────

def parse_json(path: str) -> Iterator[Event]:
    with open(path, "r", errors="replace") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            f.seek(0)
            data = [json.loads(line) for line in f if line.strip()]

    if isinstance(data, dict):
        data = [data]

    for record in data:
        if not isinstance(record, dict):
            continue
        row = {k.lower(): v for k, v in record.items()}
        ts_raw = str(_first(row, _TIMESTAMP_COLS) or "")
        msg = str(_first(row, _MSG_COLS) or json.dumps(record)[:200])
        action = str(_first(row, _ACTION_COLS) or _syslog_action(msg))
        ips = _extract_ip(msg)
        yield Event(
            timestamp=_parse_ts(ts_raw),
            source_ip=str(_first(row, _SRC_COLS) or (ips[0] if ips else "")) or None,
            dest_ip=str(_first(row, _DST_COLS) or (ips[1] if len(ips) > 1 else "")) or None,
            username=str(_first(row, _USER_COLS) or _extract_user(msg) or "") or None,
            hostname=str(_first(row, _HOST_COLS) or "") or None,
            event_id=str(_first(row, _EID_COLS) or "") or None,
            action=action,
            message=msg,
            raw=json.dumps(record),
            log_source="json",
            extra=row,
        )


# ── Apache / Nginx access log ───────────────────────────────────────────────

# Combined Log Format: 1.2.3.4 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)

def parse_accesslog(path: str) -> Iterator[Event]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if not line:
                continue
            m = _APACHE_RE.match(line)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("ts"), "%d/%b/%Y:%H:%M:%S %z")
            except Exception:
                ts = _now()
            status = m.group("status")
            method = m.group("method")
            path_str = m.group("path")
            user = m.group("user") if m.group("user") != "-" else None
            action = _http_action(status, method, path_str)
            yield Event(
                timestamp=ts,
                source_ip=m.group("ip"),
                dest_ip=None,
                username=user,
                hostname=None,
                event_id=status,
                action=action,
                message=f'{method} {path_str} → {status}',
                raw=line,
                log_source="accesslog",
                extra={"method": method, "path": path_str,
                       "status": status, "size": m.group("size")},
            )

def _http_action(status: str, method: str, path: str) -> str:
    code = int(status)
    pl = path.lower()
    if code in (401, 403):
        return "http_auth_failure"
    if code == 200 and method == "POST" and any(k in pl for k in ("/login", "/auth", "/signin")):
        return "login_success"
    if code >= 500:
        return "http_server_error"
    if code == 404:
        return "http_not_found"
    if any(k in pl for k in ("/admin", "/wp-admin", "/.env", "/phpinfo", "/etc/passwd")):
        return "http_suspicious_path"
    return "http_request"


# ── CEF (Common Event Format) ───────────────────────────────────────────────

_CEF_RE = re.compile(
    r"CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<pver>[^|]*)\|"
    r"(?P<sig>[^|]*)\|(?P<name>[^|]*)\|(?P<sev>[^|]*)\|(?P<ext>.*)"
)
_CEF_KV = re.compile(r'(\w+)=((?:[^\\=\s]|\\.)+?)(?=\s+\w+=|$)')

def parse_cef(path: str) -> Iterator[Event]:
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            if "CEF:" not in line:
                continue
            # Strip syslog prefix if present
            cef_start = line.find("CEF:")
            m = _CEF_RE.match(line[cef_start:])
            if not m:
                continue
            ext = dict(_CEF_KV.findall(m.group("ext")))
            ts_raw = ext.get("rt") or ext.get("start") or ""
            try:
                ts = datetime.fromtimestamp(int(ts_raw)/1000, tz=timezone.utc) if ts_raw.isdigit() else _now()
            except Exception:
                ts = _now()
            yield Event(
                timestamp=ts,
                source_ip=ext.get("src") or ext.get("sourceAddress"),
                dest_ip=ext.get("dst") or ext.get("destinationAddress"),
                username=ext.get("suser") or ext.get("duser"),
                hostname=ext.get("dhost") or ext.get("shost"),
                event_id=m.group("sig"),
                action=m.group("name").lower().replace(" ", "_"),
                message=m.group("name"),
                raw=line,
                log_source="cef",
                extra=ext,
            )


# ── Dispatcher ─────────────────────────────────────────────────────────────

def _sniff(path: str) -> str:
    """Return format hint by reading first 2KB."""
    try:
        with open(path, "rb") as f:
            head = f.read(2048).decode("utf-8", errors="replace")
    except Exception:
        return "syslog"
    if head.strip().startswith("{") or head.strip().startswith("["):
        return "json"
    if "CEF:" in head:
        return "cef"
    # Apache/Nginx: first non-empty line matches combined log pattern
    for line in head.splitlines():
        if line.strip() and _APACHE_RE.match(line):
            return "accesslog"
    first_line = head.split("\n")[0]
    if "," in first_line and not first_line.startswith("<"):
        return "csv"
    return "syslog"


def parse_file(path: str) -> list[Event]:
    p = Path(path)
    ext = p.suffix.lower()
    if ext == ".evtx":
        return list(parse_evtx(path))
    if ext == ".csv":
        return list(parse_csv(path))
    if ext == ".json":
        return list(parse_json(path))
    if ext == ".cef":
        return list(parse_cef(path))
    if ext in (".log", ".syslog", ".txt", ".access"):
        fmt = _sniff(path)
        if fmt == "accesslog":
            return list(parse_accesslog(path))
        if fmt == "cef":
            return list(parse_cef(path))
        if fmt == "json":
            return list(parse_json(path))
        return list(parse_syslog(path))
    # Unknown extension — sniff
    fmt = _sniff(path)
    dispatch = {"json": parse_json, "csv": parse_csv, "cef": parse_cef,
                "accesslog": parse_accesslog, "syslog": parse_syslog}
    return list(dispatch.get(fmt, parse_syslog)(path))
