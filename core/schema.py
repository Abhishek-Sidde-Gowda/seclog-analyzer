"""Common event schema — all parsers normalize into this."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Event:
    timestamp: datetime
    source_ip: Optional[str]
    dest_ip: Optional[str]
    username: Optional[str]
    hostname: Optional[str]
    event_id: Optional[str]
    action: str
    message: str
    raw: str
    log_source: str  # "evtx" | "syslog" | "csv" | "json"
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "username": self.username,
            "hostname": self.hostname,
            "event_id": self.event_id,
            "action": self.action,
            "message": self.message,
            "log_source": self.log_source,
            **self.extra,
        }
