"""Statistical anomaly scorer — baselines per (username, action) pair and flags deviations."""
from collections import defaultdict
from datetime import timezone
import math
try:
    from ..core.schema import Event
except ImportError:
    from core.schema import Event


class AnomalyScore:
    def __init__(self, event: Event, score: float, reason: str):
        self.event = event
        self.score = round(score, 3)   # 0.0 – 1.0
        self.reason = reason

    def to_dict(self) -> dict:
        d = self.event.to_dict()
        d["anomaly_score"] = self.score
        d["anomaly_reason"] = self.reason
        return d


class AnomalyDetector:
    """
    Lightweight statistical detector:
    - Per-(user, action) hourly frequency baseline using mean + stdev
    - Flags events > 2 stdev above baseline as anomalous
    - Also flags login successes from IPs that had recent failures (new-IP logon)
    """

    def __init__(self, threshold_stdev: float = 2.0):
        self.threshold = threshold_stdev
        # (user, action) -> list of hourly counts across baseline window
        self._hourly: dict[tuple, list[int]] = defaultdict(list)
        self._failure_ips: set[str] = set()

    def fit(self, events: list[Event]) -> None:
        """Build baseline from event list."""
        counts: dict[tuple, dict[int, int]] = defaultdict(lambda: defaultdict(int))
        for e in events:
            if e.username and e.action:
                hour = int(e.timestamp.replace(tzinfo=timezone.utc).timestamp()) // 3600
                counts[(e.username, e.action)][hour] += 1
            if e.action == "login_failure" and e.source_ip:
                self._failure_ips.add(e.source_ip)

        for key, hour_map in counts.items():
            self._hourly[key] = list(hour_map.values())

    def score(self, events: list[Event]) -> list[AnomalyScore]:
        results: list[AnomalyScore] = []
        counts: dict[tuple, int] = defaultdict(int)

        for e in events:
            counts[(e.username, e.action)] += 1

        for e in events:
            reasons = []
            max_score = 0.0

            key = (e.username, e.action)
            baseline = self._hourly.get(key, [])
            if baseline and len(baseline) >= 2:
                mean = sum(baseline) / len(baseline)
                variance = sum((x - mean) ** 2 for x in baseline) / len(baseline)
                stdev = math.sqrt(variance) if variance > 0 else 1.0
                current_count = counts[key]
                z = (current_count - mean) / stdev
                if z > self.threshold:
                    norm = min(z / (self.threshold * 3), 1.0)
                    max_score = max(max_score, norm)
                    reasons.append(
                        f"High frequency: {current_count} events (baseline mean={mean:.1f}, z={z:.1f})"
                    )

            # New-IP logon after failure
            if (e.action == "login_success" and e.source_ip and
                    e.source_ip in self._failure_ips):
                max_score = max(max_score, 0.85)
                reasons.append(
                    f"Login success from IP {e.source_ip} that previously had failures"
                )

            # Off-hours login (22:00 – 06:00 UTC)
            hour = e.timestamp.hour
            if e.action in ("login_success", "privileged_logon") and (hour >= 22 or hour < 6):
                max_score = max(max_score, 0.55)
                reasons.append(f"Login at off-hours UTC {hour:02d}:xx")

            if max_score > 0:
                results.append(AnomalyScore(e, max_score, "; ".join(reasons)))

        results.sort(key=lambda x: x.score, reverse=True)
        return results


def score_events(events: list[Event]) -> list[AnomalyScore]:
    detector = AnomalyDetector()
    detector.fit(events)
    return detector.score(events)
