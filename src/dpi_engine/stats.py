"""Thread-safe counters shared across the processing pipeline."""

from __future__ import annotations

import threading

from .classification import AppType


class EngineStats:
    """Aggregated packet, filtering and classification statistics."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.total_packets = 0
        self.total_bytes = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.forwarded = 0
        self.dropped = 0
        self.app_counts: dict[AppType, int] = {}
        self.detected_domains: dict[str, AppType] = {}

    def record_packet(self, size: int, is_tcp: bool, is_udp: bool) -> None:
        with self._lock:
            self.total_packets += 1
            self.total_bytes += size
            if is_tcp:
                self.tcp_packets += 1
            elif is_udp:
                self.udp_packets += 1

    def record_app(self, app: AppType, domain: str) -> None:
        with self._lock:
            self.app_counts[app] = self.app_counts.get(app, 0) + 1
            if domain:
                self.detected_domains[domain] = app

    def record_forwarded(self) -> None:
        with self._lock:
            self.forwarded += 1

    def record_dropped(self) -> None:
        with self._lock:
            self.dropped += 1

    def snapshot(self) -> dict:
        """Return a consistent copy of all counters."""
        with self._lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "forwarded": self.forwarded,
                "dropped": self.dropped,
                "app_counts": dict(self.app_counts),
                "detected_domains": dict(self.detected_domains),
            }
