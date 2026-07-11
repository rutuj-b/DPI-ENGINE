"""Blocking rules: filter traffic by IP, application, domain or port."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field

from .classification import AppType, app_type_from_name, app_type_to_string


@dataclass
class BlockReason:
    """Why a packet was blocked."""

    kind: str  # "ip", "app", "domain" or "port"
    detail: str

    def __str__(self) -> str:
        return f"{self.kind.upper()} {self.detail}"


@dataclass
class RuleStats:
    blocked_ips: int
    blocked_apps: int
    blocked_domains: int
    blocked_ports: int


class RuleManager:
    """A thread-safe collection of blocking rules.

    Domain rules match either as a wildcard (``*.example.com``) or, for plain
    strings, as a case-insensitive substring of the inspected domain.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._blocked_ips: set[str] = set()
        self._blocked_apps: set[AppType] = set()
        self._blocked_domains: set[str] = set()  # substring rules
        self._domain_patterns: list[str] = []  # wildcard rules
        self._blocked_ports: set[int] = set()

    # ------------------------------------------------------------------ IPs
    def block_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.add(ip.strip())

    def unblock_ip(self, ip: str) -> None:
        with self._lock:
            self._blocked_ips.discard(ip.strip())

    def is_ip_blocked(self, ip: str) -> bool:
        with self._lock:
            return ip in self._blocked_ips

    def blocked_ips(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    # ------------------------------------------------------------ Apps
    def block_app(self, app: AppType) -> None:
        with self._lock:
            self._blocked_apps.add(app)

    def block_app_name(self, name: str) -> bool:
        """Block by display name; returns ``False`` if the name is unknown."""
        app = app_type_from_name(name)
        if app is None:
            return False
        self.block_app(app)
        return True

    def unblock_app(self, app: AppType) -> None:
        with self._lock:
            self._blocked_apps.discard(app)

    def is_app_blocked(self, app: AppType) -> bool:
        with self._lock:
            return app in self._blocked_apps

    def blocked_apps(self) -> list[AppType]:
        with self._lock:
            return list(self._blocked_apps)

    # ------------------------------------------------------------ Domains
    def block_domain(self, domain: str) -> None:
        domain = domain.strip()
        with self._lock:
            if "*" in domain:
                if domain not in self._domain_patterns:
                    self._domain_patterns.append(domain)
            else:
                self._blocked_domains.add(domain)

    def unblock_domain(self, domain: str) -> None:
        domain = domain.strip()
        with self._lock:
            if "*" in domain:
                if domain in self._domain_patterns:
                    self._domain_patterns.remove(domain)
            else:
                self._blocked_domains.discard(domain)

    def is_domain_blocked(self, domain: str) -> bool:
        if not domain:
            return False
        lowered = domain.lower()
        with self._lock:
            for rule in self._blocked_domains:
                if rule.lower() in lowered:
                    return True
            for pattern in self._domain_patterns:
                if _wildcard_match(lowered, pattern.lower()):
                    return True
        return False

    def blocked_domains(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_domains) + list(self._domain_patterns)

    # ------------------------------------------------------------ Ports
    def block_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.add(port)

    def unblock_port(self, port: int) -> None:
        with self._lock:
            self._blocked_ports.discard(port)

    def is_port_blocked(self, port: int) -> bool:
        with self._lock:
            return port in self._blocked_ports

    # ------------------------------------------------------------ Combined
    def should_block(
        self, src_ip: str, dst_port: int, app: AppType, domain: str
    ) -> BlockReason | None:
        """Return the reason this connection should be blocked, else ``None``.

        Rules are evaluated from most to least specific: IP, port, app, domain.
        """
        if self.is_ip_blocked(src_ip):
            return BlockReason("ip", src_ip)
        if self.is_port_blocked(dst_port):
            return BlockReason("port", str(dst_port))
        if self.is_app_blocked(app):
            return BlockReason("app", app_type_to_string(app))
        if domain and self.is_domain_blocked(domain):
            return BlockReason("domain", domain)
        return None

    # ------------------------------------------------------------ Misc
    def clear(self) -> None:
        with self._lock:
            self._blocked_ips.clear()
            self._blocked_apps.clear()
            self._blocked_domains.clear()
            self._domain_patterns.clear()
            self._blocked_ports.clear()

    def stats(self) -> RuleStats:
        with self._lock:
            return RuleStats(
                blocked_ips=len(self._blocked_ips),
                blocked_apps=len(self._blocked_apps),
                blocked_domains=len(self._blocked_domains) + len(self._domain_patterns),
                blocked_ports=len(self._blocked_ports),
            )


def _wildcard_match(domain: str, pattern: str) -> bool:
    """Match ``*.example.com`` style patterns (both lower-cased already)."""
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        if domain.endswith(suffix):
            return True
        return domain == pattern[2:]  # bare domain also matches
    return False
