"""Rendering of the processing report shown after a capture is filtered."""

from __future__ import annotations

from .classification import app_type_to_string
from .engine import EngineConfig, EngineResult
from .rules import RuleManager

_WIDTH = 64


def _rule(char: str = "=") -> str:
    return char * _WIDTH


def _header(title: str) -> str:
    return f"\n{_rule()}\n{title.center(_WIDTH)}\n{_rule()}"


def format_report(
    result: EngineResult,
    config: EngineConfig,
    rules: RuleManager,
) -> str:
    """Build the full multi-section text report for a completed run."""
    stats = result.stats
    lines: list[str] = []

    lines.append(_header("PROCESSING REPORT"))
    lines.append(f"  Total packets : {stats['total_packets']}")
    lines.append(f"  Total bytes   : {stats['total_bytes']}")
    lines.append(f"  TCP packets   : {stats['tcp_packets']}")
    lines.append(f"  UDP packets   : {stats['udp_packets']}")
    lines.append(f"  Forwarded     : {stats['forwarded']}")
    lines.append(f"  Dropped       : {stats['dropped']}")
    if stats["total_packets"]:
        drop_rate = 100.0 * stats["dropped"] / stats["total_packets"]
        lines.append(f"  Drop rate     : {drop_rate:.2f}%")

    lines.append(_header("THREAD STATISTICS"))
    for i, count in enumerate(result.lb_dispatched):
        lines.append(f"  LB{i} dispatched : {count}")
    for i, count in enumerate(result.fp_processed):
        lines.append(f"  FP{i} processed  : {count}")

    lines.append(_header("APPLICATION BREAKDOWN"))
    lines.extend(_application_breakdown(stats))

    rule_stats = rules.stats()
    if any(
        (
            rule_stats.blocked_ips,
            rule_stats.blocked_apps,
            rule_stats.blocked_domains,
            rule_stats.blocked_ports,
        )
    ):
        lines.append(_header("BLOCKING RULES"))
        lines.append(f"  Blocked IPs     : {rule_stats.blocked_ips}")
        lines.append(f"  Blocked apps    : {rule_stats.blocked_apps}")
        lines.append(f"  Blocked domains : {rule_stats.blocked_domains}")
        lines.append(f"  Blocked ports   : {rule_stats.blocked_ports}")

    domains = stats["detected_domains"]
    if domains:
        lines.append(_header("DETECTED DOMAINS"))
        for domain in sorted(domains):
            lines.append(f"  {domain} -> {app_type_to_string(domains[domain])}")

    lines.append("")
    return "\n".join(lines)


def _application_breakdown(stats: dict) -> list[str]:
    total = stats["total_packets"]
    counts = stats["app_counts"]
    ordered = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)

    rows: list[str] = []
    for app, count in ordered:
        pct = (100.0 * count / total) if total else 0.0
        bar = "#" * int(pct / 5)
        label = app_type_to_string(app)
        rows.append(f"  {label:<15}{count:>6}  {pct:5.1f}%  {bar}")
    return rows
