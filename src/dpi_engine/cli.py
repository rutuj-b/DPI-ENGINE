"""Command-line interface for the DPI engine."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .engine import DPIEngine, EngineConfig
from .reports import format_report
from .rules import RuleManager


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dpi-engine",
        description="Deep packet inspection: classify and filter PCAP traffic.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Filter a capture through the DPI pipeline.")
    run.add_argument("input", help="Input PCAP file (captured traffic).")
    run.add_argument("output", help="Output PCAP file (forwarded traffic).")
    run.add_argument(
        "--block-ip", action="append", default=[], metavar="IP",
        help="Block traffic from a source IP (repeatable).",
    )
    run.add_argument(
        "--block-app", action="append", default=[], metavar="APP",
        help="Block an application, e.g. YouTube (repeatable).",
    )
    run.add_argument(
        "--block-domain", action="append", default=[], metavar="DOMAIN",
        help="Block a domain; substring or *.wildcard (repeatable).",
    )
    run.add_argument(
        "--block-port", action="append", type=int, default=[], metavar="PORT",
        help="Block a destination port (repeatable).",
    )
    run.add_argument("--lbs", type=int, default=2, help="Load balancer threads (default: 2).")
    run.add_argument("--fps", type=int, default=2, help="Fast-path workers per LB (default: 2).")
    run.set_defaults(func=_cmd_run)

    dump = sub.add_parser("dump", help="Print a per-packet summary of a capture.")
    dump.add_argument("input", help="Input PCAP file.")
    dump.add_argument("-n", "--max-packets", type=int, default=None, help="Stop after N packets.")
    dump.set_defaults(func=_cmd_dump)

    gen = sub.add_parser("generate-testdata", help="Write a synthetic test capture.")
    gen.add_argument("output", nargs="?", default="test_dpi.pcap", help="Output PCAP path.")
    gen.add_argument("--seed", type=int, default=1234, help="Random seed (default: 1234).")
    gen.set_defaults(func=_cmd_generate)

    return parser


def _cmd_run(args: argparse.Namespace) -> int:
    rules = RuleManager()
    for ip in args.block_ip:
        rules.block_ip(ip)
    for app in args.block_app:
        if not rules.block_app_name(app):
            print(f"Warning: unknown application '{app}'", file=sys.stderr)
    for domain in args.block_domain:
        rules.block_domain(domain)
    for port in args.block_port:
        rules.block_port(port)

    config = EngineConfig(num_load_balancers=args.lbs, fps_per_lb=args.fps)
    engine = DPIEngine(config=config, rules=rules)

    print(f"Processing {args.input} -> {args.output}")
    print(f"Pipeline: {config.num_load_balancers} load balancers x "
          f"{config.fps_per_lb} workers = {config.total_fps} fast paths")

    result = engine.process(args.input, args.output)
    print(format_report(result, config, rules))
    print(f"Output written to: {args.output}")
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    from .dump import dump_file

    dump_file(args.input, args.max_packets)
    return 0


def _cmd_generate(args: argparse.Namespace) -> int:
    from .capture_gen import generate

    path = generate(args.output, seed=args.seed)
    print(f"Wrote synthetic capture to {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
