# DPI Engine

**A multi-threaded deep packet inspection engine in pure Python — classify network traffic by application and filter it with flexible blocking rules, straight from PCAP files.**

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Tests](https://img.shields.io/badge/tests-38%20passing-brightgreen)

---

## Overview

Even though HTTPS traffic is encrypted, the destination hostname travels in the clear inside the TLS ClientHello — the **Server Name Indication (SNI)** field. DPI Engine exploits this, together with HTTP `Host` headers and DNS queries, to recognise which service every connection is talking to (YouTube, Facebook, GitHub, and more) and to allow or drop it based on rules you define.

```
  input.pcap  ──►   DPI Engine   ──►   output.pcap  +  traffic report
                    ├─ parse Ethernet / IPv4 / TCP / UDP
                    ├─ inspect payloads (TLS SNI, HTTP Host, DNS)
                    ├─ classify each flow by application
                    ├─ apply blocking rules (IP / app / domain / port)
                    └─ forward allowed packets, drop the rest
```

Given a capture, the engine produces a filtered capture containing only the traffic that passed the rules, plus a detailed report: packet statistics, per-thread workload, an application breakdown, and every domain it detected.

## Features

- **PCAP reader and writer** — classic libpcap captures, little- or big-endian, streamed packet by packet.
- **Protocol parser** — Ethernet, IPv4, TCP and UDP headers with correct handling of variable-length headers.
- **Deep payload inspection**:
  - TLS ClientHello → Server Name Indication (SNI)
  - HTTP request → `Host` header (case-insensitive, port-stripped)
  - DNS request → queried domain name
- **Application classification** — ~20 well-known services recognised via domain signatures, with a generic HTTP/HTTPS fallback.
- **Flow-level filtering** — connections are tracked by their five-tuple, so a blocking decision made on one packet applies to the entire connection.
- **Flexible blocking rules** — by source IP, application name, domain (substring or `*.wildcard`), and destination port.
- **Concurrent pipeline** — reader → load balancers → fast-path workers → writer, with consistent hashing so every packet of a flow reaches the same worker and per-flow state stays coherent.
- **Rich reporting** — totals, drop rate, per-thread statistics, application breakdown with bar charts, and detected domains.
- **Synthetic capture generator** — try the engine instantly, no real traffic needed.
- **Zero dependencies** — 100% Python standard library.

## Requirements

- Python **3.10** or newer — nothing else.

## Installation

Clone the repository and install it (editable install recommended for development):

```bash
pip install -e .
```

This exposes the `dpi-engine` command. Alternatively, run directly from the source tree without installing:

```bash
PYTHONPATH=src python -m dpi_engine <command> ...
```

## Quick Start

```bash
# 1. Generate a sample capture to play with
dpi-engine generate-testdata sample.pcap

# 2. Filter it: block YouTube, one source IP, and any Facebook domain
dpi-engine run sample.pcap filtered.pcap \
    --block-app YouTube \
    --block-ip 192.168.1.50 \
    --block-domain facebook

# 3. Inspect the result packet by packet
dpi-engine dump filtered.pcap -n 10
```

## Usage

### Filter a capture

```bash
dpi-engine run <input.pcap> <output.pcap> [options]
```

| Option | Description |
|---|---|
| `--block-ip IP` | Block all traffic from a source IP (repeatable) |
| `--block-app APP` | Block an application, e.g. `YouTube` (repeatable) |
| `--block-domain DOMAIN` | Block a domain — substring or `*.wildcard` (repeatable) |
| `--block-port PORT` | Block a destination port (repeatable) |
| `--lbs N` | Number of load-balancer threads (default: 2) |
| `--fps N` | Fast-path workers per load balancer (default: 2) |

Example with a larger pipeline:

```bash
dpi-engine run capture.pcap filtered.pcap --lbs 4 --fps 4
# 4 load balancers x 4 workers = 16 fast-path threads
```

### Inspect a capture

```bash
dpi-engine dump capture.pcap          # every packet
dpi-engine dump capture.pcap -n 10    # first 10 packets only
```

Prints timestamps, MAC addresses, IPs, ports, TCP flags and a payload preview for each packet.

### Generate test data

```bash
dpi-engine generate-testdata sample.pcap [--seed N]
```

Writes a small capture containing TLS handshakes (with SNI), plaintext HTTP requests, DNS queries, and traffic from a fixed "suspicious" source address — ideal for experimenting with blocking rules.

### Blockable applications

`Google`, `YouTube`, `Facebook`, `Instagram`, `Twitter/X`, `Netflix`, `Amazon`, `Microsoft`, `Apple`, `WhatsApp`, `Telegram`, `TikTok`, `Spotify`, `Zoom`, `Discord`, `GitHub`, `Cloudflare` — plus generic `HTTP`, `HTTPS` and `DNS`. Names are matched case-insensitively.

## Library API

Everything the CLI does is available programmatically:

```python
from dpi_engine import DPIEngine, EngineConfig, RuleManager, AppType

rules = RuleManager()
rules.block_app(AppType.YOUTUBE)
rules.block_domain("*.tiktok.com")

engine = DPIEngine(
    config=EngineConfig(num_load_balancers=2, fps_per_lb=2),
    rules=rules,
)
result = engine.process("input.pcap", "output.pcap")

print(result.stats["forwarded"], "forwarded /", result.stats["dropped"], "dropped")
for domain, app in result.stats["detected_domains"].items():
    print(f"  {domain} -> {app.value}")
```

## How It Works

Every connection is identified by its **five-tuple** — source IP, destination IP, source port, destination port and protocol. All packets sharing a five-tuple belong to the same flow.

```
                 ┌────────────────┐
                 │  Reader thread │  parses headers, hashes the five-tuple
                 └───────┬────────┘
              hash % LBs │
            ┌────────────┴────────────┐
            ▼                         ▼
    ┌───────────────┐         ┌───────────────┐
    │ Load balancer │         │ Load balancer │   consistent hashing:
    └───────┬───────┘         └───────┬───────┘   same flow → same worker
       ┌────┴────┐               ┌────┴────┐
       ▼         ▼               ▼         ▼
   ┌───────┐ ┌───────┐       ┌───────┐ ┌───────┐
   │Worker │ │Worker │       │Worker │ │Worker │  classify + apply rules
   └───┬───┘ └───┬───┘       └───┬───┘ └───┬───┘
       └─────────┴───────┬───────┴─────────┘
                         ▼
                 ┌───────────────┐
                 │ Writer thread │  writes forwarded packets to output
                 └───────────────┘
```

1. **Reader** — streams packets from the input PCAP, parses protocol headers, and hashes each packet's five-tuple to pick a load balancer.
2. **Load balancers** — hash the five-tuple again to pick a fast-path worker, guaranteeing a flow always lands on the same worker.
3. **Fast-path workers** — each maintains a private flow table, runs deep inspection to classify the flow, consults the rules, and either forwards the packet or drops it. Once a flow is blocked, it stays blocked.
4. **Writer** — drains the output queue and writes forwarded packets to the output PCAP.

Classification is **progressive**: a flow first receives a port-based guess (`443 → HTTPS`, `80 → HTTP`), which is upgraded the moment a hostname is recovered from a ClientHello, `Host` header or DNS query.

## Project Structure

```
├── pyproject.toml
├── src/
│   └── dpi_engine/
│       ├── pcap.py            # PCAP file reading and writing
│       ├── parser.py          # Ethernet / IPv4 / TCP / UDP parsing
│       ├── inspection.py      # TLS SNI, HTTP Host and DNS extraction
│       ├── classification.py  # domain-to-application signatures
│       ├── rules.py           # blocking rule engine
│       ├── flow.py            # per-flow state and classification
│       ├── stats.py           # thread-safe counters
│       ├── engine.py          # reader → LB → worker → writer pipeline
│       ├── reports.py         # report rendering
│       ├── dump.py            # per-packet inspection output
│       ├── capture_gen.py     # synthetic capture generator
│       └── cli.py             # command-line interface
└── tests/                     # unit and end-to-end tests
```

## Development & Testing

Run the full test suite with the standard library runner (no extra installs):

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

Or with pytest:

```bash
pip install -e ".[dev]"
pytest
```

The suite covers protocol parsing, payload inspection, classification signatures, rule evaluation, PCAP round-tripping, and full end-to-end pipeline runs across multiple thread configurations.
## Author

**Rutuj Bawankar**
GitHub: [@rutuj-b](https://github.com/rutuj-b)
