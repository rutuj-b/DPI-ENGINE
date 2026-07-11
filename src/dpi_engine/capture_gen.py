"""Synthetic capture generator for exercising the engine.

Builds a small PCAP containing TLS ClientHellos (with SNI), plaintext HTTP
requests, DNS queries and some traffic from a fixed "blocked" source address.
"""

from __future__ import annotations

import random
import struct

USER_MAC = "00:11:22:33:44:55"
GATEWAY_MAC = "aa:bb:cc:dd:ee:ff"
USER_IP = "192.168.1.100"
DNS_SERVER = "8.8.8.8"
BLOCKED_SOURCE_IP = "192.168.1.50"

TLS_CONNECTIONS = [
    ("142.250.185.206", "www.google.com", 443),
    ("142.250.185.110", "www.youtube.com", 443),
    ("157.240.1.35", "www.facebook.com", 443),
    ("157.240.1.174", "www.instagram.com", 443),
    ("104.244.42.65", "twitter.com", 443),
    ("52.94.236.248", "www.amazon.com", 443),
    ("23.52.167.61", "www.netflix.com", 443),
    ("140.82.114.4", "github.com", 443),
    ("104.16.85.20", "discord.com", 443),
    ("35.186.224.25", "zoom.us", 443),
    ("35.186.227.140", "web.telegram.org", 443),
    ("99.86.0.100", "www.tiktok.com", 443),
    ("35.186.224.47", "open.spotify.com", 443),
    ("192.0.78.24", "www.cloudflare.com", 443),
    ("13.107.42.14", "www.microsoft.com", 443),
    ("17.253.144.10", "www.apple.com", 443),
]

HTTP_CONNECTIONS = [
    ("93.184.216.34", "example.com", 80),
    ("185.199.108.153", "httpbin.org", 80),
]

DNS_QUERIES = [
    "www.google.com",
    "www.youtube.com",
    "www.facebook.com",
    "api.twitter.com",
]


class _PcapWriter:
    def __init__(self, path: str, rng: random.Random):
        self._file = open(path, "wb")
        self._rng = rng
        self._timestamp = 1_700_000_000
        # Little-endian magic, version 2.4, snaplen 65535, Ethernet link type.
        self._file.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def write_packet(self, data: bytes) -> None:
        ts_usec = self._rng.randint(0, 999_999)
        self._file.write(struct.pack("<IIII", self._timestamp, ts_usec, len(data), len(data)))
        self._file.write(data)
        self._timestamp += 1

    def close(self) -> None:
        self._file.close()


def _ethernet(src_mac: str, dst_mac: str, ethertype: int = 0x0800) -> bytes:
    return (
        bytes.fromhex(dst_mac.replace(":", ""))
        + bytes.fromhex(src_mac.replace(":", ""))
        + struct.pack(">H", ethertype)
    )


def _ipv4(src_ip: str, dst_ip: str, protocol: int, payload_len: int, rng: random.Random) -> bytes:
    header = struct.pack(
        ">BBHHHBBH",
        0x45,  # version 4, IHL 5
        0,  # ToS
        20 + payload_len,  # total length
        rng.randint(1, 65535),  # identification
        0x4000,  # flags: don't fragment
        64,  # TTL
        protocol,
        0,  # checksum (unused by the parser)
    )
    header += bytes(int(o) for o in src_ip.split("."))
    header += bytes(int(o) for o in dst_ip.split("."))
    return header


def _tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int) -> bytes:
    return struct.pack(
        ">HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        5 << 4,  # data offset: 5 words = 20 bytes
        flags,
        65535,  # window
        0,  # checksum
        0,  # urgent pointer
    )


def _udp(src_port: int, dst_port: int, payload_len: int) -> bytes:
    return struct.pack(">HHHH", src_port, dst_port, 8 + payload_len, 0)


def _tls_client_hello(sni: str, rng: random.Random) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list

    supported_versions = struct.pack(">HHB", 0x002B, 3, 2) + struct.pack(">H", 0x0304)
    extensions = sni_ext + supported_versions
    extensions_data = struct.pack(">H", len(extensions)) + extensions

    client_version = struct.pack(">H", 0x0303)
    random_bytes = bytes(rng.randint(0, 255) for _ in range(32))
    session_id = struct.pack("B", 0)
    cipher_suites = struct.pack(">H", 4) + struct.pack(">HH", 0x1301, 0x1302)
    compression = struct.pack("BB", 1, 0)

    body = (
        client_version
        + random_bytes
        + session_id
        + cipher_suites
        + compression
        + extensions_data
    )

    handshake = struct.pack("B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack("B", 0x16) + struct.pack(">H", 0x0301)
    record += struct.pack(">H", len(handshake)) + handshake
    return record


def _http_request(host: str, path: str = "/") -> bytes:
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: dpi-engine-test/1.0\r\n"
        f"Accept: */*\r\n\r\n"
    ).encode()


def _dns_query(domain: str, rng: random.Random) -> bytes:
    txid = struct.pack(">H", rng.randint(1, 65535))
    flags = struct.pack(">H", 0x0100)
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode()
    question += struct.pack("B", 0)
    question += struct.pack(">HH", 1, 1)  # type A, class IN
    return txid + flags + counts + question


def generate(path: str = "test_dpi.pcap", seed: int = 1234) -> str:
    """Write a synthetic capture to ``path`` and return the path."""
    rng = random.Random(seed)
    writer = _PcapWriter(path, rng)
    seq_base = 1000

    for dst_ip, sni, dst_port in TLS_CONNECTIONS:
        src_port = rng.randint(49152, 65535)

        eth_out = _ethernet(USER_MAC, GATEWAY_MAC)
        eth_in = _ethernet(GATEWAY_MAC, USER_MAC)

        syn = _tcp(src_port, dst_port, seq_base, 0, 0x02)
        writer.write_packet(eth_out + _ipv4(USER_IP, dst_ip, 6, len(syn), rng) + syn)

        syn_ack = _tcp(dst_port, src_port, seq_base + 1000, seq_base + 1, 0x12)
        writer.write_packet(eth_in + _ipv4(dst_ip, USER_IP, 6, len(syn_ack), rng) + syn_ack)

        ack = _tcp(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x10)
        writer.write_packet(eth_out + _ipv4(USER_IP, dst_ip, 6, len(ack), rng) + ack)

        tls = _tls_client_hello(sni, rng)
        psh = _tcp(src_port, dst_port, seq_base + 1, seq_base + 1001, 0x18)
        writer.write_packet(
            eth_out + _ipv4(USER_IP, dst_ip, 6, len(psh) + len(tls), rng) + psh + tls
        )
        seq_base += 10000

    for dst_ip, host, dst_port in HTTP_CONNECTIONS:
        src_port = rng.randint(49152, 65535)
        eth_out = _ethernet(USER_MAC, GATEWAY_MAC)

        syn = _tcp(src_port, dst_port, seq_base, 0, 0x02)
        writer.write_packet(eth_out + _ipv4(USER_IP, dst_ip, 6, len(syn), rng) + syn)

        http = _http_request(host)
        psh = _tcp(src_port, dst_port, seq_base + 1, 1, 0x18)
        writer.write_packet(
            eth_out + _ipv4(USER_IP, dst_ip, 6, len(psh) + len(http), rng) + psh + http
        )
        seq_base += 10000

    for domain in DNS_QUERIES:
        src_port = rng.randint(49152, 65535)
        dns = _dns_query(domain, rng)
        eth_out = _ethernet(USER_MAC, GATEWAY_MAC)
        udp = _udp(src_port, 53, len(dns))
        writer.write_packet(
            eth_out + _ipv4(USER_IP, DNS_SERVER, 17, len(udp) + len(dns), rng) + udp + dns
        )

    for _ in range(5):
        src_port = rng.randint(49152, 65535)
        eth = _ethernet("00:11:22:33:44:56", GATEWAY_MAC)
        syn = _tcp(src_port, 443, seq_base, 0, 0x02)
        writer.write_packet(
            eth + _ipv4(BLOCKED_SOURCE_IP, "172.217.0.100", 6, len(syn), rng) + syn
        )
        seq_base += 1000

    writer.close()
    return path
