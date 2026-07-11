"""Parsing of Ethernet / IPv4 / TCP / UDP protocol headers."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

from .tuples import PROTO_TCP, PROTO_UDP, FiveTuple

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806

# TCP flag bits.
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20


@dataclass
class ParsedPacket:
    """The protocol fields extracted from a raw Ethernet frame."""

    src_mac: str = ""
    dst_mac: str = ""
    ether_type: int = 0

    has_ip: bool = False
    ip_version: int = 0
    src_ip: str = ""
    dst_ip: str = ""
    protocol: int = 0
    ttl: int = 0

    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    seq_number: int = 0
    ack_number: int = 0

    payload_offset: int = 0
    payload_length: int = 0

    def five_tuple(self) -> FiveTuple:
        return FiveTuple(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
        )


def _mac_to_string(data: bytes) -> str:
    return ":".join(f"{b:02x}" for b in data)


def tcp_flags_to_string(flags: int) -> str:
    """Render TCP flag bits as a readable string like ``"SYN ACK"``."""
    names = [
        (SYN, "SYN"),
        (ACK, "ACK"),
        (FIN, "FIN"),
        (RST, "RST"),
        (PSH, "PSH"),
        (URG, "URG"),
    ]
    active = [name for bit, name in names if flags & bit]
    return " ".join(active) if active else "none"


def protocol_to_string(protocol: int) -> str:
    return {1: "ICMP", PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(
        protocol, f"Unknown({protocol})"
    )


def parse(data: bytes) -> ParsedPacket | None:
    """Parse a raw Ethernet frame.

    Returns a :class:`ParsedPacket`, or ``None`` if the frame is too short or
    malformed to interpret. Non-IPv4 frames parse successfully but carry no
    IP/transport fields.
    """
    length = len(data)
    if length < ETH_HEADER_LEN:
        return None

    parsed = ParsedPacket()
    parsed.dst_mac = _mac_to_string(data[0:6])
    parsed.src_mac = _mac_to_string(data[6:12])
    parsed.ether_type = struct.unpack(">H", data[12:14])[0]

    offset = ETH_HEADER_LEN
    if parsed.ether_type == ETHERTYPE_IPV4:
        offset = _parse_ipv4(data, offset, parsed)
        if offset is None:
            return None
        if parsed.protocol == PROTO_TCP:
            offset = _parse_tcp(data, offset, parsed)
        elif parsed.protocol == PROTO_UDP:
            offset = _parse_udp(data, offset, parsed)
        if offset is None:
            return None

    if offset < length:
        parsed.payload_offset = offset
        parsed.payload_length = length - offset
    else:
        parsed.payload_offset = length
        parsed.payload_length = 0

    return parsed


def _parse_ipv4(data: bytes, offset: int, parsed: ParsedPacket) -> int | None:
    if len(data) < offset + 20:
        return None

    version_ihl = data[offset]
    parsed.ip_version = (version_ihl >> 4) & 0x0F
    ihl = version_ihl & 0x0F
    if parsed.ip_version != 4:
        return None

    header_len = ihl * 4
    if header_len < 20 or len(data) < offset + header_len:
        return None

    parsed.ttl = data[offset + 8]
    parsed.protocol = data[offset + 9]
    parsed.src_ip = socket.inet_ntoa(data[offset + 12 : offset + 16])
    parsed.dst_ip = socket.inet_ntoa(data[offset + 16 : offset + 20])
    parsed.has_ip = True
    return offset + header_len


def _parse_tcp(data: bytes, offset: int, parsed: ParsedPacket) -> int | None:
    if len(data) < offset + 20:
        return None

    parsed.src_port = struct.unpack(">H", data[offset : offset + 2])[0]
    parsed.dst_port = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
    parsed.seq_number = struct.unpack(">I", data[offset + 4 : offset + 8])[0]
    parsed.ack_number = struct.unpack(">I", data[offset + 8 : offset + 12])[0]

    data_offset = (data[offset + 12] >> 4) & 0x0F
    header_len = data_offset * 4
    parsed.tcp_flags = data[offset + 13]

    if header_len < 20 or len(data) < offset + header_len:
        return None

    parsed.has_tcp = True
    return offset + header_len


def _parse_udp(data: bytes, offset: int, parsed: ParsedPacket) -> int | None:
    if len(data) < offset + 8:
        return None

    parsed.src_port = struct.unpack(">H", data[offset : offset + 2])[0]
    parsed.dst_port = struct.unpack(">H", data[offset + 2 : offset + 4])[0]
    parsed.has_udp = True
    return offset + 8
