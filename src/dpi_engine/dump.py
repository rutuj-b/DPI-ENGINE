"""Human-readable per-packet dump of a capture (an inspection aid)."""

from __future__ import annotations

import datetime as _dt

from .parser import (
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    ETHERTYPE_IPV6,
    parse,
    protocol_to_string,
    tcp_flags_to_string,
)
from .pcap import PcapReader

_ETHERTYPE_NAMES = {
    ETHERTYPE_IPV4: "IPv4",
    ETHERTYPE_IPV6: "IPv6",
    ETHERTYPE_ARP: "ARP",
}


def dump_file(path: str, max_packets: int | None = None) -> int:
    """Print a summary of each packet in ``path``; return the number read."""
    count = 0
    with PcapReader(path) as reader:
        for packet in reader:
            count += 1
            parsed = parse(packet.data)
            if parsed is None:
                print(f"\nPacket #{count}: unparseable ({len(packet.data)} bytes)")
            else:
                _print_summary(parsed, packet, count)
            if max_packets is not None and count >= max_packets:
                print(f"\n(stopped after {max_packets} packets)")
                break

    print("\n" + "=" * 40)
    print(f"Total packets read: {count}")
    print("=" * 40)
    return count


def _print_summary(parsed, packet, number: int) -> None:
    ts = _dt.datetime.fromtimestamp(packet.ts_sec)
    print(f"\n========== Packet #{number} ==========")
    print(f"Time: {ts:%Y-%m-%d %H:%M:%S}.{packet.ts_usec:06d}")

    ether_name = _ETHERTYPE_NAMES.get(parsed.ether_type)
    suffix = f" ({ether_name})" if ether_name else ""
    print("\n[Ethernet]")
    print(f"  Source MAC:      {parsed.src_mac}")
    print(f"  Destination MAC: {parsed.dst_mac}")
    print(f"  EtherType:       0x{parsed.ether_type:04x}{suffix}")

    if parsed.has_ip:
        print(f"\n[IPv{parsed.ip_version}]")
        print(f"  Source IP:      {parsed.src_ip}")
        print(f"  Destination IP: {parsed.dst_ip}")
        print(f"  Protocol:       {protocol_to_string(parsed.protocol)}")
        print(f"  TTL:            {parsed.ttl}")

    if parsed.has_tcp:
        print("\n[TCP]")
        print(f"  Source Port:      {parsed.src_port}")
        print(f"  Destination Port: {parsed.dst_port}")
        print(f"  Sequence Number:  {parsed.seq_number}")
        print(f"  Ack Number:       {parsed.ack_number}")
        print(f"  Flags:            {tcp_flags_to_string(parsed.tcp_flags)}")

    if parsed.has_udp:
        print("\n[UDP]")
        print(f"  Source Port:      {parsed.src_port}")
        print(f"  Destination Port: {parsed.dst_port}")

    if parsed.payload_length > 0:
        payload = packet.data[
            parsed.payload_offset : parsed.payload_offset + parsed.payload_length
        ]
        preview = " ".join(f"{b:02x}" for b in payload[:32])
        ellipsis = " ..." if parsed.payload_length > 32 else ""
        print("\n[Payload]")
        print(f"  Length: {parsed.payload_length} bytes")
        print(f"  Preview: {preview}{ellipsis}")
