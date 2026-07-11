"""The five-tuple that uniquely identifies a network flow."""

from __future__ import annotations

import zlib
from dataclasses import dataclass

# Protocol numbers used throughout the engine.
PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17


@dataclass(frozen=True)
class FiveTuple:
    """A connection/flow identifier.

    Two packets share a flow when they carry the same five-tuple. The tuple is
    frozen so it can be used directly as a dictionary key in flow tables.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int

    def reverse(self) -> "FiveTuple":
        """Return the tuple for traffic flowing the opposite direction."""
        return FiveTuple(
            self.dst_ip, self.src_ip, self.dst_port, self.src_port, self.protocol
        )

    def __str__(self) -> str:
        proto = {PROTO_TCP: "TCP", PROTO_UDP: "UDP"}.get(self.protocol, "?")
        return (
            f"{self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} ({proto})"
        )


def tuple_hash(tuple_: FiveTuple) -> int:
    """A stable hash used for consistent load balancing.

    The same flow always hashes to the same value, so every packet in a
    connection is routed to the same worker and its state stays coherent.
    """
    key = (
        f"{tuple_.src_ip}|{tuple_.dst_ip}|"
        f"{tuple_.src_port}|{tuple_.dst_port}|{tuple_.protocol}"
    )
    return zlib.crc32(key.encode("ascii"))
