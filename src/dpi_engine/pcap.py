"""Reading and writing classic (libpcap) ``.pcap`` capture files."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

GLOBAL_HEADER_LEN = 24
PACKET_HEADER_LEN = 16

# Magic number as it appears on disk for a little-/big-endian capture.
_MAGIC_LITTLE = b"\xd4\xc3\xb2\xa1"
_MAGIC_BIG = b"\xa1\xb2\xc3\xd4"

LINKTYPE_ETHERNET = 1


class PcapError(Exception):
    """Raised when a file is not a valid PCAP capture."""


@dataclass
class GlobalHeader:
    """The 24-byte header at the start of every capture file."""

    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int
    endian: str  # struct byte-order character, "<" or ">"


@dataclass
class Packet:
    """A single captured packet: metadata plus raw bytes."""

    ts_sec: int
    ts_usec: int
    orig_len: int
    data: bytes


class PcapReader:
    """Stream packets from a PCAP file.

    Usable as a context manager and as an iterator::

        with PcapReader("capture.pcap") as reader:
            for packet in reader:
                ...
    """

    def __init__(self, path: str):
        self.path = path
        self._file: BinaryIO | None = None
        self.header: GlobalHeader | None = None
        self._open()

    def _open(self) -> None:
        self._file = open(self.path, "rb")
        raw = self._file.read(GLOBAL_HEADER_LEN)
        if len(raw) < GLOBAL_HEADER_LEN:
            self.close()
            raise PcapError("File is too short to contain a PCAP header")

        magic = raw[:4]
        if magic == _MAGIC_LITTLE:
            endian = "<"
        elif magic == _MAGIC_BIG:
            endian = ">"
        else:
            self.close()
            raise PcapError(f"Invalid PCAP magic number: {magic.hex()}")

        fields = struct.unpack(endian + "IHHiIII", raw)
        self.header = GlobalHeader(*fields, endian=endian)

    def read_packet(self) -> Packet | None:
        """Return the next packet, or ``None`` at end of file."""
        assert self._file is not None and self.header is not None
        raw = self._file.read(PACKET_HEADER_LEN)
        if len(raw) < PACKET_HEADER_LEN:
            return None

        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            self.header.endian + "IIII", raw
        )
        if incl_len > 65535 or (self.header.snaplen and incl_len > self.header.snaplen):
            raise PcapError(f"Invalid packet length: {incl_len}")

        data = self._file.read(incl_len)
        if len(data) < incl_len:
            return None  # Truncated final record.

        return Packet(ts_sec=ts_sec, ts_usec=ts_usec, orig_len=orig_len, data=data)

    def __iter__(self) -> Iterator[Packet]:
        while True:
            packet = self.read_packet()
            if packet is None:
                return
            yield packet

    def close(self) -> None:
        if self._file is not None:
            self._file.close()
            self._file = None

    def __enter__(self) -> "PcapReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


class PcapWriter:
    """Write packets to a PCAP file, preserving the source capture's format."""

    def __init__(self, path: str, header: GlobalHeader):
        self.path = path
        self.header = header
        self._file: BinaryIO = open(path, "wb")
        self._write_global_header()

    def _write_global_header(self) -> None:
        endian = self.header.endian
        self._file.write(
            struct.pack(
                endian + "IHHiIII",
                self.header.magic_number,
                self.header.version_major,
                self.header.version_minor,
                self.header.thiszone,
                self.header.sigfigs,
                self.header.snaplen,
                self.header.network,
            )
        )

    def write_packet(self, packet: Packet) -> None:
        endian = self.header.endian
        self._file.write(
            struct.pack(
                endian + "IIII",
                packet.ts_sec,
                packet.ts_usec,
                len(packet.data),
                len(packet.data),
            )
        )
        self._file.write(packet.data)

    def close(self) -> None:
        if self._file is not None:
            self._file.close()

    def __enter__(self) -> "PcapWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
