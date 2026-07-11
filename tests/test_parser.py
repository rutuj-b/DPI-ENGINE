import struct
import unittest

from dpi_engine import parser
from dpi_engine.tuples import PROTO_TCP, PROTO_UDP


def build_frame(protocol: int, payload: bytes, dst_port: int = 443) -> bytes:
    eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("001122334455")
    eth += struct.pack(">H", 0x0800)

    transport_len = (20 if protocol == PROTO_TCP else 8) + len(payload)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + transport_len, 1, 0x4000, 64, protocol, 0)
    ip += bytes([192, 168, 1, 100]) + bytes([93, 184, 216, 34])

    if protocol == PROTO_TCP:
        transport = struct.pack(
            ">HHIIBBHHH", 51000, dst_port, 1, 0, 5 << 4, 0x18, 65535, 0, 0
        )
    else:
        transport = struct.pack(">HHHH", 51000, dst_port, 8 + len(payload), 0)

    return eth + ip + transport + payload


class ParserTests(unittest.TestCase):
    def test_parse_tcp(self):
        frame = build_frame(PROTO_TCP, b"hello", dst_port=443)
        parsed = parser.parse(frame)
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_ip)
        self.assertTrue(parsed.has_tcp)
        self.assertFalse(parsed.has_udp)
        self.assertEqual(parsed.src_ip, "192.168.1.100")
        self.assertEqual(parsed.dst_ip, "93.184.216.34")
        self.assertEqual(parsed.dst_port, 443)
        self.assertEqual(parsed.protocol, PROTO_TCP)
        self.assertEqual(parsed.payload_length, 5)
        payload = frame[parsed.payload_offset : parsed.payload_offset + parsed.payload_length]
        self.assertEqual(payload, b"hello")

    def test_parse_udp(self):
        parsed = parser.parse(build_frame(PROTO_UDP, b"dnsdata", dst_port=53))
        self.assertIsNotNone(parsed)
        self.assertTrue(parsed.has_udp)
        self.assertEqual(parsed.dst_port, 53)
        self.assertEqual(parsed.payload_length, 7)

    def test_five_tuple(self):
        parsed = parser.parse(build_frame(PROTO_TCP, b"x"))
        tup = parsed.five_tuple()
        self.assertEqual(tup.src_ip, "192.168.1.100")
        self.assertEqual(tup.protocol, PROTO_TCP)

    def test_short_frame_returns_none(self):
        self.assertIsNone(parser.parse(b"\x00\x01\x02"))

    def test_non_ipv4_has_no_ip(self):
        eth = bytes.fromhex("aabbccddeeff001122334455") + struct.pack(">H", 0x0806)
        parsed = parser.parse(eth + b"\x00" * 20)
        self.assertIsNotNone(parsed)
        self.assertFalse(parsed.has_ip)

    def test_tcp_flags_to_string(self):
        self.assertEqual(parser.tcp_flags_to_string(0x12), "SYN ACK")
        self.assertEqual(parser.tcp_flags_to_string(0), "none")


if __name__ == "__main__":
    unittest.main()
