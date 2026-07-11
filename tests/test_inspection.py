import struct
import unittest

from dpi_engine import inspection


def build_client_hello(sni: str) -> bytes:
    sni_bytes = sni.encode("ascii")
    sni_entry = struct.pack(">BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack(">HH", 0x0000, len(sni_list)) + sni_list
    extensions = sni_ext
    extensions_data = struct.pack(">H", len(extensions)) + extensions

    body = (
        struct.pack(">H", 0x0303)
        + bytes(32)  # random
        + struct.pack("B", 0)  # session id length
        + struct.pack(">H", 2) + struct.pack(">H", 0x1301)  # cipher suites
        + struct.pack("BB", 1, 0)  # compression
        + extensions_data
    )
    handshake = struct.pack("B", 0x01) + struct.pack(">I", len(body))[1:] + body
    record = struct.pack("B", 0x16) + struct.pack(">H", 0x0301)
    record += struct.pack(">H", len(handshake)) + handshake
    return record


class SNITests(unittest.TestCase):
    def test_extract_sni(self):
        payload = build_client_hello("www.example.com")
        self.assertTrue(inspection.is_tls_client_hello(payload))
        self.assertEqual(inspection.extract_sni(payload), "www.example.com")

    def test_non_tls_returns_none(self):
        self.assertIsNone(inspection.extract_sni(b"not a tls record at all"))

    def test_truncated_payload(self):
        payload = build_client_hello("host.test")[:10]
        self.assertIsNone(inspection.extract_sni(payload))


class HTTPTests(unittest.TestCase):
    def test_extract_host(self):
        payload = b"GET / HTTP/1.1\r\nHost: example.org\r\n\r\n"
        self.assertTrue(inspection.is_http_request(payload))
        self.assertEqual(inspection.extract_http_host(payload), "example.org")

    def test_host_with_port_is_stripped(self):
        payload = b"POST /x HTTP/1.1\r\nHost: api.test:8080\r\n\r\n"
        self.assertEqual(inspection.extract_http_host(payload), "api.test")

    def test_case_insensitive_header(self):
        payload = b"GET / HTTP/1.1\r\nhOsT:   spaced.example  \r\n\r\n"
        self.assertEqual(inspection.extract_http_host(payload), "spaced.example")

    def test_non_http_returns_none(self):
        self.assertIsNone(inspection.extract_http_host(b"\x16\x03\x01random"))


class DNSTests(unittest.TestCase):
    def _query(self, domain: str) -> bytes:
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        q = b""
        for label in domain.split("."):
            q += struct.pack("B", len(label)) + label.encode()
        q += b"\x00" + struct.pack(">HH", 1, 1)
        return header + q

    def test_extract_query(self):
        payload = self._query("www.google.com")
        self.assertTrue(inspection.is_dns_query(payload))
        self.assertEqual(inspection.extract_dns_query(payload), "www.google.com")

    def test_response_is_not_query(self):
        header = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0)
        self.assertFalse(inspection.is_dns_query(header + b"\x00"))


if __name__ == "__main__":
    unittest.main()
