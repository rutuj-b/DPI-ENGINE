"""Application-layer inspection: TLS SNI, HTTP Host and DNS query extraction.

Even though HTTPS traffic is encrypted, the destination hostname is sent in the
clear inside the TLS ClientHello (the Server Name Indication extension). These
helpers pull that hostname — and its HTTP and DNS equivalents — back out of the
raw payload bytes.
"""

from __future__ import annotations

CONTENT_TYPE_HANDSHAKE = 0x16
HANDSHAKE_CLIENT_HELLO = 0x01
EXTENSION_SNI = 0x0000
SNI_TYPE_HOSTNAME = 0x00

_HTTP_METHODS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI")


def _u16(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def is_tls_client_hello(payload: bytes) -> bool:
    """Return whether ``payload`` begins with a TLS ClientHello record."""
    if len(payload) < 9:
        return False
    if payload[0] != CONTENT_TYPE_HANDSHAKE:
        return False
    # Record-layer version: accept SSL 3.0 (0x0300) through TLS 1.3 (0x0304).
    version = _u16(payload, 1)
    if version < 0x0300 or version > 0x0304:
        return False
    record_length = _u16(payload, 3)
    if record_length > len(payload) - 5:
        return False
    return payload[5] == HANDSHAKE_CLIENT_HELLO


def extract_sni(payload: bytes) -> str | None:
    """Extract the SNI hostname from a TLS ClientHello, or ``None``."""
    if not is_tls_client_hello(payload):
        return None

    length = len(payload)
    # Skip the record header (5 bytes) and handshake header (4 bytes),
    # then the client version (2) and random (32).
    offset = 5 + 4 + 2 + 32

    # Session ID.
    if offset >= length:
        return None
    offset += 1 + payload[offset]

    # Cipher suites.
    if offset + 2 > length:
        return None
    offset += 2 + _u16(payload, offset)

    # Compression methods.
    if offset >= length:
        return None
    offset += 1 + payload[offset]

    # Extensions block.
    if offset + 2 > length:
        return None
    extensions_length = _u16(payload, offset)
    offset += 2
    extensions_end = min(offset + extensions_length, length)

    while offset + 4 <= extensions_end:
        ext_type = _u16(payload, offset)
        ext_length = _u16(payload, offset + 2)
        offset += 4
        if offset + ext_length > extensions_end:
            break

        if ext_type == EXTENSION_SNI:
            if ext_length < 5:
                break
            sni_list_length = _u16(payload, offset)
            if sni_list_length < 3:
                break
            sni_type = payload[offset + 2]
            sni_length = _u16(payload, offset + 3)
            if sni_type != SNI_TYPE_HOSTNAME:
                break
            if sni_length > ext_length - 5:
                break
            host = payload[offset + 5 : offset + 5 + sni_length]
            return host.decode("ascii", errors="replace")

        offset += ext_length

    return None


def is_http_request(payload: bytes) -> bool:
    """Return whether ``payload`` starts with a known HTTP request method."""
    if len(payload) < 4:
        return False
    return payload[:4] in _HTTP_METHODS


def extract_http_host(payload: bytes) -> str | None:
    """Extract the value of the HTTP ``Host`` header, or ``None``.

    Any trailing ``:port`` is stripped from the returned hostname.
    """
    if not is_http_request(payload):
        return None

    length = len(payload)
    i = 0
    while i + 6 < length:
        if (
            payload[i] in (0x48, 0x68)  # 'H' / 'h'
            and payload[i + 1] in (0x6F, 0x4F)  # 'o' / 'O'
            and payload[i + 2] in (0x73, 0x53)  # 's' / 'S'
            and payload[i + 3] in (0x74, 0x54)  # 't' / 'T'
            and payload[i + 4] == 0x3A  # ':'
        ):
            start = i + 5
            while start < length and payload[start] in (0x20, 0x09):  # space / tab
                start += 1
            end = start
            while end < length and payload[end] not in (0x0D, 0x0A):  # CR / LF
                end += 1
            if end > start:
                host = payload[start:end].decode("ascii", errors="replace").strip()
                return host.split(":", 1)[0]
        i += 1

    return None


def is_dns_query(payload: bytes) -> bool:
    """Return whether ``payload`` is a DNS query (not a response)."""
    if len(payload) < 12:
        return False
    if payload[2] & 0x80:  # QR bit set => response
        return False
    qdcount = _u16(payload, 4)
    return qdcount > 0


def extract_dns_query(payload: bytes) -> str | None:
    """Extract the queried domain name from a DNS request, or ``None``."""
    if not is_dns_query(payload):
        return None

    length = len(payload)
    offset = 12
    labels: list[str] = []

    while offset < length:
        label_length = payload[offset]
        if label_length == 0:
            break
        if label_length > 63:  # Compression pointer or invalid.
            break
        offset += 1
        if offset + label_length > length:
            break
        labels.append(payload[offset : offset + label_length].decode("ascii", "replace"))
        offset += label_length

    domain = ".".join(labels)
    return domain or None
