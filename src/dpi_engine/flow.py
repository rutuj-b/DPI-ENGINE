"""Per-flow state and the classification logic that fills it in."""

from __future__ import annotations

from dataclasses import dataclass

from .classification import AppType, sni_to_app_type
from .inspection import extract_http_host, extract_sni
from .tuples import FiveTuple

HTTP_PORT = 80
HTTPS_PORT = 443
DNS_PORT = 53


@dataclass
class Flow:
    """Accumulated state for a single connection."""

    tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""
    packets: int = 0
    byte_count: int = 0
    blocked: bool = False
    classified: bool = False


def classify(flow: Flow, payload: bytes) -> None:
    """Classify ``flow`` in place using this packet's payload.

    A flow is classified the moment a hostname is recovered (via TLS SNI, an
    HTTP Host header, or a DNS query); until then a port-based guess is applied
    without locking the flow, so a later ClientHello can still refine it.
    """
    if flow.classified:
        return

    dst_port = flow.tuple.dst_port
    src_port = flow.tuple.src_port

    if dst_port == HTTPS_PORT and len(payload) > 5:
        sni = extract_sni(payload)
        if sni:
            flow.sni = sni
            flow.app_type = sni_to_app_type(sni)
            flow.classified = True
            return

    if dst_port == HTTP_PORT and len(payload) > 10:
        host = extract_http_host(payload)
        if host:
            flow.sni = host
            flow.app_type = sni_to_app_type(host)
            flow.classified = True
            return

    if dst_port == DNS_PORT or src_port == DNS_PORT:
        flow.app_type = AppType.DNS
        flow.classified = True
        return

    # Port-based fallback — a guess we may still upgrade on a later packet.
    if dst_port == HTTPS_PORT:
        flow.app_type = AppType.HTTPS
    elif dst_port == HTTP_PORT:
        flow.app_type = AppType.HTTP
