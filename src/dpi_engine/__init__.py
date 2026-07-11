"""DPI Engine — a deep packet inspection and traffic-filtering toolkit.

The package reads PCAP captures, parses network protocol headers, inspects
application-layer payloads (TLS SNI, HTTP Host, DNS queries), classifies flows
by application, and filters traffic according to blocking rules.
"""

from .classification import AppType, app_type_to_string, sni_to_app_type
from .engine import DPIEngine, EngineConfig
from .rules import RuleManager
from .tuples import FiveTuple

__version__ = "1.0.0"

__all__ = [
    "AppType",
    "app_type_to_string",
    "sni_to_app_type",
    "DPIEngine",
    "EngineConfig",
    "RuleManager",
    "FiveTuple",
    "__version__",
]
