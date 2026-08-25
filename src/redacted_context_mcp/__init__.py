"""Redacted local context access for coding agents."""

from .discovery import (
    DiscoveryClient,
    build_discovery_update,
    discover_documents,
    merge_discovery_toml,
    write_discovery_update,
)
from .models import DiscoveryDocument, DiscoveryResult, DiscoveryUpdate

__version__ = "0.6.0"

__all__ = [
    "DiscoveryDocument",
    "DiscoveryClient",
    "DiscoveryResult",
    "DiscoveryUpdate",
    "build_discovery_update",
    "discover_documents",
    "merge_discovery_toml",
    "write_discovery_update",
]
