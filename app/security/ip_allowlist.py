"""IP allowlist enforcement (Phase 3, T3.8).

Per API key (``api_keys.ip_allowlist``) and a global fallback list
loaded from settings (``IP_ALLOWLIST`` env var, comma-separated CIDRs).
Both must contain the caller IP for the request to proceed.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


class IpNotAllowedError(Exception):
    def __init__(self, ip: str) -> None:
        super().__init__(ip)
        self.ip = ip


def _matches(ip: str, cidrs: Iterable[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            net = ipaddress.ip_network(c.strip(), strict=False)
        except ValueError:
            continue
        if addr in net:
            return True
    return False


def is_allowed(
    ip: str,
    *,
    key_allowlist: Iterable[str] | None = None,
    global_allowlist: Iterable[str] | None = None,
) -> bool:
    """Return True if `ip` passes both per-key and global allowlists.

    Empty / None list = "no restriction at this layer".
    """
    return not (
        (global_allowlist and not _matches(ip, global_allowlist))
        or (key_allowlist and not _matches(ip, key_allowlist))
    )


def enforce(
    ip: str,
    *,
    key_allowlist: Iterable[str] | None = None,
    global_allowlist: Iterable[str] | None = None,
) -> None:
    if not is_allowed(ip, key_allowlist=key_allowlist, global_allowlist=global_allowlist):
        raise IpNotAllowedError(ip)
