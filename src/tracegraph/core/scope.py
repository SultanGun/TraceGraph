"""Investigation target scope validation and SSRF network safety controls."""

import ipaddress
import re

from tracegraph.core.enums import EntityType
from tracegraph.core.exceptions import ScopeError

# Reserved non-public IPv4 networks according to IANA / RFC 6890
_DISALLOWED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # Private-Use (RFC 1918)
    ipaddress.ip_network("100.64.0.0/10"),  # Shared Address Space (RFC 6598)
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link Local
    ipaddress.ip_network("172.16.0.0/12"),  # Private-Use (RFC 1918)
    ipaddress.ip_network("192.0.0.0/24"),  # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),  # Documentation (TEST-NET-1)
    ipaddress.ip_network("192.88.99.0/24"),  # 6to4 Relay Anycast
    ipaddress.ip_network("192.168.0.0/16"),  # Private-Use (RFC 1918)
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # Documentation (TEST-NET-2)
    ipaddress.ip_network("203.0.113.0/24"),  # Documentation (TEST-NET-3)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved for Future Use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited Broadcast
]


def is_public_ip(ip_str: str) -> bool:
    """Check if an IP address is a globally routable public address.

    Rejects private, loopback, link-local, multicast, documentation, and reserved ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False

    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if isinstance(ip, ipaddress.IPv4Address):
        for net in _DISALLOWED_IPV4_NETWORKS:
            if ip in net:
                return False

    return True


def assert_public_ip(ip_str: str) -> None:
    """Raise ScopeError if IP address is not a globally routable public address."""
    if not is_public_ip(ip_str):
        raise ScopeError(
            f"IP address '{ip_str}' is a private, loopback, or reserved address "
            "and cannot be collected externally"
        )


class ScopeValidator:
    """Enforces target boundary constraints defined for an investigation."""

    def __init__(self, scope_str: str | None = None) -> None:
        self.scope_str = (scope_str or "").strip()
        self.domains: set[str] = set()
        self.domain_patterns: list[re.Pattern] = []
        self.ip_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.ip_addresses: set[str] = set()
        self.is_unrestricted = not self.scope_str or self.scope_str == "*"

        if not self.is_unrestricted:
            self._parse_scope(self.scope_str)

    def _parse_scope(self, scope_str: str) -> None:
        # Split on commas, spaces, or semicolons
        tokens = [t.strip() for t in re.split(r"[,;\s]+", scope_str) if t.strip()]
        for token in tokens:
            # Check if token is CIDR
            if "/" in token:
                try:
                    net = ipaddress.ip_network(token, strict=False)
                    self.ip_networks.append(net)
                    continue
                except ValueError:
                    pass

            # Check if token is IP
            try:
                ip = ipaddress.ip_address(token)
                self.ip_addresses.add(str(ip))
                continue
            except ValueError:
                pass

            # Otherwise treat as domain / wildcard domain
            clean_domain = token.lower().rstrip(".")
            if clean_domain.startswith("*."):
                base = clean_domain[2:]
                pattern = re.compile(rf"^(?:[a-zA-Z0-9_-]+\.)*{re.escape(base)}$", re.IGNORECASE)
                self.domain_patterns.append(pattern)
                self.domains.add(base)
            else:
                self.domains.add(clean_domain)
                # An exact domain scope also covers its subdomains
                pattern = re.compile(
                    rf"^(?:[a-zA-Z0-9_-]+\.)*{re.escape(clean_domain)}$", re.IGNORECASE
                )
                self.domain_patterns.append(pattern)

    def is_in_scope(self, target: str, entity_type: EntityType | str) -> bool:
        """Verify whether a target falls within the configured scope."""
        if self.is_unrestricted:
            return True

        val = target.strip()
        e_type = EntityType(entity_type) if isinstance(entity_type, str) else entity_type

        if e_type in (EntityType.IPV4, EntityType.IPV6):
            try:
                ip = ipaddress.ip_address(val)
                if str(ip) in self.ip_addresses:
                    return True
                for net in self.ip_networks:
                    if ip in net:
                        return True
            except ValueError:
                return False
            return False

        if e_type in (EntityType.DOMAIN, EntityType.NAMESERVER):
            domain_val = val.lower().rstrip(".")
            if domain_val in self.domains:
                return True
            for pattern in self.domain_patterns:
                if pattern.match(domain_val):
                    return True
            return False

        if e_type == EntityType.CIDR:
            try:
                cand_net = ipaddress.ip_network(val, strict=False)
                for net in self.ip_networks:
                    if cand_net.subnet_of(net) or cand_net == net:
                        return True
            except ValueError:
                return False
            return False

        # Fallback: exact match
        return val in self.domains or val in self.ip_addresses

    def assert_in_scope(self, target: str, entity_type: EntityType | str) -> None:
        """Raise ScopeError if target is not in declared scope."""
        if not self.is_in_scope(target, entity_type):
            e_val = entity_type.value if isinstance(entity_type, EntityType) else str(entity_type)
            raise ScopeError(
                f"Target '{target}' ({e_val}) is outside declared investigation "
                f"scope: '{self.scope_str}'"
            )
