"""Normalization and canonicalization routines for OSINT infrastructure entities."""

import ipaddress
import re
from urllib.parse import urlparse, urlunparse

from tracegraph.core.enums import EntityType
from tracegraph.core.exceptions import ModelValidationError

# RFC 1035 label pattern (relaxed for OSINT target validation)
_DOMAIN_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$")
_ASN_RE = re.compile(r"^(?:AS|as)?(\d{1,10})$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def normalize_domain(value: str) -> str:
    """Normalize domain name to lowercase, stripped FQDN format."""
    val = value.strip().rstrip(".")
    if not val:
        raise ModelValidationError("Domain value cannot be empty")
    if len(val) > 253:
        raise ModelValidationError(f"Domain name exceeds 253 characters: {val}")

    # Handle IDNA / punycode encoding if non-ascii
    try:
        val = val.encode("idna").decode("ascii").lower()
    except Exception as e:
        raise ModelValidationError(f"Invalid domain encoding: {val}") from e

    labels = val.split(".")
    if not labels or any(not label for label in labels):
        raise ModelValidationError(f"Domain contains empty labels: {val}")

    for label in labels:
        if len(label) > 63:
            raise ModelValidationError(f"Domain label exceeds 63 characters: {label}")
        if not _DOMAIN_LABEL_RE.match(label):
            raise ModelValidationError(f"Domain label contains invalid characters: {label}")

    return val


def normalize_ipv4(value: str) -> str:
    """Validate and normalize IPv4 address to canonical dotted-decimal notation."""
    val = value.strip()
    parts = val.split(".")
    if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
        val = ".".join(str(int(p)) for p in parts)
    try:
        ip = ipaddress.IPv4Address(val)
        return str(ip)
    except Exception as e:
        raise ModelValidationError(f"Invalid IPv4 address: '{value}'") from e


def normalize_ipv6(value: str) -> str:
    """Validate and normalize IPv6 address to canonical compressed lowercase string."""
    val = value.strip()
    try:
        ip = ipaddress.IPv6Address(val)
        return ip.compressed.lower()
    except Exception as e:
        raise ModelValidationError(f"Invalid IPv6 address: '{value}'") from e


def normalize_asn(value: str) -> str:
    """Normalize Autonomous System Number to canonical 'AS<number>' format."""
    val = value.strip()
    match = _ASN_RE.match(val)
    if not match:
        raise ModelValidationError(f"Invalid ASN format (expected AS12345 or 12345): '{value}'")
    asn_num = int(match.group(1))
    if asn_num < 0 or asn_num > 4294967295:
        raise ModelValidationError(f"ASN value outside 32-bit integer range: '{value}'")
    return f"AS{asn_num}"


def normalize_cidr(value: str) -> str:
    """Validate and normalize CIDR notation to canonical network representation."""
    val = value.strip()
    try:
        net = ipaddress.ip_network(val, strict=False)
        return str(net).lower()
    except Exception as e:
        raise ModelValidationError(f"Invalid CIDR notation: '{value}'") from e


def normalize_url(value: str) -> str:
    """Normalize URL with lowercased scheme and host."""
    val = value.strip()
    if not val:
        raise ModelValidationError("URL cannot be empty")
    parsed = urlparse(val)
    if not parsed.scheme or not parsed.netloc:
        raise ModelValidationError(f"Invalid URL (missing scheme or host): '{value}'")

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    return urlunparse((scheme, netloc, path, parsed.params, parsed.query, parsed.fragment))


def normalize_certificate(value: str) -> str:
    """Normalize certificate fingerprint to uppercase hex without punctuation."""
    cleaned = value.strip().replace(":", "").replace(" ", "").replace("-", "")
    if not cleaned or not _HEX_RE.match(cleaned):
        raise ModelValidationError(f"Invalid certificate fingerprint hex: '{value}'")
    return cleaned.upper()


def normalize_entity_value(entity_type: EntityType, value: str) -> str:
    """Normalize a value based on its EntityType."""
    if not isinstance(value, str):
        raise ModelValidationError(f"Entity value must be a string, got {type(value).__name__}")

    if entity_type in (EntityType.DOMAIN, EntityType.NAMESERVER):
        return normalize_domain(value)
    if entity_type == EntityType.IPV4:
        return normalize_ipv4(value)
    if entity_type == EntityType.IPV6:
        return normalize_ipv6(value)
    if entity_type == EntityType.ASN:
        return normalize_asn(value)
    if entity_type == EntityType.CIDR:
        return normalize_cidr(value)
    if entity_type == EntityType.URL:
        return normalize_url(value)
    if entity_type == EntityType.CERTIFICATE:
        return normalize_certificate(value)

    # Fallback default normalization
    cleaned = value.strip()
    if not cleaned:
        raise ModelValidationError("Entity value cannot be empty")
    return cleaned


def validate_and_normalize(entity_type: EntityType | str, value: str) -> tuple[EntityType, str]:
    """Validate entity type and normalize value. Returns typed tuple."""
    if isinstance(entity_type, str):
        try:
            entity_type = EntityType(entity_type.upper())
        except ValueError:
            valid_types = ", ".join(t.value for t in EntityType)
            raise ModelValidationError(
                f"Unknown entity type '{entity_type}'. Must be one of: {valid_types}"
            )

    normalized = normalize_entity_value(entity_type, value)
    return entity_type, normalized
