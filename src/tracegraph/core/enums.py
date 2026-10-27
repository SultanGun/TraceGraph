"""Enumerations defining entity types, relationship types, and collection statuses."""

from enum import StrEnum


class EntityType(StrEnum):
    """Categorization of infrastructure entities."""

    DOMAIN = "DOMAIN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    ASN = "ASN"
    CIDR = "CIDR"
    NAMESERVER = "NAMESERVER"
    CERTIFICATE = "CERTIFICATE"
    URL = "URL"


class RelationshipType(StrEnum):
    """Verifiable directional links between infrastructure entities."""

    RESOLVES_TO = "RESOLVES_TO"
    HOSTED_ON = "HOSTED_ON"
    BELONGS_TO = "BELONGS_TO"
    SUBDOMAIN_OF = "SUBDOMAIN_OF"
    SERVED_BY = "SERVED_BY"
    CERTIFIED_BY = "CERTIFIED_BY"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    MAIL_EXCHANGER_FOR = "MAIL_EXCHANGER_FOR"


class CollectionStatus(StrEnum):
    """Execution status of an observation collector."""

    SUCCESS = "SUCCESS"
    EMPTY = "EMPTY"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
