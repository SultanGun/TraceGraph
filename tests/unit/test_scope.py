"""Unit tests for investigation target scope validation and SSRF defenses."""

import pytest

from tracegraph.core.enums import EntityType
from tracegraph.core.exceptions import ScopeError
from tracegraph.core.scope import ScopeValidator, assert_public_ip, is_public_ip


class TestScopeValidator:
    def test_unrestricted_scope(self):
        validator = ScopeValidator("*")
        assert validator.is_in_scope("example.com", EntityType.DOMAIN)
        assert validator.is_in_scope("93.184.215.14", EntityType.IPV4)
        assert validator.is_in_scope("2606:2800:220:1:248:1893:25c8:1946", EntityType.IPV6)

    def test_domain_scope_matching(self):
        validator = ScopeValidator("example.com, target.org")
        assert validator.is_in_scope("example.com", EntityType.DOMAIN)
        assert validator.is_in_scope("sub.example.com", EntityType.DOMAIN)
        assert validator.is_in_scope("target.org", EntityType.DOMAIN)
        assert not validator.is_in_scope("other.com", EntityType.DOMAIN)
        assert not validator.is_in_scope("faketarget.org", EntityType.DOMAIN)

    def test_wildcard_domain_scope(self):
        validator = ScopeValidator("*.corp.local")
        assert validator.is_in_scope("auth.corp.local", EntityType.DOMAIN)
        assert validator.is_in_scope("deep.sub.corp.local", EntityType.DOMAIN)
        assert validator.is_in_scope("corp.local", EntityType.DOMAIN)
        assert not validator.is_in_scope("evilcorp.local", EntityType.DOMAIN)

    def test_ip_scope_matching(self):
        validator = ScopeValidator("93.184.215.14, 1.1.1.1")
        assert validator.is_in_scope("93.184.215.14", EntityType.IPV4)
        assert validator.is_in_scope("1.1.1.1", EntityType.IPV4)
        assert not validator.is_in_scope("93.184.215.15", EntityType.IPV4)

    def test_cidr_scope_matching(self):
        validator = ScopeValidator("93.184.215.0/24")
        assert validator.is_in_scope("93.184.215.1", EntityType.IPV4)
        assert validator.is_in_scope("93.184.215.254", EntityType.IPV4)
        assert validator.is_in_scope("93.184.215.0/28", EntityType.CIDR)
        assert not validator.is_in_scope("93.184.216.1", EntityType.IPV4)

    def test_assert_in_scope_raises_scope_error(self):
        validator = ScopeValidator("example.com")
        validator.assert_in_scope("example.com", EntityType.DOMAIN)
        with pytest.raises(ScopeError):
            validator.assert_in_scope("unauthorized.com", EntityType.DOMAIN)


class TestPublicIPSafety:
    def test_public_ips_allowed(self):
        assert is_public_ip("93.184.215.14") is True
        assert is_public_ip("8.8.8.8") is True
        assert is_public_ip("1.1.1.1") is True
        assert is_public_ip("2606:2800:220:1:248:1893:25c8:1946") is True

    def test_private_and_loopback_ips_blocked(self):
        # RFC 1918
        assert is_public_ip("10.0.0.1") is False
        assert is_public_ip("172.16.0.1") is False
        assert is_public_ip("192.168.1.1") is False

        # Loopback
        assert is_public_ip("127.0.0.1") is False
        assert is_public_ip("127.0.0.2") is False
        assert is_public_ip("::1") is False

        # Link Local
        assert is_public_ip("169.254.1.1") is False
        assert is_public_ip("fe80::1") is False

        # Documentation (RFC 5737)
        assert is_public_ip("192.0.2.1") is False
        assert is_public_ip("198.51.100.1") is False
        assert is_public_ip("203.0.113.1") is False

        # CGNAT / Shared space (RFC 6598)
        assert is_public_ip("100.64.0.1") is False

        # Broadcast & 0.0.0.0
        assert is_public_ip("0.0.0.0") is False
        assert is_public_ip("255.255.255.255") is False

    def test_assert_public_ip_raises_scope_error(self):
        assert_public_ip("8.8.8.8")
        with pytest.raises(ScopeError):
            assert_public_ip("127.0.0.1")
        with pytest.raises(ScopeError):
            assert_public_ip("10.10.10.10")
