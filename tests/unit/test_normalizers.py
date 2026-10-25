"""Unit tests for entity normalization routines."""

import pytest

from tracegraph.core.enums import EntityType
from tracegraph.core.exceptions import ModelValidationError
from tracegraph.core.normalizers import (
    normalize_asn,
    normalize_certificate,
    normalize_cidr,
    normalize_domain,
    normalize_ipv4,
    normalize_ipv6,
    normalize_url,
    validate_and_normalize,
)


class TestNormalizers:
    def test_domain_normalization(self):
        assert normalize_domain(" EXAMPLE.COM. ") == "example.com"
        assert normalize_domain("sub-domain.test.org") == "sub-domain.test.org"

    def test_domain_normalization_invalid(self):
        with pytest.raises(ModelValidationError):
            normalize_domain("")
        with pytest.raises(ModelValidationError):
            normalize_domain("invalid..domain")
        with pytest.raises(ModelValidationError):
            normalize_domain("invalid domain with spaces.com")
        with pytest.raises(ModelValidationError):
            normalize_domain("a" * 64 + ".com")

    def test_ipv4_normalization(self):
        assert normalize_ipv4(" 192.168.01.01 ") == "192.168.1.1"
        assert normalize_ipv4("8.8.8.8") == "8.8.8.8"

    def test_ipv4_normalization_invalid(self):
        with pytest.raises(ModelValidationError):
            normalize_ipv4("256.0.0.1")
        with pytest.raises(ModelValidationError):
            normalize_ipv4("not-an-ip")

    def test_ipv6_normalization(self):
        assert (
            normalize_ipv6("2001:0DB8:0000:0000:0000:0000:1428:57AB")
            == "2001:db8::1428:57ab"
        )
        assert normalize_ipv6("::1") == "::1"

    def test_ipv6_normalization_invalid(self):
        with pytest.raises(ModelValidationError):
            normalize_ipv6("2001:xyz::1")

    def test_asn_normalization(self):
        assert normalize_asn("15169") == "AS15169"
        assert normalize_asn("as15169") == "AS15169"
        assert normalize_asn("AS13335") == "AS13335"

    def test_asn_normalization_invalid(self):
        with pytest.raises(ModelValidationError):
            normalize_asn("AS-INVALID")
        with pytest.raises(ModelValidationError):
            normalize_asn("99999999999999999")

    def test_cidr_normalization(self):
        assert normalize_cidr("192.168.1.15/24") == "192.168.1.0/24"
        assert normalize_cidr("10.0.0.0/8") == "10.0.0.0/8"

    def test_cidr_normalization_invalid(self):
        with pytest.raises(ModelValidationError):
            normalize_cidr("192.168.1.1/33")

    def test_url_normalization(self):
        assert (
            normalize_url("HTTP://EXAMPLE.COM:80/path/to/resource")
            == "http://example.com/path/to/resource"
        )
        assert (
            normalize_url("HTTPS://EXAMPLE.COM:443/")
            == "https://example.com/"
        )

    def test_certificate_normalization(self):
        assert normalize_certificate("aa:bb:cc:dd") == "AABBCCDD"
        assert normalize_certificate("aa-bb-cc-dd") == "AABBCCDD"
        assert normalize_certificate("  aabbccdd  ") == "AABBCCDD"

    def test_validate_and_normalize_string_type(self):
        t, val = validate_and_normalize("domain", "  TEST.ORG ")
        assert t == EntityType.DOMAIN
        assert val == "test.org"

    def test_validate_and_normalize_invalid_type(self):
        with pytest.raises(ModelValidationError):
            validate_and_normalize("NON_EXISTENT_TYPE", "val")
