"""Tests for the address predicates and small sanitisers.

``is_public_ip`` and ``is_unicast_host_ip`` gate what pcapper calls internet
exposure, a scan target, a beacon destination and a C2 peer, so a wrong answer
here does not produce a crash — it produces a wrong finding in a report.
"""

from __future__ import annotations

import pytest

from pcapper.utils import (
    detect_file_type_bytes,
    is_private_ip,
    is_public_ip,
    is_unicast_host_ip,
    shannon_entropy,
)


class TestIsPublicIp:
    @pytest.mark.parametrize("value", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1"])
    def test_routable_unicast_is_public(self, value: str) -> None:
        assert is_public_ip(value)

    @pytest.mark.parametrize("value", ["192.0.2.1", "198.51.100.1", "203.0.113.1"])
    def test_rfc5737_documentation_ranges_are_not_public(self, value: str) -> None:
        """TEST-NET-1/2/3 are reserved, so Python reports them as private. Worth
        pinning because they are the obvious choice for a synthetic capture and
        would quietly fail to exercise any internet-exposure path."""
        assert not is_public_ip(value)

    @pytest.mark.parametrize(
        "value",
        [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "fe80::1",
            "::1",
            "fd00::1",
        ],
    )
    def test_non_routable_is_not_public(self, value: str) -> None:
        assert not is_public_ip(value)

    @pytest.mark.parametrize("value", ["224.0.0.251", "239.255.255.250", "ff02::1", "ff0e::1"])
    def test_multicast_is_never_public(self, value: str) -> None:
        """Python reports global-scope IPv6 multicast as is_global, so without
        the explicit exclusion benign Neighbor Discovery and mDNS read as
        internet exposure."""
        assert not is_public_ip(value)

    @pytest.mark.parametrize("value", ["", "not-an-ip", "999.1.1.1", "1.2.3"])
    def test_garbage_is_not_public(self, value: str) -> None:
        assert not is_public_ip(value)

    def test_none_is_handled(self) -> None:
        assert not is_public_ip(None)  # type: ignore[arg-type]


class TestIsPrivateIp:
    @pytest.mark.parametrize("value", ["10.1.2.3", "192.168.0.1", "172.20.0.1", "fd00::1"])
    def test_rfc1918_and_ula(self, value: str) -> None:
        assert is_private_ip(value)

    def test_public_is_not_private(self) -> None:
        assert not is_private_ip("8.8.8.8")

    def test_garbage(self) -> None:
        assert not is_private_ip("nope")


class TestIsUnicastHostIp:
    @pytest.mark.parametrize("value", ["10.0.0.5", "8.8.8.8", "2606:4700::1", "fe80::1"])
    def test_real_hosts(self, value: str) -> None:
        assert is_unicast_host_ip(value)

    @pytest.mark.parametrize(
        "value",
        [
            "255.255.255.255",  # limited broadcast
            "192.168.1.255",  # /24 directed broadcast
            "224.0.0.251",  # mDNS
            "239.255.255.250",  # SSDP
            "ff02::1",  # all-nodes
            "0.0.0.0",  # unspecified
        ],
    )
    def test_one_to_many_destinations_are_excluded(self, value: str) -> None:
        """Broadcast and multicast are announcement channels, not host targets;
        counting them as peers makes benign browse/discovery chatter read as
        scanning or beaconing."""
        assert not is_unicast_host_ip(value)

    def test_garbage(self) -> None:
        assert not is_unicast_host_ip("...")


class TestShannonEntropy:
    def test_empty_string(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_repeated_symbol_has_no_entropy(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_two_equally_likely_symbols(self) -> None:
        assert shannon_entropy("abab") == pytest.approx(1.0)

    def test_random_looking_string_scores_higher_than_english(self) -> None:
        assert shannon_entropy("f3Kq9ZxV7bNw2Lp0") > shannon_entropy("intranet")


class TestDetectFileTypeBytes:
    @pytest.mark.parametrize(
        "data,expected_substring",
        [
            (b"%PDF-1.7\n", "PDF"),
            (b"\x89PNG\r\n\x1a\n", "PNG"),
            (b"\x7fELF\x02\x01\x01", "ELF"),
            (b"GIF89a", "GIF"),
        ],
    )
    def test_known_signatures(self, data: bytes, expected_substring: str) -> None:
        assert expected_substring in detect_file_type_bytes(data)

    def test_empty_input_does_not_raise(self) -> None:
        assert isinstance(detect_file_type_bytes(b""), str)

    def test_unrecognised_input_does_not_raise(self) -> None:
        assert isinstance(detect_file_type_bytes(b"\x01\x02\x03\x04"), str)
