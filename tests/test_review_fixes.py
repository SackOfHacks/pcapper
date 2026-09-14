"""Regression tests for the defects fixed in the 2026-09 production-readiness
review. Each test names the failure it pins; most would have passed silently
before the fix by producing a wrong report rather than an error.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from pcapper import device_detection, skeptical, utils
from pcapper.reporting_format import format_table

REPO = Path(__file__).parent.parent


# --- utils -------------------------------------------------------------------


class TestDetectFileType:
    def test_pcap_magic_both_byte_orders_and_nanosecond(self, tmp_path) -> None:
        for magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            p = tmp_path / "x.pcap"
            p.write_bytes(magic + b"\x00" * 20)
            assert utils.detect_file_type(p) == "pcap", magic.hex()

    def test_pcapng_magic(self, tmp_path) -> None:
        p = tmp_path / "x.pcapng"
        p.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
        assert utils.detect_file_type(p) == "pcapng"

    def test_non_capture_is_unknown_not_pcap(self, tmp_path) -> None:
        """Used to return "pcap" for anything, so a renamed zip or a
        gzip-compressed capture was read as an empty capture: zero packets,
        no error."""
        p = tmp_path / "x.pcap"
        p.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)  # gzip
        assert utils.detect_file_type(p) == "unknown"
        p.write_bytes(b"")
        assert utils.detect_file_type(p) == "unknown"

    def test_missing_file_is_unknown(self, tmp_path) -> None:
        assert utils.detect_file_type(tmp_path / "absent.pcap") == "unknown"


class TestOpenPrivate:
    def test_writes_text_and_bytes(self, tmp_path) -> None:
        p = tmp_path / "a.txt"
        with utils.open_private(p, "w") as h:
            h.write("secret")
        assert p.read_text(encoding="utf-8") == "secret"
        b = tmp_path / "b.bin"
        utils.safe_write_bytes(b, b"\x00\xff")
        assert b.read_bytes() == b"\x00\xff"

    def test_append_mode_appends(self, tmp_path) -> None:
        p = tmp_path / "log.txt"
        with utils.open_private(p, "a") as h:
            h.write("one\n")
        with utils.open_private(p, "a") as h:
            h.write("two\n")
        assert p.read_text(encoding="utf-8") == "one\ntwo\n"

    def test_created_owner_only(self, tmp_path, posix_only) -> None:
        """The file must be 0600 from creation, not chmod'd after a
        world-readable write."""
        p = tmp_path / "c.txt"
        with utils.open_private(p, "w") as h:
            assert (os.fstat(h.fileno()).st_mode & 0o777) == 0o600
            h.write("x")

    def test_rejects_read_modes(self, tmp_path) -> None:
        with pytest.raises(ValueError):
            utils.open_private(tmp_path / "d", "r")


class TestEnvInt:
    def test_default_and_malformed(self, monkeypatch) -> None:
        monkeypatch.delenv("PCAPPER_X", raising=False)
        assert utils.env_int("PCAPPER_X", 7) == 7
        monkeypatch.setenv("PCAPPER_X", "abc")
        assert utils.env_int("PCAPPER_X", 7) == 7
        monkeypatch.setenv("PCAPPER_X", " 42 ")
        assert utils.env_int("PCAPPER_X", 7) == 42

    def test_minimum_is_enforced(self, monkeypatch) -> None:
        monkeypatch.setenv("PCAPPER_X", "-5")
        assert utils.env_int("PCAPPER_X", 7, minimum=1) == 1


class TestPacketLengths:
    def test_wirelen_beats_caplen_when_present(self) -> None:
        class Pkt:
            original = b"\x00" * 60
            wirelen = 1514

        assert utils.packet_length(Pkt()) == 60
        assert utils.packet_wirelen(Pkt()) == 1514

    def test_wirelen_falls_back_to_caplen(self) -> None:
        class Pkt:
            original = b"\x00" * 60

        assert utils.packet_wirelen(Pkt()) == 60


class TestExtractEthertype:
    def test_from_raw_frame_bytes(self) -> None:
        class Pkt:
            original = b"\xff" * 12 + b"\x88\xa4" + b"\x00" * 10

        assert utils.extract_ethertype(Pkt()) == 0x88A4


# --- memoization -------------------------------------------------------------


class TestMemoization:
    def test_outer_ot_analyzer_result_is_shared_on_hit(self, pcap, monkeypatch) -> None:
        """Copying on hit is off by default; the ratchet test guarantees no
        caller mutates a shared result."""
        monkeypatch.delenv("PCAPPER_ANALYSIS_MEMO_COPY", raising=False)
        from pcapper.bacnet import analyze_bacnet
        from pcapper.utils import clear_analysis_memo

        clear_analysis_memo()
        first = analyze_bacnet(pcap("modbus.pcap"), show_status=False)
        second = analyze_bacnet(pcap("modbus.pcap"), show_status=False)
        assert first is second

    def test_inner_builder_is_never_shared(self, pcap) -> None:
        """analyze_port_protocol is post-processed in place by every OT
        analyzer, so it must hand out a fresh object every call."""
        from pcapper.industrial_helpers import analyze_port_protocol

        a = analyze_port_protocol(pcap("modbus.pcap"), "X", tcp_ports={502}, show_status=False)
        b = analyze_port_protocol(pcap("modbus.pcap"), "X", tcp_ports={502}, show_status=False)
        assert a is not b
        assert a.anomalies is not b.anomalies

    def test_copy_can_be_restored(self, pcap, monkeypatch) -> None:
        monkeypatch.setenv("PCAPPER_ANALYSIS_MEMO_COPY", "1")
        from pcapper.icmp import analyze_icmp
        from pcapper.utils import clear_analysis_memo

        clear_analysis_memo()
        first = analyze_icmp(pcap("dns.pcap"), show_status=False)
        second = analyze_icmp(pcap("dns.pcap"), show_status=False)
        assert first is not second and first == second


# --- skeptical filter ----------------------------------------------------------


class TestSkepticalFilter:
    def test_tls_rule_needs_missing_sni_evidence(self) -> None:
        """all() over zero ratios is True: any TLS handshake-failure finding
        that merely mentioned "proxy" used to be downgraded."""
        det = {
            "source": "TLS",
            "severity": "high",
            "summary": "TLS handshake failures",
            "details": "12 failures via proxy 10.0.0.1:80",
        }
        assert skeptical.apply_skeptical_filter(det, strict=False) is det

    def test_tls_rule_fires_with_full_evidence(self) -> None:
        det = {
            "source": "TLS",
            "severity": "high",
            "summary": "TLS handshake failures",
            "details": "missing_sni=12/12 CONNECT tunnel via proxy:80",
        }
        out = skeptical.apply_skeptical_filter(det, strict=False)
        assert out["skeptical_rule"] == "blocked-outbound-tunnel"
        assert out["severity"] == "warning"

    def test_cdn_membership_is_cidr_based(self) -> None:
        assert skeptical._is_cdn_ip("104.16.1.1")
        assert skeptical._is_cdn_ip("104.31.255.254")
        assert not skeptical._is_cdn_ip("104.32.0.1")
        assert not skeptical._is_cdn_ip("8.8.8.8")
        assert not skeptical._is_cdn_ip("not-an-ip")

    def test_destination_extraction_drops_invalid_addresses(self) -> None:
        assert skeptical._extract_destination_ips("-> 999.1.1.1 -> 10.0.0.1") == ["10.0.0.1"]

    def test_many_variant_honours_cli_default(self) -> None:
        det = {"source": "TCP", "severity": "high", "summary": "Potential TCP SYN flood",
               "details": "-> 104.16.1.1 SYN=100 SYN-ACK=0 (0.0%)"}
        skeptical.set_default_strict(True)
        try:
            assert skeptical.apply_skeptical_filter_many([det])[0] is det
        finally:
            skeptical.set_default_strict(False)
        assert skeptical.apply_skeptical_filter_many([det])[0]["severity"] == "warning"


# --- device detection ------------------------------------------------------------


class TestDeviceDetectionFalsePositives:
    def test_boarding_is_not_boa_httpd(self) -> None:
        fields = device_detection.extract_device_fields("Boarding pass server version 2")
        assert "Boa" not in str(fields.get("software", ""))

    def test_boa_with_version_still_detected(self) -> None:
        # extract_device_fields is gated on a device-hint word ("device" here).
        fields = device_detection.extract_device_fields("embedded device Boa/0.94.14rc21")
        assert fields.get("software") == "Boa 0.94.14rc21"

    def test_cisco_ios_is_not_apple(self) -> None:
        fields = device_detection.extract_device_fields("Cisco IOS Software, C2960 version 15.2")
        assert fields.get("os", "").startswith("Cisco IOS")

    def test_apple_ios_still_detected(self) -> None:
        fields = device_detection.extract_device_fields("iPhone device iOS 17.1")
        assert fields.get("os") == "iOS 17.1"

    def test_ge_fragment_is_not_general_electric(self) -> None:
        assert device_detection.extract_device_fields("device id ge 42 model X").get("vendor") != "GE"

    def test_ge_product_family_is(self) -> None:
        assert device_detection.extract_device_fields("GE Fanuc PLC model 90-30").get("vendor") == "GE"

    def test_google_drive_is_not_a_vfd(self) -> None:
        assert device_detection.extract_device_fields("Google Drive device sync").get("device_type") != "Drive/VFD"


# --- carving -------------------------------------------------------------------------


def _fake_pe(section_bytes: int = 200) -> bytes:
    """A minimal PE: MZ stub, e_lfanew -> "PE\\0\\0", one section whose raw
    data ends the file. Real enough for the size logic, nothing more."""
    lfanew = 0x80
    pe = bytearray(b"MZ" + b"\x00" * (lfanew - 2))
    pe[0x3C:0x40] = lfanew.to_bytes(4, "little")
    coff = b"PE\x00\x00" + b"\x4c\x01" + (1).to_bytes(2, "little") + b"\x00" * 12
    opt_size = 0xE0
    coff += opt_size.to_bytes(2, "little") + b"\x00" * 2
    pe += coff + b"\x00" * opt_size
    raw_ptr = len(pe) + 40
    section = bytearray(40)
    section[16:20] = section_bytes.to_bytes(4, "little")
    section[20:24] = raw_ptr.to_bytes(4, "little")
    pe += section
    pe += b"\xcc" * section_bytes
    return bytes(pe)


class TestCarvingSignatures:
    def test_bare_mz_is_not_a_pe(self) -> None:
        from pcapper.carving import _pe_end

        assert _pe_end(b"MZ" + b"\x00" * 100, 0) is None

    def test_pe_length_comes_from_the_section_table(self) -> None:
        from pcapper.carving import _carve_blob, _pe_end

        image = _fake_pe(200)
        data = b"HTTP/1.1 200 OK\r\n\r\n" + image + b"trailing junk"
        offset = data.index(b"MZ")
        assert _pe_end(data, offset) == offset + len(image)
        blob, exact = _carve_blob(data, offset, 1 << 20, "EXE/DLL")
        assert exact and blob == image

    def test_pdf_ends_at_eof_marker(self) -> None:
        from pcapper.carving import _carve_blob

        pdf = b"%PDF-1.4\nstuff\n%%EOF\n"
        data = pdf + b"GET /next HTTP/1.1"
        blob, exact = _carve_blob(data, 0, 1 << 20, "PDF")
        assert exact and blob == pdf

    def test_png_jpg_gif_zip_trailers(self) -> None:
        from pcapper.carving import _carve_blob

        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 8 + b"IEND\xaeB`\x82"
        assert _carve_blob(png + b"xx", 0, 1 << 20, "PNG") == (png, True)
        jpg = b"\xff\xd8\xff\xe0" + b"\x11" * 10 + b"\xff\xd9"
        assert _carve_blob(jpg + b"xx", 0, 1 << 20, "JPG") == (jpg, True)
        gif = b"GIF89a" + b"\x01" * 6 + b"\x00;"
        assert _carve_blob(gif + b"xx", 0, 1 << 20, "GIF") == (gif, True)
        zip_ = b"PK\x03\x04" + b"\x00" * 26 + b"PK\x05\x06" + b"\x00" * 16 + b"\x02\x00" + b"hi"
        assert _carve_blob(zip_ + b"xx", 0, 1 << 20, "ZIP") == (zip_, True)

    def test_format_without_trailer_is_bounded(self) -> None:
        from pcapper.carving import _carve_blob

        gz = b"\x1f\x8b\x08\x00" + b"\x00" * 100
        blob, exact = _carve_blob(gz, 0, 32, "GZIP")
        assert not exact and len(blob) == 32

    def test_trailer_of_a_later_file_is_not_used(self) -> None:
        """A %%EOF beyond the carve limit belongs to some other file."""
        from pcapper.carving import _carve_blob

        data = b"%PDF-1.4\n" + b"A" * 100 + b"%%EOF\n"
        blob, exact = _carve_blob(data, 0, 50, "PDF")
        assert not exact and len(blob) == 50

    def test_single_scan_finds_every_signature_in_order(self) -> None:
        from pcapper.carving import _find_signatures

        data = b"..%PDF-..\x89PNG\r\n\x1a\n..GIF8..MZ.."
        labels = [label for _off, label, _magic in _find_signatures(data)]
        assert labels == ["PDF", "PNG", "GIF", "EXE/DLL"]


# --- dns: VirusTotal egress hygiene ------------------------------------------------


class TestDnsVirusTotalHygiene:
    def test_internal_and_reverse_names_are_never_candidates(self) -> None:
        from pcapper.dns import vt_lookup_candidate

        for name in (
            "fileserver.corp", "printer.local", "nas.lan", "dc01.internal",
            "50.10.168.192.in-addr.arpa", "b.a.9.8.ip6.arpa", "host.home.arpa",
            "_ipp._tcp.local", "localhost", "single-label", "192.168.10.50",
            "bad..name", "-leading.example.com", "",
        ):
            assert not vt_lookup_candidate(name), name

    def test_public_names_are_candidates(self) -> None:
        from pcapper.dns import vt_lookup_candidate

        for name in ("updates.example.net", "Example.COM.", "a.b.c.example.org"):
            assert vt_lookup_candidate(name), name

    def test_only_public_names_are_sent(self) -> None:
        from pcapper.dns import _vt_lookup_domains

        sent: list[str] = []

        def fake_lookup(domain: str, _key: str):
            sent.append(domain)
            return {"domain": domain, "malicious": 0, "suspicious": 0, "harmless": 1,
                    "undetected": 0, "timeout": 0, "reputation": 0,
                    "last_analysis_date": None, "report_url": "", "score": 0,
                    "rating": "clean"}, None

        results, errors = _vt_lookup_domains(
            ["evil.example.net", "dc01.corp", "10.168.192.in-addr.arpa", "printer.local"],
            "k", lookup=fake_lookup,
        )
        assert sent == ["evil.example.net"]
        assert set(results) == {"evil.example.net"}
        assert any("3 internal/non-public name(s) withheld" in e for e in errors)

    def test_time_budget_stops_the_pass(self, monkeypatch) -> None:
        from pcapper import dns as dns_mod

        clock = [0.0]
        monkeypatch.setattr(dns_mod.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(dns_mod.time, "sleep", lambda _s: None)
        dns_mod._VT_CACHE.clear()

        def slow_lookup(domain: str, _key: str):
            clock[0] += 50.0
            return {"domain": domain, "malicious": 0, "suspicious": 0, "harmless": 1,
                    "undetected": 0, "timeout": 0, "reputation": 0,
                    "last_analysis_date": None, "report_url": "", "score": 0,
                    "rating": "clean"}, None

        names = [f"h{i}.example.net" for i in range(10)]
        results, errors = dns_mod._vt_lookup_domains(names, "k", lookup=slow_lookup, budget_seconds=120)
        assert 2 <= len(results) < 10
        assert any("time budget of 120s spent" in e for e in errors)

    def test_domain_is_percent_encoded_in_the_request(self, monkeypatch) -> None:
        from pcapper import dns as dns_mod

        seen: list[str] = []

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"data": {"attributes": {"last_analysis_stats": {}}}}'

        def fake_urlopen(req, timeout):
            seen.append(req.full_url)
            return _Resp()

        monkeypatch.setattr(dns_mod.urllib.request, "urlopen", fake_urlopen)
        dns_mod._vt_lookup_domain("evil.example/../../users?x=1#f", "k")
        assert seen and "/api/v3/domains/evil.example%2F..%2F..%2Fusers%3Fx%3D1%23f" in seen[0]


class TestHttpVirusTotalHygiene:
    @staticmethod
    def _clean(target: str) -> dict:
        return {"target": target, "malicious": 0, "suspicious": 0, "harmless": 1,
                "undetected": 0, "timeout": 0, "reputation": 0, "score": 0, "rating": "clean"}

    def test_only_public_hosts_and_urls_are_sent(self) -> None:
        from pcapper import http as http_mod

        sent: list[tuple[str, str]] = []

        def fake_domain(domain: str, _key: str):
            sent.append(("domain", domain))
            return self._clean(domain), None

        def fake_url(url: str, _key: str):
            sent.append(("url", url))
            return self._clean(url), None

        http_mod._VT_CACHE.clear()
        targets = [
            ("domain", "cdn.example.net"),
            ("domain", "fileserver.corp"),
            ("domain", "10.0.0.5"),
            ("url", "http://cdn.example.net/a.exe"),
            ("url", "http://192.168.1.10/login"),
            ("url", "http://plc-01/system.html"),
            ("url", "http://printer.local/"),
        ]
        results, errors = http_mod._vt_lookup_targets(
            targets, "k", lookup_domain=fake_domain, lookup_url=fake_url
        )
        assert sent == [("domain", "cdn.example.net"), ("url", "http://cdn.example.net/a.exe")]
        assert len(results) == 2
        assert any("5 internal/non-public target(s) withheld" in e for e in errors)

    def test_time_budget_stops_the_pass(self, monkeypatch) -> None:
        from pcapper import http as http_mod

        clock = [0.0]
        monkeypatch.setattr(http_mod.time, "monotonic", lambda: clock[0])
        monkeypatch.setattr(http_mod.time, "sleep", lambda _s: None)
        http_mod._VT_CACHE.clear()

        def slow_domain(domain: str, _key: str):
            clock[0] += 50.0
            return self._clean(domain), None

        targets = [("domain", f"h{i}.example.net") for i in range(10)]
        results, errors = http_mod._vt_lookup_targets(
            targets, "k", lookup_domain=slow_domain, budget_seconds=120
        )
        assert 2 <= len(results) < 10
        assert any("time budget of 120s spent" in e for e in errors)

    def test_domain_is_percent_encoded_in_the_request(self, monkeypatch) -> None:
        from pcapper import http as http_mod

        seen: list[str] = []

        class _Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b'{"data": {"attributes": {"last_analysis_stats": {}}}}'

        def fake_urlopen(req, timeout):
            seen.append(req.full_url)
            return _Resp()

        monkeypatch.setattr(http_mod.urllib.request, "urlopen", fake_urlopen)
        http_mod._vt_lookup_domain("evil.example/../../users?x=1#f", "k")
        assert seen and "/api/v3/domains/evil.example%2F..%2F..%2Fusers%3Fx%3D1%23f" in seen[0]


class TestHttpStartLineGate:
    """The pre-decode gate must accept exactly what the parser accepts."""

    def test_requests_and_responses_pass(self) -> None:
        from pcapper.http import _HTTP_START_RE

        for line in (
            b"GET / HTTP/1.1\r\nHost: a\r\n\r\n",
            b"GET /no-version\r\n",
            b"PROPFIND /webdav/ HTTP/1.1\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"HTTP/1.0 404 Not Found\r\n",
        ):
            assert _HTTP_START_RE.match(line[:64]), line

    def test_non_http_payloads_are_rejected(self) -> None:
        from pcapper.http import _HTTP_START_RE

        for payload in (
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03",  # TLS ClientHello
            b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a",  # Modbus/TCP
            b"GETTING started",
            b"HTTP/1.1",
            b"",
        ):
            assert not _HTTP_START_RE.match(payload[:64]), payload

    def test_webdav_methods_are_parsed(self) -> None:
        from pcapper.http import HTTP_METHODS

        assert {"PROPFIND", "MKCOL", "MOVE"} <= HTTP_METHODS


# --- TLS / certificates ---------------------------------------------------------


TLS_PCAP = Path(__file__).parent / "data" / "tls.pcap"


class TestTlsFixture:
    def test_handshakes_and_hygiene_findings(self) -> None:
        from pcapper.tls import analyze_tls

        summary = analyze_tls(TLS_PCAP, show_status=False)
        assert summary.client_hellos == 4 and summary.server_hellos == 4
        assert summary.sni_counts == {"cdn-update.xyz": 2, "shop.example.net": 1}
        assert summary.sni_missing_no_ech == 1
        assert summary.weak_ciphers == {"0x000a": 2}
        assert summary.versions["TLS1.0"] == 2
        assert set(summary.alpn_counts) == {"h2", "http/1.1"}
        titles = {d["summary"] for d in summary.detections}
        assert "Legacy TLS versions observed" in titles
        assert "Weak TLS cipher suites observed" in titles
        assert "Suspicious SNI TLDs observed" in titles
        # Window spans TLS packets (all 12 here), not the whole capture.
        assert summary.first_seen is not None and summary.duration_seconds == pytest.approx(0.55)

    def test_certificate_is_attributed_to_the_server_and_its_sni(self) -> None:
        from pcapper.tls import analyze_tls

        summary = analyze_tls(TLS_PCAP, show_status=False)
        assert summary.cert_count == 1
        cert = summary.cert_artifacts[0]
        assert cert.src_ip == "192.168.10.10"  # the service that presented it
        assert cert.sni == "shop.example.net"  # attributed from the client hello
        assert summary.self_signed_certs == 1 and summary.expired_certs == 1
        assert summary.weak_certs == 0  # Ed25519 is not a weak key
        assert any("Cert SHA256:" in a and "service=shop.example.net" in a for a in summary.artifacts)


class TestCertificates:
    def test_dns_sans_no_longer_flag_every_certificate(self) -> None:
        from pcapper.certificates import analyze_certificates

        summary = analyze_certificates(TLS_PCAP, show_status=False)
        assert summary.cert_count == 1
        reasons = {item["reason"] for item in summary.name_mismatches}
        assert "dst_ip_not_in_san" not in reasons and "server_ip_not_in_san" not in reasons

    def test_endpoint_profile_is_the_presenting_server(self) -> None:
        from pcapper.certificates import analyze_certificates

        summary = analyze_certificates(TLS_PCAP, show_status=False)
        assert [p["endpoint"] for p in summary.endpoint_profiles] == ["192.168.10.10"]

    def test_tls_packets_counts_records_on_any_port(self) -> None:
        from pcapper.certificates import analyze_certificates

        summary = analyze_certificates(TLS_PCAP, show_status=False)
        assert summary.total_packets == 12 and summary.tls_packets == 12

    def test_memoized_across_tls_and_certificates_steps(self) -> None:
        from pcapper.certificates import analyze_certificates
        from pcapper.tls import analyze_tls

        utils.clear_analysis_memo()
        direct = analyze_certificates(TLS_PCAP, show_status=False)
        analyze_tls(TLS_PCAP, show_status=False)  # runs analyze_certificates internally
        assert analyze_certificates(TLS_PCAP, show_status=False) is direct


# --- DHCP -----------------------------------------------------------------------


MIXED_PCAP = Path(__file__).parent / "data" / "mixed.pcap"


def _dhcp6_option(code: int, value: bytes) -> bytes:
    return code.to_bytes(2, "big") + len(value).to_bytes(2, "big") + value


class TestDhcp:
    def test_offer_answering_a_discover_is_not_a_violation(self) -> None:
        from pcapper.dhcp import analyze_dhcp

        summary = analyze_dhcp(MIXED_PCAP, show_status=False)
        assert summary.dhcp_packets == 2
        assert summary.message_types == {"DISCOVER": 1, "OFFER": 1}
        assert summary.transaction_violations == []
        assert summary.deterministic_checks.get("transaction_integrity_violation", []) == []

    def test_offer_with_no_client_transaction_is_flagged(self, tmp_path) -> None:
        from scapy.all import wrpcap  # type: ignore
        from scapy.layers.dhcp import BOOTP, DHCP  # type: ignore
        from scapy.layers.inet import IP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore

        from pcapper.dhcp import analyze_dhcp

        chaddr = bytes.fromhex("020000000001")
        offer = (
            Ether(src="02:00:00:00:00:fe", dst="02:00:00:00:00:01")
            / IP(src="192.168.10.1", dst="192.168.10.50")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr="192.168.10.50", chaddr=chaddr, xid=0x4242)
            / DHCP(options=[("message-type", "offer"), ("server_id", "192.168.10.1"), "end"])
        )
        offer.time = 1609459200.0
        target = tmp_path / "unsolicited_offer.pcap"
        wrpcap(str(target), [offer])
        summary = analyze_dhcp(target, show_status=False)
        assert len(summary.transaction_violations) == 1
        assert summary.transaction_violations[0]["type"] == "OFFER"

    def test_dhcpv6_wire_format_names_decode(self) -> None:
        from pcapper.dhcp import _decode_dns_names, _parse_dhcp6_options

        assert _decode_dns_names(b"\x04corp\x07example\x03net\x00\x03lab\x05local\x00") == [
            "corp.example.net",
            "lab.local",
        ]
        payload = (
            b"\x01\x00\x00\x2a"  # SOLICIT, xid 42
            + _dhcp6_option(39, b"\x00" + b"\x04ws01\x04corp\x00")  # Client FQDN
            + _dhcp6_option(15, b"\x00\x05admin")  # User Class
            + _dhcp6_option(24, b"\x04corp\x07example\x03net\x00")  # Domain Search
        )
        msg_type, options, xid = _parse_dhcp6_options(payload)
        assert (msg_type, xid) == ("SOLICITv6", 42)
        assert options["hostname"] == "ws01.corp"
        assert options["domain_name"] == ["corp.example.net"]
        assert "admin" in options["user_class"]


# --- NTP / VLAN / SNMP ----------------------------------------------------------


class TestNtp:
    def test_roles_and_window_from_mixed_fixture(self) -> None:
        from pcapper.ntp import analyze_ntp

        summary = analyze_ntp(MIXED_PCAP, show_status=False)
        assert summary.ntp_packets == 2
        assert summary.mode_counts == {"client": 1, "server": 1}
        assert summary.client_counts == {"192.168.10.50": 2}
        assert summary.server_counts == {"192.168.10.10": 2}
        assert summary.duration_seconds == pytest.approx(0.05)  # NTP window, not the capture
        assert analyze_ntp(MIXED_PCAP, show_status=False) is summary  # memoized


class TestVlan:
    def test_single_tag_stats(self) -> None:
        from pcapper.vlan import analyze_vlans

        summary = analyze_vlans(MIXED_PCAP, show_status=False)
        assert summary.total_tagged_packets == 6
        assert [s.vlan_id for s in summary.vlan_stats] == [10]
        assert summary.double_tagged_packets == 0

    def test_double_tagged_frames_are_flagged(self, tmp_path) -> None:
        from scapy.all import wrpcap  # type: ignore
        from scapy.layers.inet import IP, UDP  # type: ignore
        from scapy.layers.l2 import Dot1Q, Ether  # type: ignore

        from pcapper.vlan import analyze_vlans

        frame = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / Dot1Q(vlan=1)
            / Dot1Q(vlan=20)
            / IP(src="192.168.10.50", dst="192.168.20.10")
            / UDP(sport=40000, dport=53)
        )
        frame.time = 1609459200.0
        target = tmp_path / "qinq.pcap"
        wrpcap(str(target), [frame])
        summary = analyze_vlans(target, show_status=False)
        assert summary.double_tagged_packets == 1
        hit = next(d for d in summary.detections if d["type"] == "vlan_double_tagged")
        assert hit["severity"] == "high" and "1->20(1)" in hit["details"]


class TestSnmpRoles:
    @staticmethod
    def _poll_pcap(tmp_path: Path) -> Path:
        from scapy.all import wrpcap  # type: ignore
        from scapy.layers.inet import IP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.layers.snmp import SNMP, SNMPget, SNMPresponse, SNMPvarbind  # type: ignore

        manager, agent = "192.168.10.50", "192.168.10.10"
        oid = "1.3.6.1.2.1.1.1.0"
        request = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src=manager, dst=agent)
            / UDP(sport=50100, dport=161)
            / SNMP(version=1, community="public", PDU=SNMPget(id=7, varbindlist=[SNMPvarbind(oid=oid)]))
        )
        response = (
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src=agent, dst=manager)
            / UDP(sport=161, dport=50100)
            / SNMP(
                version=1,
                community="public",
                PDU=SNMPresponse(id=7, varbindlist=[SNMPvarbind(oid=oid, value="Linux plc-01 5.10")]),
            )
        )
        request.time, response.time = 1609459200.0, 1609459200.01
        target = tmp_path / "snmp_poll.pcap"
        wrpcap(str(target), [request, response])
        return target

    def test_agent_response_does_not_make_the_agent_a_client(self, tmp_path) -> None:
        from pcapper.snmp import analyze_snmp

        summary = analyze_snmp(self._poll_pcap(tmp_path), show_status=False)
        assert summary.total_messages == 2
        assert summary.client_counts == {"192.168.10.50": 2}
        assert summary.server_counts == {"192.168.10.10": 2}
        assert len(summary.conversations) == 1
        conv = summary.conversations[0]
        assert (conv.client_ip, conv.server_ip, conv.server_port, conv.packets) == (
            "192.168.10.50", "192.168.10.10", 161, 2
        )
        assert "Linux plc-01 5.10" in summary.plaintext_strings
        assert not any("exfiltration" in str(d["summary"]) for d in summary.detections)
        assert any("Default SNMP community" in str(d["summary"]) for d in summary.detections)


# --- UDP ------------------------------------------------------------------------


class TestUdpRoles:
    def test_dns_reply_keeps_the_server_role_and_service_port(self, tmp_path) -> None:
        from scapy.all import wrpcap  # type: ignore
        from scapy.layers.dns import DNS, DNSQR, DNSRR  # type: ignore
        from scapy.layers.inet import IP, UDP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore

        from pcapper.udp import analyze_udp

        client, server = "192.168.10.50", "192.168.10.10"
        query = (
            Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            / IP(src=client, dst=server)
            / UDP(sport=50100, dport=53)
            / DNS(id=1, rd=1, qd=DNSQR(qname="www.example.net"))
        )
        reply = (
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / IP(src=server, dst=client)
            / UDP(sport=53, dport=50100)
            / DNS(id=1, qr=1, qd=DNSQR(qname="www.example.net"),
                  an=DNSRR(rrname="www.example.net", rdata="93.184.216.34"))
        )
        query.time, reply.time = 1609459200.0, 1609459200.02
        target = tmp_path / "dns_pair.pcap"
        wrpcap(str(target), [query, reply])
        summary = analyze_udp(target, show_status=False)
        assert summary.udp_packets == 2
        assert summary.client_counts == {client: 2}
        assert summary.server_counts == {server: 2}
        assert summary.port_counts == {53: 2}  # the ephemeral port is not a "top port"
        assert summary.duration_seconds == pytest.approx(0.02)


# --- TCP ------------------------------------------------------------------------


HTTP_PCAP = Path(__file__).parent / "data" / "http.pcap"


class TestTcpRoles:
    def test_handshake_assigns_roles_and_syn_ack_is_not_a_syn(self) -> None:
        from pcapper.tcp import analyze_tcp

        summary = analyze_tcp(HTTP_PCAP, show_status=False)
        client, server = "192.168.10.50", "93.184.216.34"
        assert summary.tcp_packets == 5  # SYN, SYN-ACK, ACK, request, response
        assert summary.client_counts == {client: 5}
        assert summary.server_counts == {server: 5}
        assert summary.port_counts == {80: 5}
        assert summary.syn_counts == {client: 1}  # the SYN-ACK is not a SYN from the server
        by_dir = {(c.src_ip, c.dst_ip): c for c in summary.conversations}
        assert by_dir[(server, client)].syn == 0 and by_dir[(server, client)].syn_ack == 1
        assert summary.retrans_timeseries == []  # ACK-then-data on the same seq is not a retransmission
        assert not any("SYN without SYN-ACK" in str(d["summary"]) for d in summary.detections)

    def test_real_retransmission_is_still_counted(self) -> None:
        from pcapper.tcp import analyze_tcp

        summary = analyze_tcp(MIXED_PCAP, show_status=False)  # request sent twice, same seq
        assert sum(summary.retrans_timeseries) == 1


# --- TCP segment length / beacon ---------------------------------------------------


class TestTcpSegmentLength:
    def test_padding_is_not_data(self) -> None:
        from scapy.layers.inet import IP, TCP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore

        syn = Ether(bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=445, flags="S")) + b"\x00" * 6)
        assert len(syn[TCP].payload) == 6  # scapy hangs the padding under TCP
        assert utils.tcp_segment_length(syn[TCP], syn[IP]) == 0

    def test_data_segment_length(self) -> None:
        from scapy.layers.inet import IP, TCP  # type: ignore
        from scapy.layers.l2 import Ether  # type: ignore
        from scapy.packet import Raw  # type: ignore

        seg = Ether(bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n")))
        assert utils.tcp_segment_length(seg[TCP], seg[IP]) == 18
        assert utils.tcp_segment_length(seg[TCP], None) is None


class TestBeacon:
    def test_runs_on_fixture_and_memoizes(self) -> None:
        from pcapper.beacon import analyze_beacons

        from scapy.all import rdpcap  # type: ignore

        utils.clear_analysis_memo()
        summary = analyze_beacons(MIXED_PCAP, show_status=False)
        assert summary.total_packets == len(rdpcap(str(MIXED_PCAP)))
        assert summary.errors == []
        assert analyze_beacons(MIXED_PCAP, show_status=False) is summary


# --- IPs ------------------------------------------------------------------------


class TestIps:
    def test_mixed_fixture_counts_and_memo(self) -> None:
        from pcapper.ips import analyze_ips

        utils.clear_analysis_memo()
        summary = analyze_ips(MIXED_PCAP, show_status=False)
        assert summary.errors == []
        assert summary.protocol_counts["ARP"] == 3
        assert summary.protocol_counts["ICMP"] == 7 and summary.protocol_counts["ICMPv6"] == 2
        assert summary.protocol_counts["UDP"] == 5 and summary.protocol_counts["TCP"] > 0
        assert summary.ipv6_count == 2
        assert analyze_ips(MIXED_PCAP, show_status=False) is summary

    def test_host_address_helpers(self) -> None:
        from pcapper.ips import _is_internal_host_address, _is_unicast_host_address

        assert _is_unicast_host_address("10.0.0.5")
        assert not _is_unicast_host_address("10.0.0.255")
        assert not _is_unicast_host_address("224.0.0.251")
        assert not _is_unicast_host_address("169.254.1.1")
        assert _is_internal_host_address("192.168.1.20")
        assert not _is_internal_host_address("93.184.216.34")
        assert not _is_internal_host_address("not-an-ip")

    def test_intel_urls_are_percent_encoded(self, monkeypatch) -> None:
        from pcapper import ips as ips_mod

        seen: list[str] = []
        monkeypatch.setattr(ips_mod, "_fetch_json", lambda url, headers, timeout=5.0: seen.append(url) or None)
        ips_mod._virustotal_lookup("1.2.3.4/../users", "k")
        ips_mod._otx_lookup("1.2.3.4?x=1", "k")
        assert "/ip_addresses/1.2.3.4%2F..%2Fusers" in seen[0]
        assert "/IPv4/1.2.3.4%3Fx%3D1/general" in seen[1]


# --- ARP ------------------------------------------------------------------------


class TestArpFrameTrailer:
    """Bytes after the ARP body are Padding to scapy, never Raw; the trailer
    extraction used to look for Raw and therefore never found anything."""

    @staticmethod
    def _arp_pcap(tmp_path: Path, trailer: bytes) -> Path:
        from scapy.all import wrpcap  # type: ignore
        from scapy.layers.l2 import ARP, Ether  # type: ignore

        frame = bytes(
            Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
            / ARP(op=2, hwsrc="02:00:00:00:00:02", psrc="192.168.10.10",
                  hwdst="02:00:00:00:00:01", pdst="192.168.10.50")
        )
        pkt = Ether(frame + trailer)
        pkt.time = 1609459200.0
        target = tmp_path / "arp_trailer.pcap"
        wrpcap(str(target), [pkt])
        return target

    def test_zero_padding_yields_nothing(self, tmp_path) -> None:
        from pcapper.arp import analyze_arp

        summary = analyze_arp(self._arp_pcap(tmp_path, b"\x00" * 18), show_status=False)
        assert summary.arp_packets == 1
        assert not summary.plaintext_observed and not summary.files_discovered

    def test_printable_trailer_is_reported(self, tmp_path) -> None:
        from pcapper.arp import analyze_arp

        summary = analyze_arp(
            self._arp_pcap(tmp_path, b"\x00\x00" + b"C:\\loot\\secret-doc.pdf" + b"\x00" * 4),
            show_status=False,
        )
        assert any("secret-doc.pdf" in token for token in summary.plaintext_observed)
        assert summary.files_discovered == ["secret-doc.pdf"]
        assert any(a.kind == "file" and a.detail == "secret-doc.pdf" for a in summary.artifacts)


# --- rendering ---------------------------------------------------------------------


class TestFormatTable:
    def test_ragged_rows_render_instead_of_raising(self) -> None:
        text = format_table([["A", "B", "C"], ["1"], ["1", "2", "3", "4"]])
        assert "A" in text and "4" in text


# --- CLI --------------------------------------------------------------------------


@pytest.mark.slow
class TestCliRejectsNonCapture:
    def test_pcap_extension_without_magic_exits_2(self, tmp_path) -> None:
        bogus = tmp_path / "evidence.pcap"
        bogus.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 64)
        proc = subprocess.run(
            [sys.executable, "-m", "pcapper", str(bogus), "--dns", "--quiet"],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=dict(os.environ, NO_COLOR="1", PYTHONIOENCODING="utf-8"),
            cwd=REPO, timeout=300,
        )
        assert proc.returncode == 2, proc.stdout[-500:]
        assert "not a pcap/pcapng capture" in proc.stderr
