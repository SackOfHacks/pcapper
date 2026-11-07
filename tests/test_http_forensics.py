from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

from pcapper.http import SUSPICIOUS_URI_RE, _normalize_host, analyze_http
import pcapper.http2 as http2


def test_suspicious_uri_matches_command_parameter_values() -> None:
    assert SUSPICIOUS_URI_RE.search("/index.php?cmd=whoami")
    assert SUSPICIOUS_URI_RE.search("/exec")
    assert not SUSPICIOUS_URI_RE.search("/execute")


def test_host_normalization_preserves_ipv6_literals() -> None:
    assert _normalize_host("[2001:db8::1]:8080") == "2001:db8::1"
    assert _normalize_host("EXAMPLE.COM:8080") == "example.com"


def test_file_discovery_errors_are_reported(tmp_path, monkeypatch) -> None:
    import pcapper.files

    def fail_file_discovery(*_args, **_kwargs):
        raise RuntimeError("fixture failure")

    monkeypatch.setattr(pcapper.files, "analyze_files", fail_file_discovery)

    result = analyze_http(tmp_path / "empty.pcap", packets=[], show_status=False)

    assert any(
        "HTTP file discovery failed: RuntimeError: fixture failure" in error
        for error in result.errors
    )


def test_http_state_caps_report_omitted_correlations_and_channels(
    tmp_path, monkeypatch
) -> None:
    import pcapper.http

    monkeypatch.setattr(pcapper.http, "MAX_HTTP_CHANNELS", 1)
    monkeypatch.setattr(pcapper.http, "MAX_HTTP_CONVERSATIONS", 1)
    capture = tmp_path / "http_state_limits.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820 + index, dport=80)
            / Raw(
                load=f"GET /resource{index} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
            )
            for index in range(2)
        ],
    )

    result = analyze_http(capture, show_status=False)

    assert any("pending-request flow cap reached" in error for error in result.errors)
    assert any("beacon-channel cap reached" in error for error in result.errors)


def test_http2_connection_tracking_is_bounded_and_reported(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(http2, "MAX_HTTP2_CONNECTIONS", 1)
    capture = tmp_path / "http2_connection_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src=f"10.0.0.{index + 1}", dst="10.0.0.10")
            / TCP(sport=51820 + index, dport=8080)
            / Raw(load=http2.HTTP2_PREFACE)
            for index in range(2)
        ],
    )

    result = http2.analyze_http2(capture, show_status=False)

    assert result.http2_packets == 1
    assert any("connection tracking limit" in error for error in result.errors)
