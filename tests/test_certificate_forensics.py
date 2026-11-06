from __future__ import annotations

from pathlib import Path

from scapy.all import rdpcap, wrpcap

import pcapper.certificates as certificates


def test_certificate_flow_buffer_limit_is_reported(tmp_path, monkeypatch) -> None:
    source = Path(__file__).parent / "data" / "tls.pcap"
    capture = tmp_path / "tls_certificate_flows.pcap"
    wrpcap(str(capture), rdpcap(str(source)))
    monkeypatch.setattr(certificates, "MAX_CERTIFICATE_FLOWS", 1)

    result = certificates.analyze_certificates(capture, show_status=False)

    assert any("Certificate flow limit reached" in error for error in result.errors)
