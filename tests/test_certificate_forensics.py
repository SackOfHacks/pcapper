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


def test_expiry_is_judged_at_capture_time(tmp_path) -> None:
    """A certificate valid when it was presented is not an "expired"
    finding because it lapsed later; one already past not-after at the
    packet time is."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    from pcapper.certificates import analyze_certificates

    def tls_certificate_record(not_after: dt.datetime) -> bytes:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "c2.example")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1234).not_valid_before(dt.datetime(2016, 1, 1, tzinfo=dt.timezone.utc))
                .not_valid_after(not_after).sign(key, hashes.SHA256()))
        der = cert.public_bytes(serialization.Encoding.DER)
        certs = len(der).to_bytes(3, "big") + der
        body = len(certs).to_bytes(3, "big") + certs
        handshake = b"\x0b" + len(body).to_bytes(3, "big") + body
        return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake

    capture_time = dt.datetime(2017, 6, 12, tzinfo=dt.timezone.utc).timestamp()
    results = {}
    for label, not_after in (("valid-then", dt.datetime(2018, 6, 7, tzinfo=dt.timezone.utc)),
                             ("lapsed-then", dt.datetime(2017, 1, 1, tzinfo=dt.timezone.utc))):
        pkt = Ether() / IP(src="198.51.100.7", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="PA") / Raw(
            load=tls_certificate_record(not_after))
        pkt.time = capture_time
        capture = tmp_path / f"{label}.pcap"
        wrpcap(str(capture), [pkt])
        summary = analyze_certificates(capture, show_status=False)
        assert summary.cert_count == 1, label
        results[label] = [e["reason"] for e in summary.expired]
    assert results == {"valid-then": [], "lapsed-then": ["expired"]}
