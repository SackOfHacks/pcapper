from __future__ import annotations

from collections import Counter
from pathlib import Path

from pcapper.exfil import ExfilSummary
from pcapper.reporting import render_exfil_summary


def test_exfil_rendering_high_confidence_verdict_includes_reasons() -> None:
    summary = ExfilSummary(
        path=Path("fixture_exfil.pcap"),
        total_packets=1000,
        total_bytes=20_000_000,
        outbound_bytes=15_000_000,
        outbound_flows=[
            {
                "src": "10.0.0.5",
                "dst": "185.66.41.24",
                "proto": "TCP",
                "dst_port": 443,
                "packets": 120,
                "bytes": 10_000_000,
                "duration_seconds": 40.0,
                "bytes_per_second": 250_000.0,
            }
        ],
        internal_flows=[],
        ot_flows=[],
        top_external_dsts=Counter({"185.66.41.24": 12_000_000}),
        dns_tunnel_suspects=[{"src": "10.0.0.5", "total": 45, "unique": 42, "long": 18, "avg_entropy": 3.9, "max_label": 41}],
        http_post_suspects=[
            {
                "src": "10.0.0.5",
                "dst": "185.66.41.24",
                "host": "evil.example",
                "uri": "/upload",
                "bytes": 6_000_000,
                "requests": 9,
                "mode": "single",
                "content_type": "application/octet-stream",
            }
        ],
        file_artifacts=[],
        file_exfil_suspects=[
            {
                "src": "10.0.0.5",
                "dst": "185.66.41.24",
                "protocol": "HTTP",
                "filename": "archive.zip",
                "size": 5_500_000,
                "packet": 88,
                "file_type": "ZIP/Office",
                "risk_score": 6,
                "risk_reasons": ["private_to_public", "suspicious_ext=.zip", "size>=4.8 MB"],
            }
        ],
        protocol_exfil_checks={
            "dns": ["10.0.0.5 unique=42/45"],
            "http_https": ["POST 10.0.0.5->185.66.41.24 bytes=5.7 MB"],
            "icmp": [],
            "ftp": [],
            "smtp": [],
            "websockets": [],
            "ntp": [],
        },
        detections=[],
        artifacts=[],
        errors=[],
        first_seen=1.0,
        last_seen=90.0,
        duration_seconds=89.0,
    )

    output = render_exfil_summary(summary, verbose=False)

    assert "YES - exfiltration activity is likely occurring" in output
    assert "Analyst Verdict" in output
    assert "Confidence" in output
    assert "Reasons:" in output
    assert "Yes, there is evidence for DNS exfil" in output
    assert "Yes, there is evidence for HTTP/HTTPS exfil" in output
    assert "No, there is no strong evidence for ICMP exfil" in output


def test_exfil_rendering_no_strong_signal_verdict() -> None:
    summary = ExfilSummary(
        path=Path("fixture_clean.pcap"),
        total_packets=100,
        total_bytes=300_000,
        outbound_bytes=50_000,
        outbound_flows=[],
        internal_flows=[],
        ot_flows=[],
        top_external_dsts=Counter(),
        dns_tunnel_suspects=[],
        http_post_suspects=[],
        file_artifacts=[],
        file_exfil_suspects=[],
        protocol_exfil_checks={
            "dns": [],
            "http_https": [],
            "icmp": [],
            "ftp": [],
            "smtp": [],
            "websockets": [],
            "ntp": [],
        },
        detections=[],
        artifacts=[],
        errors=[],
        first_seen=1.0,
        last_seen=8.0,
        duration_seconds=7.0,
    )

    output = render_exfil_summary(summary, verbose=False)

    assert "NO STRONG SIGNAL" in output
    assert "No high-confidence exfiltration heuristic crossed its threshold" in output
