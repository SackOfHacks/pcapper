from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace

from pcapper.industrial_helpers import IndustrialAnalysis
from pcapper.overview import (
    OverviewSummary,
    _build_hunt_leads,
    _detect_ot_modules_from_ports,
    analyze_overview,
)
from pcapper.protocols import Conversation, Endpoint
from pcapper.reporting import render_overview_summary
from pcapper.services import ServiceAsset, ServiceSummary


def test_detect_ot_modules_from_ports_infers_s7_and_mqtt() -> None:
    protocols = SimpleNamespace(
        conversations=[
            Conversation(
                src="10.0.0.10",
                dst="10.0.0.20",
                protocol="Unknown",
                packets=12,
                bytes=9000,
                start_ts=1.0,
                end_ts=10.0,
                ports={102},
            ),
            Conversation(
                src="10.0.0.30",
                dst="10.0.0.40",
                protocol="Unknown",
                packets=8,
                bytes=6000,
                start_ts=2.0,
                end_ts=11.0,
                ports={1883},
            ),
        ]
    )
    services = SimpleNamespace(
        assets=[
            ServiceAsset(ip="10.0.0.10", port=102, protocol="TCP", service_name="S7"),
            ServiceAsset(ip="10.0.0.30", port=1883, protocol="TCP", service_name="MQTT"),
        ]
    )

    detected = _detect_ot_modules_from_ports(protocols, services)

    assert detected.get("s7") == [102]
    assert detected.get("mqtt") == [1883]


def test_build_hunt_leads_marks_ot_boundary_host_with_s7comm_marker() -> None:
    ip_activity = [
        {
            "ip": "10.0.0.10",
            "packets_sent": 40,
            "packets_recv": 34,
            "packets_total": 74,
            "bytes_total": 4096,
            "peer_count": 2,
            "public_peer_count": 1,
            "top_ports": [102],
            "top_protocols": ["S7comm"],
            "services_hosted": ["S7"],
            "services_used": [],
            "service_count": 1,
            "first_seen": 1.0,
            "last_seen": 30.0,
        }
    ]

    leads = _build_hunt_leads(
        ip_activity=ip_activity,
        notable_flows=[],
        module_results=[],
        ot_markers=["s7", "s7comm"],
        limit=8,
    )

    assert any(
        str(item.get("finding", "")) == "OT/ICS-speaking host communicating across boundary"
        for item in leads
    )


def test_analyze_overview_adds_ot_iot_cross_zone_context(
    monkeypatch, tmp_path: Path
) -> None:
    pcap_path = tmp_path / "overview_test.pcap"
    pcap_path.write_bytes(b"")

    protocol_summary = SimpleNamespace(
        top_protocols=[("S7comm", 140), ("MQTT", 55)],
        port_protocols=[("S7/MMS/ICCP", 140), ("MQTT", 55)],
        conversations=[
            Conversation(
                src="10.0.0.10",
                dst="8.8.8.8",
                protocol="S7comm",
                packets=140,
                bytes=4_000_000,
                start_ts=1.0,
                end_ts=120.0,
                ports={102},
            ),
            Conversation(
                src="10.0.0.10",
                dst="10.0.0.30",
                protocol="MQTT",
                packets=55,
                bytes=250_000,
                start_ts=5.0,
                end_ts=119.0,
                ports={1883},
            ),
        ],
        endpoints=[
            Endpoint(
                address="10.0.0.10",
                packets_sent=180,
                packets_recv=35,
                bytes_sent=4_500_000,
                bytes_recv=400_000,
                protocols={"S7comm", "MQTT"},
            ),
            Endpoint(
                address="8.8.8.8",
                packets_sent=20,
                packets_recv=160,
                bytes_sent=200_000,
                bytes_recv=4_100_000,
                protocols={"S7comm"},
            ),
        ],
        anomalies=[],
        errors=[],
        analyst_verdict="",
    )

    services_summary = ServiceSummary(
        path=pcap_path,
        total_services=2,
        assets=[
            ServiceAsset(
                ip="10.0.0.10",
                port=102,
                protocol="TCP",
                service_name="S7",
                packets=140,
                bytes=4_000_000,
                clients={"8.8.8.8"},
                first_seen=1.0,
                last_seen=120.0,
            ),
            ServiceAsset(
                ip="10.0.0.30",
                port=1883,
                protocol="TCP",
                service_name="MQTT",
                packets=55,
                bytes=250_000,
                clients={"10.0.0.10"},
                first_seen=5.0,
                last_seen=119.0,
            ),
        ],
        risks=[],
        hierarchy={"S7": 1, "MQTT": 1},
        errors=[],
    )

    monkeypatch.setattr(
        "pcapper.overview.analyze_pcap",
        lambda _path, show_status=True: SimpleNamespace(
            packet_count=250,
            duration_seconds=120.0,
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_protocols",
        lambda _path, show_status=True: protocol_summary,
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_services",
        lambda _path, show_status=True: services_summary,
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_threats",
        lambda _path, show_status=True, vt_lookup=False: SimpleNamespace(
            detections=[],
            errors=[],
            ot_risk_score=0,
            ot_risk_findings=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_scan",
        lambda _path, show_status=True: SimpleNamespace(
            scan_sources=[],
            scanner_count=0,
            errors=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_ctf",
        lambda _path, show_status=True: SimpleNamespace(
            hits=[],
            decoded_hits=[],
            candidate_findings=[],
            errors=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_ot_commands",
        lambda _path, show_status=True, fast=False, config=None: SimpleNamespace(
            command_counts=Counter({"WriteVar": 12}),
            control_rate_per_min=12.5,
            control_burst_max=7,
            errors=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_safety",
        lambda _path, show_status=True: SimpleNamespace(
            hits=[],
            service_counts=Counter(),
            errors=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_s7",
        lambda _path, show_status=True: IndustrialAnalysis(
            path=pcap_path,
            protocol_packets=140,
            requests=10,
            responses=10,
            commands=Counter({"WriteVar": 5}),
            anomalies=[],
            errors=[],
        ),
    )
    monkeypatch.setattr(
        "pcapper.overview.analyze_mqtt",
        lambda _path, show_status=True: IndustrialAnalysis(
            path=pcap_path,
            protocol_packets=55,
            requests=8,
            responses=8,
            commands=Counter({"PUBLISH": 8}),
            anomalies=[],
            errors=[],
        ),
    )

    summary = analyze_overview(pcap_path, show_status=False)

    assert "s7" in summary.modules_run
    assert "mqtt" in summary.modules_run
    assert summary.summary_details.get("cross_zone_ot_iot_flows", 0) >= 1
    assert summary.summary_details.get("iot_family_count", 0) >= 1
    assert any(
        "IoT messaging protocols detected" in rec for rec in summary.recommendations
    )
    assert any(
        str(item.get("finding", "")) == "OT/ICS-speaking host communicating across boundary"
        for item in summary.hunt_leads
    )


def test_render_overview_includes_detected_devices_information_section() -> None:
    summary = OverviewSummary(
        path=Path("sample.pcap"),
        total_packets=100,
        duration_seconds=60.0,
        top_protocols=[("S7comm", 60)],
        top_services=[("S7", 1)],
        observed_ips=[],
        observed_protocols=[("S7comm", 60)],
        observed_services=[("S7", 1)],
        summary_details={"cross_zone_ot_iot_flows": 1},
        ot_protocols=["Siemens S7", "MQTT"],
        modules_run=[],
        module_results=[],
        ot_highlights=[],
        hunt_highlights=[],
        forensics_highlights=[],
        ctf_highlights=[],
        recommendations=[],
        errors=[],
        capture_start=1.0,
        capture_end=60.0,
        ip_activity=[
            {
                "ip": "10.0.0.10",
                "scope": "internal",
                "role": "service-host",
                "activity": "hosts S7",
                "packets_sent": 45,
                "packets_recv": 15,
                "packets_total": 60,
                "bytes_sent": 4000,
                "bytes_recv": 2000,
                "bytes_total": 6000,
                "first_seen": 1.0,
                "last_seen": 60.0,
                "peer_count": 1,
                "top_protocols": ["S7comm", "MQTT"],
                "top_peers": ["10.0.0.20(60)"],
                "top_ports": [102, 1883],
                "services_hosted": ["S7", "MQTT"],
                "services_used": [],
            }
        ],
        protocol_activity=[],
        service_activity=[],
        notable_flows=[],
        hunt_leads=[],
    )

    rendered = render_overview_summary(summary)

    assert "Detected Devices Information" in rendered
    assert "OT/ICS Device" in rendered
