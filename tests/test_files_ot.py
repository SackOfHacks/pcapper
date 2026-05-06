from __future__ import annotations

from pathlib import Path

import pytest

from pcapper.files import (
    FileArtifact,
    FileTransferSummary,
    _append_ot_transfer_detections,
    _scan_s7_program_transfers,
    analyze_files,
)
from pcapper import files as files_module
from pcapper.reporting import render_files_summary


def _wrap_tpkt(cotp_payload: bytes) -> bytes:
    total = 4 + len(cotp_payload)
    return b"\x03\x00" + total.to_bytes(2, "big") + cotp_payload


def _build_cotp_dt(s7_payload: bytes) -> bytes:
    return b"\x02\xF0\x80" + s7_payload


def _build_s7_job(pdu_ref: int, param: bytes) -> bytes:
    header = b"\x32\x01\x00\x00" + pdu_ref.to_bytes(2, "big")
    header += len(param).to_bytes(2, "big") + b"\x00\x00"
    return header + param


def _build_enip_frame(command: int, payload: bytes) -> bytes:
    header = command.to_bytes(2, "little")
    header += len(payload).to_bytes(2, "little")
    header += b"\x00" * 20
    return header + payload


def _build_cip_file_object_download_request(data: bytes) -> bytes:
    path = b"\x20\x37\x24\x01"  # Class 0x37 (File Object), Instance 0x01
    return bytes([0x4C, len(path) // 2]) + path + data


def _write_single_tcp_payload_pcap(
    path: Path,
    *,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    payload: bytes,
) -> None:
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.packet import Raw  # type: ignore
    from scapy.utils import wrpcap  # type: ignore

    pkt = (
        IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags="PA", seq=1, ack=1)
        / Raw(load=payload)
    )
    wrpcap(str(path), [pkt])


def test_scan_s7_program_transfers_detects_request_download() -> None:
    payload = _wrap_tpkt(_build_cotp_dt(_build_s7_job(1, bytes([0x1A, 0x00]))))

    events = _scan_s7_program_transfers(payload)

    assert len(events) == 1
    assert events[0]["function"] == "RequestDownload"
    assert events[0]["direction"] == "download"


def test_append_ot_transfer_detections_flags_firmware_and_plc_downloads() -> None:
    artifacts = [
        FileArtifact(
            protocol="ENIP",
            src_ip="10.1.1.10",
            dst_ip="10.1.1.20",
            src_port=44818,
            dst_port=44818,
            filename="enip_programdownload_100.bin",
            size_bytes=8192,
            packet_index=100,
            note="ENIP/CIP ProgramDownload payload (request)",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="TFTP",
            src_ip="10.1.1.30",
            dst_ip="10.1.1.40",
            src_port=54123,
            dst_port=69,
            filename="controller_firmware_v3.hex",
            size_bytes=4096,
            packet_index=200,
            note="TFTP upload data",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="HTTP",
            src_ip="10.1.1.70",
            dst_ip="10.1.1.80",
            src_port=80,
            dst_port=54000,
            filename="device_firmware_update.img",
            size_bytes=16384,
            packet_index=250,
            note="HTTP download payload",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="S7",
            src_ip="10.1.1.50",
            dst_ip="10.1.1.60",
            src_port=102,
            dst_port=102,
            filename="s7_requestdownload_download_300_1.bin",
            size_bytes=480,
            packet_index=300,
            note="S7 PLC program download command (RequestDownload)",
            file_type="BINARY",
        ),
    ]

    detections = _append_ot_transfer_detections(artifacts, [])
    summary_map = {str(item.get("summary", "")): item for item in detections}

    assert "OT firmware transfer activity observed" in summary_map
    assert "PLC program download activity observed" in summary_map

    firmware = summary_map["OT firmware transfer activity observed"]
    assert "downloads=1" in str(firmware.get("details", ""))
    assert "uploads=1" in str(firmware.get("details", ""))

    plc = summary_map["PLC program download activity observed"]
    assert plc.get("severity") == "high"


def test_append_ot_transfer_detections_flags_cip_file_object_services() -> None:
    artifacts = [
        FileArtifact(
            protocol="ENIP",
            src_ip="10.2.0.10",
            dst_ip="10.2.0.20",
            src_port=44818,
            dst_port=44818,
            filename="enip_FileObjectInitiateDownload_download_aaa111.bin",
            size_bytes=2048,
            packet_index=101,
            note="ENIP/CIP FileObjectInitiateDownload payload (request)",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="ENIP",
            src_ip="10.2.0.20",
            dst_ip="10.2.0.10",
            src_port=44818,
            dst_port=44818,
            filename="enip_FileObjectUploadTransfer_response_bbb222.bin",
            size_bytes=4096,
            packet_index=102,
            note="ENIP/CIP FileObjectUploadTransfer payload (response)",
            file_type="BINARY",
        ),
    ]

    detections = _append_ot_transfer_detections(artifacts, [])
    summary_map = {str(item.get("summary", "")): item for item in detections}

    assert "CIP File Object transfer activity observed" in summary_map
    cip_detection = summary_map["CIP File Object transfer activity observed"]
    details = str(cip_detection.get("details", ""))
    assert "Downloads=1" in details
    assert "uploads=1" in details


def test_append_ot_transfer_detections_flags_vendor_program_signatures() -> None:
    artifacts = [
        FileArtifact(
            protocol="FTP",
            src_ip="10.3.1.10",
            dst_ip="10.3.1.20",
            src_port=21,
            dst_port=51000,
            filename="line_a_logic.acd",
            size_bytes=8192,
            packet_index=201,
            note="FTP download data",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="SMB2",
            src_ip="10.3.1.30",
            dst_ip="10.3.1.40",
            src_port=445,
            dst_port=55344,
            filename="cell_b_project.s7p",
            size_bytes=12288,
            packet_index=202,
            note="SMB2 write data",
            file_type="BINARY",
        ),
        FileArtifact(
            protocol="HTTP",
            src_ip="10.3.1.50",
            dst_ip="10.3.1.60",
            src_port=80,
            dst_port=54200,
            filename="packaging_line.gxw",
            size_bytes=9216,
            packet_index=203,
            note="HTTP upload payload",
            file_type="BINARY",
        ),
    ]

    detections = _append_ot_transfer_detections(artifacts, [])
    summary_map = {str(item.get("summary", "")): item for item in detections}

    assert "Vendor PLC program transfer signatures observed" in summary_map
    vendor_detection = summary_map["Vendor PLC program transfer signatures observed"]
    details = str(vendor_detection.get("details", ""))
    assert "Rockwell/Allen-Bradley=1" in details
    assert "Siemens=1" in details
    assert "Mitsubishi MELSEC=1" in details


def test_append_ot_transfer_detections_ignores_generic_http_web_assets() -> None:
    artifacts = [
        FileArtifact(
            protocol="HTTP",
            src_ip="204.79.197.200",
            dst_ip="10.10.110.131",
            src_port=80,
            dst_port=51234,
            filename="37177be5.js",
            size_bytes=1024,
            packet_index=1,
            note="HTTP Response Body",
            file_type="UNKNOWN",
            content_type="application/javascript",
        ),
        FileArtifact(
            protocol="HTTP",
            src_ip="204.79.197.200",
            dst_ip="10.10.110.131",
            src_port=80,
            dst_port=51235,
            filename="SharedSpriteDesktop_0317.png",
            size_bytes=2048,
            packet_index=2,
            note="HTTP Response Body",
            file_type="PNG",
            content_type="image/png",
        ),
        FileArtifact(
            protocol="HTTP",
            src_ip="52.237.223.38",
            dst_ip="10.10.110.131",
            src_port=80,
            dst_port=51236,
            filename="trans.gif",
            size_bytes=256,
            packet_index=3,
            note="HTTP Response Body",
            file_type="GIF",
            content_type="image/gif",
        ),
    ]

    detections = _append_ot_transfer_detections(artifacts, [])
    summaries = {str(item.get("summary", "")) for item in detections}

    assert "OT firmware transfer activity observed" not in summaries


def test_render_files_summary_shows_ot_detection_evidence() -> None:
    summary = FileTransferSummary(
        path=Path("sample.pcap"),
        total_candidates=0,
        candidates=[],
        artifacts=[],
        extracted=[],
        views=[],
        detections=[
            {
                "severity": "warning",
                "summary": "OT firmware transfer activity observed",
                "details": "Firmware downloads=1 uploads=1.",
                "source": "Files",
                "top_sources": [("10.1.1.10", 1)],
                "top_destinations": [("10.1.1.20", 1)],
                "evidence": ["ENIP enip_programdownload_100.bin 10.1.1.10->10.1.1.20"],
            }
        ],
        errors=[],
    )

    rendered = render_files_summary(summary, verbose=False)

    assert "OT firmware transfer activity observed" in rendered
    assert "Top Sources:" in rendered
    assert "Top Destinations:" in rendered
    assert "Evidence:" in rendered


def test_render_files_summary_collapses_duplicates_for_all_pcaps() -> None:
    duplicate = FileArtifact(
        protocol="HTTP",
        src_ip="10.10.110.2",
        dst_ip="10.10.110.1",
        src_port=80,
        dst_port=49210,
        filename="status_logs_filter_dynamic.php",
        size_bytes=35,
        packet_index=35,
        note="HTTP Response Body",
        file_type="BINARY",
        hostname="10.10.110.2",
        content_type="text/html; charset=UTF-8",
    )
    summary = FileTransferSummary(
        path=Path("ALL_PCAPS"),
        total_candidates=0,
        candidates=[],
        artifacts=[duplicate, duplicate, duplicate],
        extracted=[],
        views=[],
        detections=[],
        errors=[],
    )

    rendered = render_files_summary(summary, verbose=False)

    assert "Summarized view collapsed 2 duplicate artifact row(s)" in rendered
    assert "HTTP Response Body [x3]" in rendered


def test_analyze_files_ot_s7_supports_extract_view_and_raw(tmp_path: Path) -> None:
    if files_module.dpkt is None:
        pytest.skip("dpkt unavailable")
    pcap_path = tmp_path / "s7_ot_files.pcap"
    payload = _wrap_tpkt(_build_cotp_dt(_build_s7_job(7, bytes([0x1A, 0x00]))))
    _write_single_tcp_payload_pcap(
        pcap_path,
        src_ip="10.10.1.10",
        dst_ip="10.10.1.20",
        sport=20000,
        dport=102,
        payload=payload,
    )

    out_dir = tmp_path / "extracted"
    summary = analyze_files(
        pcap_path,
        extract_name="s7_requestdownload",
        output_dir=out_dir,
        view_name="s7_requestdownload",
        view_raw=True,
        show_status=False,
    )

    assert summary.extracted
    assert summary.views
    assert summary.views[0]["raw"] is True
    extracted_bytes = summary.extracted[0].read_bytes()
    assert extracted_bytes.startswith(b"\x03\x00")
    assert bytes(summary.views[0]["payload"]).startswith(b"\x03\x00")


def test_analyze_files_ot_cip_file_object_supports_extract_view_and_raw(
    tmp_path: Path,
) -> None:
    if files_module.dpkt is None:
        pytest.skip("dpkt unavailable")
    pcap_path = tmp_path / "enip_file_object_ot_files.pcap"
    cip_payload = _build_cip_file_object_download_request(b"A" * 96)
    enip_payload = _build_enip_frame(0x006C, cip_payload)
    _write_single_tcp_payload_pcap(
        pcap_path,
        src_ip="10.20.1.10",
        dst_ip="10.20.1.20",
        sport=44818,
        dport=44818,
        payload=enip_payload,
    )

    out_dir = tmp_path / "extracted"
    summary = analyze_files(
        pcap_path,
        extract_name="fileobjectinitiatedownload",
        output_dir=out_dir,
        view_name="fileobjectinitiatedownload",
        view_raw=True,
        show_status=False,
    )

    assert summary.extracted
    assert summary.views
    assert summary.views[0]["raw"] is True
    view_payload = bytes(summary.views[0]["payload"])
    assert b"\x4c\x02\x20\x37\x24\x01" in view_payload
    assert any(
        str(item.get("summary", "")) == "CIP File Object transfer activity observed"
        for item in summary.detections
    )
