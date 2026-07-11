from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    append_public_exposure_anomaly,
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

ICCP_PORT = 102

# ICCP / TASE.2 (IEC 60870-6) runs MMS over COTP/TPKT on port 102 — the same
# stack as IEC 61850 MMS — so plain port/MMS detection cannot tell them apart.
# These TASE.2-specific object names (IEC 60870-6-503) appear as ASCII MMS
# ObjectName/ItemId strings and uniquely identify ICCP traffic.
TASE2_MARKERS = (
    b"Bilateral_Table_ID",
    b"TASE2_Version",
    b"Supported_Features",
    b"Transfer_Set",
    b"Next_DSTransfer_Set",
    b"DSTransfer_Set",
    b"DSConditions_Detected",
    b"Transfer_Report",
)
# TASE.2 Block 5 device-control object/keywords. A control operation on a
# bilaterally-agreed point is an unauthorized-command / manipulation risk.
TASE2_CONTROL_MARKERS = (b"Operate", b"SetTag", b"Command", b"Device")
MMS_WRITE_TAG = 0xA5  # MMS confirmed-request Write service (see mms.py).


def _looks_iccp(payload: bytes) -> bool:
    return any(m in payload for m in TASE2_MARKERS)


def _parse_commands(payload: bytes) -> list[str]:
    if not _looks_iccp(payload):
        return []
    cmds = ["ICCP/TASE.2"]
    if MMS_WRITE_TAG in payload:
        cmds.append("MMS Write")
    if any(m in payload for m in TASE2_CONTROL_MARKERS):
        cmds.append("TASE.2 Control Object")
    if b"Bilateral_Table_ID" in payload:
        cmds.append("Bilateral Table Access")
    return cmds


def _detect_anomalies(
    payload: bytes, src_ip: str, dst_ip: str, ts: float, commands: list[str]
) -> list[IndustrialAnomaly]:
    anomalies: list[IndustrialAnomaly] = []
    if not _looks_iccp(payload):
        return anomalies
    has_write = "MMS Write" in commands
    has_control = "TASE.2 Control Object" in commands
    if has_write and has_control:
        anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="ICCP/TASE.2 Control Command",
                description=(
                    "TASE.2 device-control write (Operate/SetTag) over ICCP — a "
                    "command to a bilaterally-agreed control point (e.g. breaker / "
                    "setpoint) between control centers. Confirm it is authorized."
                ),
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0855 Unauthorized Command Message; T0831 Manipulation of Control",
                evidence=[c for c in commands if c],
            )
        )
    elif has_write:
        anomalies.append(
            IndustrialAnomaly(
                severity="MEDIUM",
                title="ICCP/TASE.2 Write Operation",
                description="MMS Write over ICCP/TASE.2 (data / transfer-set modification).",
                src=src_ip,
                dst=dst_ip,
                ts=ts,
                attack="T0836 Modify Parameter",
                evidence=[c for c in commands if c],
            )
        )
    return anomalies


def analyze_iccp(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="ICCP/TASE.2",
        tcp_ports={ICCP_PORT},
        command_parser=_parse_commands,
        anomaly_detector=_detect_anomalies,
        enable_enrichment=True,
        show_status=show_status,
    )
    append_public_exposure_anomaly(analysis, "ICCP/TASE.2")
    return analysis
