from __future__ import annotations

import ipaddress
from pathlib import Path

from .industrial_helpers import (
    IndustrialAnalysis,
    IndustrialAnomaly,
    analyze_port_protocol,
)

# Genisys — a master/slave polling SCADA protocol used in rail signaling and
# substation control (US&S / Alstom), carried over TCP (commonly port 10001).
# Port 10001 is not Genisys-exclusive, so this matches on the unambiguous frame
# shape instead. A Genisys message begins with a control byte (poll/ack/data:
# 0xF1/0xF2/0xFB/0xFD) and is terminated by a 0xF6 end-of-message delimiter that
# appears ONLY at the end (data 0xF6 bytes are escaped), and frames are small.
# These three properties together are specific enough to avoid the false matches
# that a bare "starts 0xF*, ends 0xF6" test produces on large binary payloads.
# Vendor framing has no authoritative public function map, so this is a presence
# + exposure detector.
GENISYS_PORT = 10001
_GENISYS_END = 0xF6
_GENISYS_START = {0xF1, 0xF2, 0xFB, 0xFD}
_GENISYS_MAX_LEN = 256


def _match_signature(payload: bytes) -> bool:
    return (
        3 <= len(payload) <= _GENISYS_MAX_LEN
        and payload[0] in _GENISYS_START
        and payload[-1] == _GENISYS_END
        and payload.count(_GENISYS_END) == 1
    )


def analyze_genisys(path: Path, show_status: bool = True) -> IndustrialAnalysis:
    analysis = analyze_port_protocol(
        path=path,
        protocol_name="Genisys",
        signature_matcher=_match_signature,
        enable_enrichment=True,
        show_status=show_status,
    )
    public_endpoints = []
    for ip_value in set(analysis.src_ips) | set(analysis.dst_ips):
        try:
            if ipaddress.ip_address(ip_value).is_global:
                public_endpoints.append(ip_value)
        except Exception:
            continue
    if public_endpoints and len(analysis.anomalies) < 200:
        analysis.anomalies.append(
            IndustrialAnomaly(
                severity="HIGH",
                title="Genisys Exposure to Public IP",
                description=(
                    "Genisys (rail/substation SCADA) traffic observed with public "
                    f"endpoint(s): {', '.join(sorted(public_endpoints)[:5])}."
                ),
                src="*",
                dst="*",
                ts=0.0,
            )
        )
    return analysis
