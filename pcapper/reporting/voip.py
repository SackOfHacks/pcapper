"""Rendered output for phone-over-IP analysis.

Ordered the way a VoIP investigation actually runs: what protocols are present,
who called whom, what was recovered from it, then the media quality detail.
"""

from __future__ import annotations

from ..coloring import danger, header, label, muted, ok, warn
from ..utils import format_bytes_as_mb, format_duration, format_ts
from ..voip import VoipSummary
from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _redact_in_text,
    _render_deterministic_checks,
    _render_protocol_verdict,
    _truncate_text,
    _verbose_output,
)

CHECK_LABELS = [
    ("voip_scanning_or_enumeration", "Scanning / extension enumeration"),
    ("voip_authentication_attacks", "Authentication attack"),
    ("voip_credential_exposure", "Credential exposure"),
    ("voip_provisioning_exposure", "Provisioning exposure"),
    ("voip_media_key_exposure", "Media key exposure"),
    ("voip_toll_fraud_indicators", "Toll-fraud indicators"),
    ("voip_registration_hijack", "Registration hijacking"),
    ("voip_unsignaled_or_hijacked_media", "Unsignalled / hijacked media"),
    ("voip_dtmf_or_sensitive_digits", "Sensitive digits / content"),
    ("voip_internet_exposure", "Internet exposure"),
    ("voip_transport_or_dos_abuse", "Transport hygiene / DoS"),
]


def render_voip_summary(
    summary: VoipSummary, limit: int = 12, verbose: bool = False
) -> str:
    if not summary:
        return ""
    effective_verbose = _verbose_output() or verbose
    row_limit = _limit_value(limit)

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"VOIP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines,
        label="VoIP",
        detections=getattr(summary, "detections", None),
        anomalies=getattr(summary, "anomalies", None),
    )

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors[: _limit_value(8)]:
            lines.append(danger(f"- {err}"))

    if summary.analysis_notes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes[: _limit_value(8)]:
            lines.append(muted(f"- {note}"))

    # --- overview ------------------------------------------------------------
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("Signalling Packets", str(summary.signaling_packets)))
    lines.append(_format_kv("RTP Packets", str(summary.rtp_packets)))
    if summary.rtp_bytes:
        lines.append(_format_kv("RTP Bytes", format_bytes_as_mb(summary.rtp_bytes)))
    if summary.rtcp_packets:
        lines.append(_format_kv("RTCP Packets", str(summary.rtcp_packets)))
    if summary.stun_packets:
        lines.append(_format_kv("STUN/TURN Packets", str(summary.stun_packets)))
    if summary.t38_packets:
        lines.append(_format_kv("T.38 Fax Packets", str(summary.t38_packets)))
    if summary.duration_seconds is not None:
        lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    lines.append(_format_kv("Calls / Dialogs", str(len(summary.calls))))
    lines.append(_format_kv("Registrations", str(len(summary.registrations))))

    if not summary.protocols:
        lines.append(muted("No phone-over-IP traffic identified in this capture."))
        lines.append(SECTION_BAR)
        return _finalize_output(lines)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocols Observed"))
    lines.append(
        _counter_table(
            summary.protocols, "Protocol", limit=row_limit, count_label="Packets"
        )
    )

    if summary.transport_counts:
        lines.append(
            _format_kv(
                "SIP Transport",
                ", ".join(
                    f"{name} ({count})"
                    for name, count in sorted(summary.transport_counts.items())
                ),
            )
        )
    if summary.server_ports:
        lines.append(
            _format_kv(
                "Signalling Ports",
                ", ".join(
                    f"{port} ({count})"
                    for port, count in summary.server_ports.most_common(row_limit)
                ),
            )
        )

    # --- calls ---------------------------------------------------------------
    if summary.calls:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Calls / Dialogs"))
        rows = [["Time", "Proto", "From", "To", "Disposition", "Dur", "Auth"]]
        for call in summary.calls[:row_limit]:
            rows.append(
                [
                    format_ts(call.first_seen),
                    call.protocol,
                    _truncate_text(call.from_user or call.caller_ip or "-", 26),
                    _truncate_text(call.to_user or call.callee_ip or "-", 26),
                    call.disposition,
                    (
                        f"{call.duration_seconds:.1f}s"
                        if call.duration_seconds is not None
                        else "-"
                    ),
                    "yes" if call.authenticated else ("chal" if call.challenged else "no"),
                ]
            )
        lines.append(_format_table(rows))
        if len(summary.calls) > row_limit:
            lines.append(muted(f"(+{len(summary.calls) - row_limit} more dialogs)"))
        for call in summary.calls[:row_limit]:
            if call.dtmf:
                lines.append(
                    warn(f"  {call.call_id[:40]} keypad digits: {call.dtmf}")
                )

    # --- registrations -------------------------------------------------------
    if summary.registrations:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Registrations"))
        rows = [["Proto", "Account", "Attempts", "OK", "Chal", "Fail", "Source IPs"]]
        for reg in summary.registrations[:row_limit]:
            rows.append(
                [
                    reg.protocol,
                    _truncate_text(reg.aor, 40),
                    str(reg.attempts),
                    str(reg.successes),
                    str(reg.challenges),
                    str(reg.failures),
                    _truncate_text(", ".join(reg.source_ips), 34),
                ]
            )
        lines.append(_format_table(rows))

    # --- credentials ---------------------------------------------------------
    # Deliberately unredacted: recovering these is the point of the tool, and
    # the output directory is written owner-only for exactly this reason.
    if summary.credentials:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Recovered Credentials"))
        lines.append(
            danger(
                f"{len(summary.credentials)} credential(s) recovered in cleartext "
                "signalling — treat this output as evidence."
            )
        )
        rows = [["Time", "Proto", "Context", "User", "Realm", "Src -> Dst"]]
        for cred in summary.credentials[:row_limit]:
            rows.append(
                [
                    format_ts(cred.ts),
                    cred.protocol,
                    _truncate_text(cred.context, 18),
                    _truncate_text(cred.username or "-", 22),
                    _truncate_text(cred.realm or "-", 20),
                    f"{cred.src_ip} -> {cred.dst_ip}",
                ]
            )
        lines.append(_format_table(rows))
        if len(summary.credentials) > row_limit:
            lines.append(
                muted(f"(+{len(summary.credentials) - row_limit} more credentials)")
            )
        crackable = [c.crackable for c in summary.credentials if c.crackable]
        if crackable:
            modes = sorted({c.protocol for c in summary.credentials if c.crackable})
            hint = (
                " — SIP lines are hashcat -m 11400"
                if "SIP" in modes
                else ""
            )
            lines.append(label(f"Crack-ready material ({', '.join(modes)}){hint}:"))
            shown = crackable if effective_verbose else crackable[:3]
            for line in shown:
                lines.append(muted(f"  {line}"))
            if not effective_verbose and len(crackable) > 3:
                lines.append(
                    muted(f"  (+{len(crackable) - 3} more; -v for all, or --json)")
                )

    # --- keypad digits -------------------------------------------------------
    if summary.dtmf:
        lines.append(SUBSECTION_BAR)
        lines.append(header("DTMF Keypad Digits"))
        lines.append(
            warn(
                "Digits pressed during calls. Frequently IVR PINs, calling-card "
                "numbers, account numbers or card data."
            )
        )
        rows = [["Carrier", "Source", "Destination", "Stream", "Digits"]]
        for entry in summary.dtmf[:row_limit]:
            rows.append(
                [
                    entry.protocol,
                    _truncate_text(entry.source, 24),
                    _truncate_text(entry.destination, 24),
                    _truncate_text(entry.stream, 14),
                    entry.digits,
                ]
            )
        lines.append(_format_table(rows))

    # --- media ---------------------------------------------------------------
    if summary.rtp_streams:
        lines.append(SUBSECTION_BAR)
        lines.append(header("RTP Streams"))
        rows = [
            ["Source", "Destination", "SSRC", "Codec", "Pkts", "Loss", "Jitter", "Flags"]
        ]
        for stream in summary.rtp_streams[:row_limit]:
            flags = []
            if stream.encrypted:
                flags.append("SRTP")
            if not stream.signaled:
                flags.append("unsignalled")
            if stream.dtmf_digits:
                flags.append("DTMF")
            if stream.audio_path:
                flags.append("wav")
            rows.append(
                [
                    f"{stream.src_ip}:{stream.src_port}",
                    f"{stream.dst_ip}:{stream.dst_port}",
                    f"0x{stream.ssrc:08x}",
                    stream.codec,
                    str(stream.packets),
                    f"{stream.loss_percent}%",
                    f"{stream.jitter_ms:.1f}ms",
                    ",".join(flags) or "-",
                ]
            )
        lines.append(_format_table(rows))
        if len(summary.rtp_streams) > row_limit:
            lines.append(
                muted(f"(+{len(summary.rtp_streams) - row_limit} more streams)")
            )

    if summary.media:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Negotiated Media (SDP)"))
        rows = [["Type", "Profile", "Endpoint", "Direction", "Codecs", "Keying"]]
        for entry in summary.media[:row_limit]:
            if entry.cleartext_keys:
                keying = danger("CLEARTEXT KEY")
            elif entry.dtls_fingerprint:
                keying = "DTLS-SRTP"
            elif entry.crypto_suites:
                keying = "SDES"
            else:
                keying = "none"
            rows.append(
                [
                    entry.media_type,
                    entry.transport or "-",
                    f"{entry.address}:{entry.port}",
                    entry.direction,
                    _truncate_text(", ".join(entry.codecs), 30),
                    keying,
                ]
            )
        lines.append(_format_table(rows))
        keyed = [m for m in summary.media if m.cleartext_keys]
        if keyed:
            lines.append(
                danger(
                    "SRTP master keys were sent in the clear (a=crypto inline). "
                    "Anyone who captured this traffic can decrypt the media:"
                )
            )
            for entry in keyed[: _limit_value(4)]:
                lines.append(
                    muted(
                        f"  {entry.address}:{entry.port} "
                        f"{entry.crypto_suites[0] if entry.crypto_suites else '?'} "
                        f"inline:{entry.cleartext_keys[0]}"
                    )
                )

    if summary.extracted_audio:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Extracted Audio"))
        for item in summary.extracted_audio[: _limit_value(10)]:
            lines.append(ok(f"- {item}"))

    # --- endpoints and identity ---------------------------------------------
    if summary.devices:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Devices / Endpoints"))
        lines.append(
            _counter_table(
                summary.devices, "Identity", limit=row_limit, count_label="Seen"
            )
        )
    if summary.user_agents or summary.servers:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Software Fingerprints"))
        if summary.user_agents:
            lines.append(
                _counter_table(
                    summary.user_agents,
                    "User-Agent",
                    limit=row_limit,
                    count_label="Msgs",
                )
            )
        if summary.servers:
            lines.append(
                _counter_table(
                    summary.servers, "Server", limit=row_limit, count_label="Msgs"
                )
            )
    if summary.rtcp_cnames:
        lines.append(
            _format_kv(
                "RTCP CNAMEs",
                ", ".join(
                    f"{name} ({count})"
                    for name, count in summary.rtcp_cnames.most_common(row_limit)
                ),
            )
        )
    if summary.stun_mapped_addresses:
        lines.append(SUBSECTION_BAR)
        lines.append(header("STUN / TURN"))
        lines.append(
            _counter_table(
                summary.stun_mapped_addresses,
                "Attribute",
                limit=row_limit,
                count_label="Seen",
            )
        )
    if summary.enum_lookups:
        lines.append(
            _format_kv(
                "ENUM Lookups",
                ", ".join(sorted(summary.enum_lookups)[:row_limit]),
            )
        )

    # --- numbers -------------------------------------------------------------
    if summary.to_users:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Dialled / Called Parties"))
        lines.append(
            _counter_table(
                summary.to_users, "Called", limit=row_limit, count_label="Calls"
            )
        )
    if summary.from_users:
        lines.append(
            _counter_table(
                summary.from_users, "Caller", limit=row_limit, count_label="Calls"
            )
        )

    # --- provisioning --------------------------------------------------------
    if summary.provisioning:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Phone Provisioning Fetches"))
        rows = [["Transport", "Client", "Server", "File", "Classification"]]
        for entry in summary.provisioning[:row_limit]:
            rows.append(
                [
                    entry.transport,
                    entry.client_ip,
                    entry.server_ip,
                    _truncate_text(entry.filename, 40),
                    entry.classification or "-",
                ]
            )
        lines.append(_format_table(rows))
        lines.append(
            muted(
                "Phone configuration files carry the SIP account password in "
                "cleartext; TFTP requires no authentication to fetch them."
            )
        )

    # --- in-band content -----------------------------------------------------
    if summary.messages:
        lines.append(SUBSECTION_BAR)
        lines.append(header("In-Band Messages"))
        for message in summary.messages[: _limit_value(8)]:
            lines.append(
                muted(
                    f"{format_ts(message.ts)} [{message.protocol} {message.kind}] "
                    f"{message.src_ip} -> {message.dst_ip}: "
                    f"{_redact_in_text(_truncate_text(message.body, 120))}"
                )
            )

    # --- findings ------------------------------------------------------------
    detections = _filtered_detections(summary, effective_verbose)
    if detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections"))
        for detection in detections[: max(row_limit, 20)]:
            severity = str(detection.get("severity", "info")).lower()
            if severity in ("critical", "high"):
                marker = danger(f"[{severity.upper()}]")
            elif severity in ("warning", "medium"):
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {detection.get('summary', '')}")
            details = detection.get("details", "")
            if details:
                lines.append(muted(f"  {_redact_in_text(str(details))}"))

    if getattr(summary, "deterministic_checks", None):
        _render_deterministic_checks(
            lines, summary, "Deterministic VoIP Security Checks", CHECK_LABELS
        )

    if getattr(summary, "threat_hypotheses", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Threat Hypotheses"))
        for item in summary.threat_hypotheses[: _limit_value(6)]:
            if not isinstance(item, dict):
                continue
            lines.append(warn(f"- {item.get('hypothesis', '')}"))
            if item.get("rationale"):
                lines.append(muted(f"    Why: {item['rationale']}"))
            if item.get("next_step"):
                lines.append(muted(f"    Next: {item['next_step']}"))

    if getattr(summary, "benign_context", None):
        notes = [str(v) for v in (summary.benign_context or []) if str(v).strip()]
        if notes:
            lines.append(SUBSECTION_BAR)
            lines.append(header("False-Positive Context"))
            for note in notes[: _limit_value(8)]:
                lines.append(muted(f"- {note}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
