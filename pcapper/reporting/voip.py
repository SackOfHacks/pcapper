"""Rendered output for phone-over-IP analysis (SIP/SDP, SCCP, MGCP, MEGACO,
IAX2, H.323, RTP/RTCP/SRTP, T.38, STUN/TURN, provisioning).

Ordered the way a VoIP investigation runs: what was recovered (credentials,
keys, digits, audio), who called whom, who registered, then the devices.
Media quality, negotiated SDP detail, STUN and hypotheses are -v material.
"""

from __future__ import annotations

from ..utils import format_bytes_as_mb, format_duration
from ..voip import VoipSummary
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for

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


def render_voip_summary(summary: VoipSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    rep = st.Report("VoIP", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.protocols and not st.material(findings):
        return rep.absent("phone-over-IP traffic", summary.errors)
    rows_max = None if (st.verbose() or verbose) else limit

    severity, text = st.verdict(
        findings,
        high="high-severity VoIP activity: treat recovered credentials, keys and digits as evidence",
        medium="VoIP activity to review",
    )
    rep.headline(severity, text, st.join([
        st.plural(len(summary.calls), "call"),
        st.plural(len(summary.registrations), "registration"),
        f"{st.count(summary.signaling_packets)} signalling / {st.count(summary.rtp_packets)} RTP packets",
        st.duration(summary.duration_seconds) if summary.duration_seconds is not None else "",
    ]))
    rep.scope(st.top(summary.protocols, 6))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    if summary.analysis_notes:
        rep.section("Notes", st.bullets(summary.analysis_notes, max_items=8, noun="note"))
    rep.section("Findings", st.findings_block(findings))

    # Deliberately unredacted: recovering these is the point of the tool, and
    # the output directory is written owner-only for exactly this reason.
    if summary.credentials:
        cred_lines = [f"  {st.bad(st.plural(len(summary.credentials), 'credential'))} recovered from cleartext signalling"]
        if st.verbose():
            cred_rows = [[st.ts(c.ts), c.protocol, c.context, c.username or "-", c.realm or "-",
                          st.flow(c.src_ip, c.dst_ip), ""] for c in summary.credentials]
        else:  # identical credentials (a brute-force run) collapse to one row
            groups: dict = {}
            for c in summary.credentials:
                key = (c.protocol, c.context, c.username or "-", c.realm or "-", st.flow(c.src_ip, c.dst_ip))
                groups.setdefault(key, []).append(c)
            cred_rows = [[st.ts(min((x.ts for x in g if x.ts), default=None)), *key, f"×{len(g)}" if len(g) > 1 else ""]
                         for key, g in groups.items()]
        cred_lines += st.table(
            ["Time", "Protocol", "Context", "User", "Realm", "Flow", ""],
            cred_rows, max_rows=rows_max, widths=(None, None, 18, 22, 20), noun="credential",
        )
        crackable = [c.crackable for c in summary.credentials if c.crackable]
        if crackable:
            modes = sorted({c.protocol for c in summary.credentials if c.crackable})
            hint = " (SIP lines: hashcat -m 11400)" if "SIP" in modes else ""
            cred_lines.append(f"  {st.strong('Crack-ready')} {', '.join(modes)}{hint}")
            shown = crackable if st.verbose() else crackable[:3]
            cred_lines += [f"    {st.dim(line)}" for line in shown]
            if len(crackable) > len(shown):
                cred_lines.append(st.more(len(crackable) - len(shown), "crack-ready line"))
        rep.section("Credentials", cred_lines)

    keyed = [m for m in summary.media if m.cleartext_keys]
    if keyed:
        rep.section("Cleartext media keys", [
            f"  {st.bad('SRTP master keys sent in the clear')} (a=crypto inline): anyone with this capture can decrypt the media"
        ] + [f"    {m.address}:{m.port}  {m.crypto_suites[0] if m.crypto_suites else '?'}  inline:{m.cleartext_keys[0]}"
             for m in (keyed if st.verbose() else keyed[:4])])

    if summary.calls:
        call_lines = st.table(
            ["Time", "Protocol", "From", "To", "Disposition", "Duration", "Auth"],
            [[st.ts(c.first_seen), c.protocol, c.from_user or c.caller_ip or "-", c.to_user or c.callee_ip or "-",
              c.disposition, f"{c.duration_seconds:.1f}s" if c.duration_seconds is not None else "-",
              "yes" if c.authenticated else ("challenged" if c.challenged else "no")] for c in summary.calls],
            align="lllllrl", max_rows=rows_max, widths=(None, None, 26, 26), noun="call",
        )
        shown_calls = summary.calls if rows_max is None else summary.calls[:rows_max]
        call_lines += [f"  {st.caution('digits')} {c.call_id[:40]}: {c.dtmf}" for c in shown_calls if c.dtmf]
        rep.section("Calls", call_lines)

    rep.section("Registrations", st.table(
        ["Protocol", "Account", "Attempts", "OK", "Challenged", "Failed", "Sources"],
        [[r.protocol, r.aor, st.count(r.attempts), st.count(r.successes), st.count(r.challenges),
          st.bad(str(r.failures)) if r.failures else "0", ", ".join(r.source_ips)] for r in summary.registrations],
        align="llrrrrl", max_rows=rows_max, widths=(None, 40, None, None, None, None, 34), noun="registration",
    ))

    if summary.dtmf:
        rep.section("Keypad digits (DTMF)", [
            f"  {st.dim('Often IVR PINs, calling-card, account or card numbers.')}"
        ] + st.table(
            ["Carrier", "Source", "Destination", "Stream", "Digits"],
            [[d.protocol, d.source, d.destination, d.stream, st.caution(d.digits)] for d in summary.dtmf],
            max_rows=rows_max, widths=(None, 24, 24, 14),
        ))

    if summary.provisioning:
        rep.section("Provisioning fetches", st.table(
            ["Transport", "Client", "Server", "File", "Classification"],
            [[p.transport, p.client_ip, p.server_ip, p.filename, p.classification or "-"] for p in summary.provisioning],
            max_rows=rows_max, widths=(None, None, None, 40),
        ) + [f"  {st.dim('Phone configuration files carry the SIP password in cleartext; TFTP needs no authentication.')}"])

    if summary.extracted_audio:
        rep.section("Extracted audio", st.bullets(summary.extracted_audio, max_items=10, noun="file"))

    if summary.messages:
        rep.section("In-band messages", st.table(
            ["Time", "Kind", "Flow", "Body"],
            [[st.ts(m.ts), f"{m.protocol} {m.kind}", st.flow(m.src_ip, m.dst_ip), _redact_in_text(m.body)]
             for m in summary.messages],
            max_rows=8, widths=(None, None, None, 120), noun="message",
        ))

    rep.section("Devices and software", st.kv([
        counter_line("Devices", summary.devices, 5),
        counter_line("User-Agents", summary.user_agents, 5),
        counter_line("Servers", summary.servers, 5),
    ]))

    # ---- reference material (-v) ----------------------------------------
    rep.section("Traffic", st.kv([
        ("Total packets", st.count(summary.total_packets)),
        ("Signalling packets", st.count(summary.signaling_packets)),
        ("RTP packets", st.count(summary.rtp_packets)),
        ("RTP bytes", format_bytes_as_mb(summary.rtp_bytes) if summary.rtp_bytes else ""),
        ("RTCP packets", st.count(summary.rtcp_packets) if summary.rtcp_packets else ""),
        ("STUN/TURN packets", st.count(summary.stun_packets) if summary.stun_packets else ""),
        ("T.38 fax packets", st.count(summary.t38_packets) if summary.t38_packets else ""),
        ("Duration", format_duration(summary.duration_seconds) if summary.duration_seconds is not None else ""),
        counter_line("Protocols", summary.protocols, None),
        ("SIP transport", ", ".join(f"{n} ({c})" for n, c in sorted(summary.transport_counts.items()))),
        counter_line("Signalling ports", summary.server_ports, None),
    ]), detail=True)

    def _keying(m) -> str:  # type: ignore[no-untyped-def]
        return (st.bad("CLEARTEXT KEY") if m.cleartext_keys else "DTLS-SRTP" if m.dtls_fingerprint
                else "SDES" if m.crypto_suites else "none")

    rep.section("RTP streams", st.table(
        ["Source", "Destination", "SSRC", "Codec", "Packets", "Loss", "Jitter", "Flags"],
        [[f"{s.src_ip}:{s.src_port}", f"{s.dst_ip}:{s.dst_port}", f"0x{s.ssrc:08x}", s.codec, st.count(s.packets),
          f"{s.loss_percent}%", f"{s.jitter_ms:.1f}ms",
          ",".join(f for f, on in (("SRTP", s.encrypted), ("unsignalled", not s.signaled),
                                   ("DTMF", bool(s.dtmf_digits)), ("wav", bool(s.audio_path))) if on) or "-"]
         for s in summary.rtp_streams],
        align="llllrrrl", max_rows=None,
    ), detail=True)
    rep.section("Negotiated media (SDP)", st.table(
        ["Type", "Profile", "Endpoint", "Direction", "Codecs", "Keying"],
        [[m.media_type, m.transport or "-", f"{m.address}:{m.port}", m.direction, ", ".join(m.codecs), _keying(m)]
         for m in summary.media],
        max_rows=None,
    ), detail=True)
    rep.section("Parties", st.kv([
        counter_line("Called", summary.to_users, None),
        counter_line("Callers", summary.from_users, None),
    ]), detail=True)
    rep.section("STUN, ENUM and RTCP", st.kv([
        counter_line("STUN/TURN attributes", summary.stun_mapped_addresses, None),
        ("ENUM lookups", ", ".join(sorted(summary.enum_lookups))),
        counter_line("RTCP CNAMEs", summary.rtcp_cnames, None),
    ]), detail=True)

    hypotheses = [h for h in (getattr(summary, "threat_hypotheses", None) or []) if isinstance(h, dict)]
    hyp_lines: list[str] = []
    for h in hypotheses:
        hyp_lines.append(f"  {st.caution('•')} {h.get('hypothesis', '')}")
        if h.get("rationale"):
            hyp_lines.append(f"      {st.dim('why: ' + str(h['rationale']))}")
        if h.get("next_step"):
            hyp_lines.append(f"      {st.dim('next: ' + str(h['next_step']))}")
    rep.section("Threat hypotheses", hyp_lines, detail=True)
    rep.section("False-positive context", st.bullets(
        [str(v) for v in (getattr(summary, "benign_context", None) or []) if str(v).strip()], max_items=None,
    ), detail=True)

    if st.analysis_sections() and getattr(summary, "deterministic_checks", None):
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic VoIP Security Checks", CHECK_LABELS)
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
