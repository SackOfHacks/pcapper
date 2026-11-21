"""Rendered output for protocol and conversation analysis.

Default view: protocol anomalies (with ATT&CK), the protocol mix, insecure
and cleartext protocols on the wire, the largest conversations, corroborated
host findings and tunneling/cadence suspicions. -v adds the protocol
hierarchy, port and EtherType breakdowns, zone posture, baseline and role
drift, sequence integrity, false-positive context and endpoints.
"""

from __future__ import annotations

from ..protocols import ProtocolSummary
from ..utils import format_bytes_as_mb, format_duration
from . import _style as st

_INSECURE_WIRE_PROTOCOLS = {
    "Telnet": "cleartext remote admin (credentials in the clear) — T1040",
    "FTP": "cleartext file transfer / credentials — T1040",
    "FTP-Data": "cleartext file transfer payloads — T1040",
    "TFTP": "no-auth file transfer (config/firmware exfil) — T1040",
    "HTTP": "cleartext web (credentials/cookies/data exposed) — T1040",
    "HTTP-Alt": "cleartext web (alt port) — T1040",
    "HTTP-Proxy": "cleartext web proxy — T1040",
    "POP3": "cleartext mail retrieval / credentials — T1040",
    "IMAP": "cleartext mail access / credentials — T1040",
    "SMTP": "cleartext mail (may carry AUTH LOGIN/PLAIN) — T1040",
    "SNMP": "SNMP v1/v2c community strings in cleartext — T1040",
    "LDAP": "cleartext directory queries / simple-bind credentials — T1040",
    "Syslog": "cleartext log data (UDP, spoofable) — T1040",
    "NetBIOS": "legacy name service — poisoning/relay abuse — T1557",
    "mDNS": "multicast name service — spoofing/recon — T1557",
}


_ANOMALY_ATTACK = {
    "Port Scan": "T1046 Network Service Discovery",
    "TCP Null Scan": "T1046 Network Service Discovery",
    "TCP FIN Scan": "T1046 Network Service Discovery",
    "TCP Xmas Scan": "T1046 Network Service Discovery",
    "ARP Spoofing": "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning",
    "Gratuitous ARP": "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning",
    "Cleartext Creds": "T1040 Network Sniffing",
    "Credential Leakage": "T1040 Network Sniffing",
    "Basic Auth": "T1040 Network Sniffing",
    "Cleartext Auth": "T1040 Network Sniffing",
    "Broadcast Storm": "T1498 Network Denial of Service",
    "TCP Reset Flood": "T1498 Network Denial of Service",
    "Large ICMP Payloads": "T1572 Protocol Tunneling",
    "IP Fragmentation": "T1599 Network Boundary Bridging / evasion",
}
_NAME_SHORTENINGS = [
    ("ICMPv6 Neighbor Discovery - Neighbor Solicitation", "ICMPv6 Neighbor Sol."),
    ("ICMPv6 Neighbor Discovery - Neighbor Advertisement", "ICMPv6 Neighbor Adv."),
    ("ICMPv6 Neighbor Discovery - Router Solicitation", "ICMPv6 Router Sol."),
    ("ICMPv6 Neighbor Discovery - Router Advertisement", "ICMPv6 Router Adv."),
    ("ICMPv6 Neighbor Discovery Option - Scapy Unimplemented", "ICMPv6 Option (Unknown)"),
    ("ICMPv6 Neighbor Discovery Option", "ICMPv6 Option"),
    ("IPv6 Extension Header - Hop-by-Hop Options Header", "IPv6 Hop-by-Hop"),
    ("IPv6 Extension Header", "IPv6 Ext"),
    ("MLDv2 - Multicast Listener Report", "MLDv2 Report"),
]


def _clean_name(name: str) -> str:
    name = name.replace(" in ICMP", " (quoted)")
    for old, new in _NAME_SHORTENINGS:
        name = name.replace(old, new)
    return name


def _hierarchy(node, depth: int = 0) -> list[str]:  # type: ignore[no-untyped-def]
    branch = ("  " * depth + "└ ") if depth else ""
    lines = [f"  {(branch + _clean_name(node.name)).ljust(50)} {node.packets} pkts, {format_bytes_as_mb(node.bytes)}"]
    for sub in sorted(node.sub_protocols.values(), key=lambda n: n.packets, reverse=True):
        lines += _hierarchy(sub, depth + 1)
    return lines


def _profiles(items: object, columns: list[tuple[str, str]], align: str = "") -> list[str]:
    rows = []
    for profile in list(items or []):
        if isinstance(profile, dict):
            rows.append([" -> ".join(map(str, profile.get(k) or [])) if isinstance(profile.get(k), list) else profile.get(k, "-")
                         for _, k in columns])
    return st.table([c for c, _ in columns], rows, align=align, max_rows=None if st.verbose() else 5, noun="profile")


def render_protocols_summary(summary: ProtocolSummary, verbose: bool = False) -> str:
    rep = st.Report("Protocols", summary.path)
    findings = []
    for a in summary.anomalies or []:
        f = st.finding(a)
        f.title = str(getattr(a, "type", "") or f.title)
        f.attack = _ANOMALY_ATTACK.get(f.title, "")
        findings.append(f)
    if not summary.total_packets and not st.material(findings):
        return rep.absent("packets", summary.errors)
    severity, text = st.verdict(findings, high="high-severity protocol anomalies: investigate the hosts below",
                                medium="protocol anomalies to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.total_packets)} packets", st.duration(summary.duration),
        st.plural(len(summary.top_protocols), "protocol"), st.plural(len(summary.conversations), "conversation"),
    ]))
    verdict = str(getattr(summary, "analyst_verdict", "") or "")
    if verdict:
        confidence = str(getattr(summary, "analyst_confidence", "") or "").lower()
        rep.scope(f"analyzer: {verdict}" + (f" ({confidence} confidence)" if confidence else ""))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    total = summary.total_packets or 0

    def _pct_rows(items: list) -> list:
        return [[n, st.count(c), f"{(c / total * 100) if total else 0:.1f}%"] for n, c in items]

    rep.section("Protocols", st.table(["Protocol", "Packets", "Traffic"], _pct_rows(summary.top_protocols),
                                      align="lrr", max_rows=12 if not st.verbose() else None, noun="protocol"))
    insecure: dict[str, int] = {}
    for name, cnt in list(summary.port_protocols) + list(summary.top_protocols):
        if name in _INSECURE_WIRE_PROTOCOLS:
            insecure[name] = max(insecure.get(name, 0), int(cnt))
    rep.section("Insecure and cleartext protocols", st.table(
        ["Protocol", "Packets", "Risk / ATT&CK"],
        [[st.caution(n), st.count(insecure[n]), _INSECURE_WIRE_PROTOCOLS[n]] for n in sorted(insecure, key=lambda n: -insecure[n])],
        align="lrl", max_rows=None,
    ))
    corroborated = [f for f in (getattr(summary, "corroborated_findings", None) or []) if isinstance(f, dict)]
    rep.section("Corroborated hosts", st.table(
        ["Host", "Score", "Confidence", "Reasons"],
        [[f.get("host", "-"), f.get("score", 0), f.get("confidence", "-"), ", ".join(map(str, f.get("reasons") or [])) or "-"]
         for f in corroborated], align="lrll", max_rows=None if st.verbose() else 6,
    ))
    rep.section("Tunneling suspicion", _profiles(getattr(summary, "tunneling_profiles", None), [
        ("Src", "src"), ("Dst", "dst"), ("Proto", "protocol"), ("Avg payload", "avg_payload"), ("Packets", "packets"),
        ("Confidence", "confidence")], "lllrrl"))
    rep.section("Cadence anomalies", _profiles(getattr(summary, "beacon_profiles", None), [
        ("Src", "src"), ("Dst", "dst"), ("Proto", "protocol"), ("Packets", "packets"), ("Duration s", "duration_s"),
        ("PPS", "pps")], "lllrrr"))
    convs = sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)
    rep.section("Conversations", st.table(
        ["Src", "Dst", "Proto", "Packets", "Bytes", "Duration", "Ports"],
        [[c.src, c.dst, c.protocol, st.count(c.packets), format_bytes_as_mb(c.bytes), st.duration(c.end_ts - c.start_ts),
          ",".join(map(str, sorted(c.ports)))] for c in convs],
        align="lllrrrl", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, widths=(None, None, None, None, None, None, 30),
        noun="conversation",
    ))

    # ---- reference material (-v) ----------------------------------------
    reasons = [str(v) for v in (getattr(summary, "analyst_reasons", None) or [])]
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", str(getattr(summary, "analyst_confidence", "") or "").upper())])
                + st.bullets(reasons, max_items=None), detail=True)
    rep.section("Traffic", st.kv([("Total packets", str(summary.total_packets)), ("Duration", format_duration(summary.duration))]),
                detail=True)
    rep.section("Port-based protocols", st.table(["Protocol", "Packets", "Traffic"], _pct_rows(summary.port_protocols),
                                                 align="lrr", max_rows=None), detail=True)
    rep.section("EtherType protocols", st.table(["Protocol", "Packets", "Traffic"], _pct_rows(summary.ethertype_protocols),
                                                align="lrr", max_rows=None), detail=True)
    root = summary.hierarchy
    tree = [ln for sub in sorted(root.sub_protocols.values(), key=lambda n: n.packets, reverse=True) for ln in _hierarchy(sub)] \
        if root.sub_protocols else _hierarchy(root)
    rep.section("Hierarchy", tree, detail=True)
    rep.section("Sequence integrity", _profiles(getattr(summary, "sequence_profiles", None), [
        ("Entity", "entity"), ("Sequence", "sequence"), ("Evidence", "evidence_count"), ("Confidence", "confidence")]),
        detail=True)
    rep.section("Zone posture", _profiles(getattr(summary, "zone_protocol_profiles", None), [
        ("Src", "src"), ("Dst", "dst"), ("Proto", "protocol"), ("Zone", "zone_pair"), ("Packets", "packets"),
        ("Confidence", "confidence")]), detail=True)
    rep.section("Baseline drift", _profiles(getattr(summary, "baseline_drift_profiles", None), [
        ("Protocol", "protocol"), ("Baseline", "baseline_prevalence"), ("Current %", "current_prevalence_pct"),
        ("Status", "status")]), detail=True)
    rep.section("Role drift", _profiles(getattr(summary, "role_inversion_profiles", None), [
        ("Host", "host"), ("Protocol", "protocol"), ("Count", "protocol_count"), ("Zone", "zone"), ("Confidence", "confidence")]),
        detail=True)
    rep.section("False-positive context", st.bullets(
        [str(v) for v in (getattr(summary, "false_positive_context", None) or []) if str(v).strip()], max_items=None), detail=True)
    eps = sorted(summary.endpoints, key=lambda e: e.bytes_sent + e.bytes_recv, reverse=True)
    rep.section("Endpoints", st.table(
        ["Address", "Sent", "Received", "Bytes", "Protocols"],
        [[e.address, st.count(e.packets_sent), st.count(e.packets_recv), format_bytes_as_mb(e.bytes_sent + e.bytes_recv),
          ",".join(sorted(str(p) for p in e.protocols))] for e in eps],
        align="lrrrl", max_rows=None), detail=True)
    return rep.render()
