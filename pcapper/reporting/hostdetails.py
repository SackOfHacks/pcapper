"""Rendered output for --hostdetails (-ip TARGET): everything about one
host. The default view is its identity (names, MACs and vendor, OS, browser
roles, accounts), the detections it is part of (as actor or target), the
services it hosts, the remote access into it and the services it reached,
its authentication and SMB share access, and an activity digest (web, DNS,
downloads; DNS lookups are --dnsqueries -ip). Full web/download/TLS/e-mail/peer-intel tables, the scored
assessment and the traffic counters are -v detail."""

from __future__ import annotations

from collections import Counter

from ..hostdetails import HostDetailsSummary
from ..ipmac import mac_manufacturer
from ..services import COMMON_PORTS
from ..utils import format_duration, format_ts
from ..utils import is_public_ip as _is_public_ip
from . import _style as st
from ._common import _redact_in_text


def _packet_number_hint(record: object) -> str:
    if not isinstance(record, dict):
        return "-"

    def _normalize_packet(value: object) -> str | None:
        if value is None:
            return None
        if isinstance(value, int):
            return str(value) if value > 0 else None
        if isinstance(value, float):
            if value.is_integer() and value > 0:
                return str(int(value))
            return None
        if isinstance(value, (list, tuple, set)):
            numeric_values = sorted(
                int(v)
                for v in value
                if isinstance(v, int) and int(v) > 0
            )
            if numeric_values:
                return str(numeric_values[0])
            for item in value:
                normalized = _normalize_packet(item)
                if normalized:
                    return normalized
            return None
        text = str(value).strip()
        if not text or text == "-":
            return None
        if text.isdigit() and int(text) > 0:
            return text
        return None

    for key in (
        "packet",
        "packet_number",
        "pkt",
        "frame",
        "first_packet",
        "first_pkt",
        "syn_packet",
        "syn_packet_number",
        "last_packet",
    ):
        normalized = _normalize_packet(record.get(key))
        if normalized:
            return normalized

    for key in ("packet_refs", "packet_examples"):
        normalized = _normalize_packet(record.get(key))
        if normalized:
            return normalized

    packets_value = record.get("packets")
    if isinstance(packets_value, (list, tuple, set)):
        normalized = _normalize_packet(packets_value)
        if normalized:
            return normalized

    return "-"


_HD_REMOTE_ACCESS_PORTS = {
    22: "SSH",
    23: "Telnet",
    135: "RPC/DCOM",
    139: "SMB/NetBIOS",
    445: "SMB",
    1433: "MSSQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC",
    5985: "WinRM",
    5986: "WinRM-TLS",
    5938: "TeamViewer",
    6379: "Redis",
}


def _hd_remote_access_flag(port: object, byte_count: int, peer_external: bool):
    """Classify an outbound service the host reached: interactive/admin remote
    access (RDP/SSH/VNC/...), or a suspected C2/reverse-shell (a sustained
    session to a non-standard high port). Returns (flag_text, paint_fn)."""
    try:
        p = int(port)
    except Exception:
        return "-", (lambda t: t)
    if p in _HD_REMOTE_ACCESS_PORTS:
        return f"REMOTE-ACCESS ({_HD_REMOTE_ACCESS_PORTS[p]})", st.caution
    # Non-standard high port with sustained traffic = suspected C2 / reverse shell.
    if p >= 1024 and p not in COMMON_PORTS and byte_count >= 50_000:
        return ("SUSP-C2" if peer_external else "SUSP-SHELL"), st.bad
    return "-", (lambda t: t)


def _grouped(items: list[dict], key, *, first: str = "ts", last: str = "ts", size: str = "") -> list[tuple[tuple, dict]]:
    """Records grouped by ``key(item)``: count, first and last time, the
    first packet number and (with ``size``) the total size."""
    groups: dict[tuple, dict] = {}
    for item in items:
        bucket = groups.setdefault(key(item), {"count": 0, "first": None, "last": None, "packet": "-", "bytes": 0})
        bucket["count"] += 1
        for name, field_name, pick in (("first", first, min), ("last", last, max)):
            value = item.get(field_name)
            if isinstance(value, (int, float)):
                bucket[name] = value if bucket[name] is None else pick(bucket[name], value)
        if bucket["packet"] == "-":
            bucket["packet"] = _packet_number_hint(item)
        if size:
            bucket["bytes"] += int(item.get(size) or item.get("bytes") or 0)
    return list(groups.items())


def render_hostdetails_summary(summary: HostDetailsSummary, limit: int = 20, verbose: bool = False) -> str:
    target = str(summary.target_ip)
    rep = st.Report(f"Host {target}", summary.path)
    detections = list(summary.detections or [])
    actor = [d for d in detections if str(d.get("host_role", "")) == "actor"]
    victim = [d for d in detections if str(d.get("host_role", "")) == "target"]
    verdict = str(getattr(summary, "host_verdict", "") or "")
    worst = max((d.get("severity", "info") for d in detections), key=st.sev_rank, default=None)
    if verdict.startswith(("LIKELY COMPROMISED", "HIGH RISK")):
        severity = "high" if st.sev_rank(worst) <= st.sev_rank("high") else worst
    elif verdict.startswith("SUSPICIOUS"):
        severity = worst if st.sev_rank(worst) >= st.sev_rank("medium") else "medium"
    else:
        severity = worst if st.sev_rank(worst) >= st.sev_rank("low") else None
    role = (f"actor in {len(actor)} and target in {len(victim)} detections" if actor and victim else
            f"source of {st.plural(len(actor), 'detection')}" if actor else f"target of {st.plural(len(victim), 'detection')}" if victim else "")
    names = [str(h) for h in (summary.hostnames or []) if str(h).strip()]
    rep.headline(severity if detections or verdict else False,
                 st.join([verdict.split(" - ")[0].lower() if verdict else "", role]) or "host profile",
                 st.join([", ".join(names[:2]), summary.operating_system if summary.operating_system not in ("", "-", "Unknown") else "",
                          f"{st.size(summary.bytes_sent)} out / {st.size(summary.bytes_recv)} in",
                          st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else ""]))
    filters = st.join([f"hostname {summary.hostname_query}" if str(summary.hostname_query or "").strip() else "",
                       f"port {summary.port_filter}" if summary.port_filter else "",
                       f"search {summary.search_query!r}" if str(summary.search_query or "").strip() else ""])
    if filters:
        rep.scope(f"filtered by {filters}")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    roles = list(getattr(summary, "netbios_roles", None) or [])
    role_text = ", ".join(roles)
    users = sorted({str(u.get("username", "")).strip() for u in (summary.user_evidence or []) if str(u.get("username", "")).strip()})
    uas = list(summary.user_agents or [])
    rep.section("Identity", st.kv([
        ("Hostnames", st.listing(names, 6)),
        ("MACs", st.listing([f"{m} ({v})" if (v := mac_manufacturer(m)) and v != "-" else m for m in (summary.mac_addresses or [])], 4)),
        ("OS / device", str(summary.operating_system or "")),
        ("Browser roles", st.bad(role_text) if any(r in role_text for r in ("Domain Controller", "Master Browser", "SQL Server")) else role_text),
        ("Domain / workgroup", str(getattr(summary, "netbios_domain", "") or "")),
        ("Comment", str(getattr(summary, "netbios_comment", "") or "")),
        ("Users", st.listing([_redact_in_text(u) for u in users], 8)),
        ("User-Agents", (f"{len(uas)}: " if len(uas) > 1 else "") + st.listing([st.cut(u, 70) for u in uas], 2) if uas else ""),
    ]))

    merged: dict[tuple[int, str, str], dict] = {}
    for d in detections:  # the same detection from two analyzers is one row
        row = merged.setdefault((st.sev_rank(d.get("severity")), str(d.get("host_role", "-")), str(d.get("summary", "-")).lower()),
                                {"det": d, "sources": []})
        if str(d.get("source", "-")) not in row["sources"]:
            row["sources"].append(str(d.get("source", "-")))
    rep.section("Detections", st.table(
        ["Severity", "Role", "Detection", "Source", "Detail"],
        [[st.badge(r["det"].get("severity", "info")), r["det"].get("host_role", "-"), _redact_in_text(str(r["det"].get("summary", "-"))),
          ", ".join(r["sources"]), _redact_in_text(str(r["det"].get("details", "-")))]
         for _k, r in sorted(merged.items(), key=lambda kv: -kv[0][0])],
        widths=(None, None, 48, None, 70), max_rows=10, noun="detection",
    ) + ([st.dim(f"  next: pcapper <capture> --streams -ip {target}, --files -ip {target}; "
                 + ("scope it as a likely-compromised/hostile origin (EDR + AD logs)" if actor else
                    "assess exposure and whether an attempt succeeded"))] if detections else []))

    grouped_users: dict[tuple[str, str], dict] = {}
    for u in summary.user_evidence or []:
        name = str(u.get("username", "")).strip()
        if not name:
            continue
        entry = grouped_users.setdefault((name.lower(), str(u.get("domain", "")).strip().lower()),
                                         {"username": name, "domain": str(u.get("domain", "")).strip(), "methods": [], "where": ""})
        method = str(u.get("method", "")).strip()
        if method and method not in entry["methods"]:
            entry["methods"].append(method)
        entry["where"] = entry["where"] or str(u.get("location", "")).strip()
    rep.section("Accounts", st.table(
        ["Username", "Domain", "Seen via", "Where"],
        [[_redact_in_text(e["username"]), e["domain"] or "-", ", ".join(e["methods"]) or "-", e["where"] or "-"]
         for e in sorted(grouped_users.values(), key=lambda e: e["username"].lower())],
        widths=(None, None, None, 44), max_rows=10, noun="account",
    ) if grouped_users else [st.dim("  no user account recovered: no authenticated protocol carried a username for this host")])

    hosted = [i for i in (summary.services or []) if str(i.get("role", "")).lower() == "server" and str(i.get("asset", "")).startswith(f"{target}:")]
    rep.section("Services hosted", st.table(
        ["Service", "Port", "Proto", "Confirmed by", "Software", "Packets", "Bytes", "Clients"],
        [[i.get("service", "-"), i.get("port", "-"), i.get("protocol", "-"),
          "SYN/ACK" if i.get("handshake_confirmed") else str(i.get("discovery_method", "observed") or "observed"), i.get("software") or "-",
          st.count(i.get("packets", 0)), st.size(int(i.get("bytes", 0) or 0)), i.get("peers") or "-"] for i in hosted],
        align="lrlllrrl", widths=(None, None, None, None, 32, None, None, 36), max_rows=10, noun="service",
    ))

    inbound: dict[tuple[str, str, str], dict] = {}
    outbound: dict[tuple[str, str, str], dict] = {}
    for conv in summary.conversations or []:
        peer = str(conv.get("peer", "") or "")
        if not peer or peer == target:
            continue
        proto = str(conv.get("protocol", "-") or "-")
        for store, ports in ((inbound, [p for p in (conv.get("local_service_ports") or []) if int(p) in _HD_REMOTE_ACCESS_PORTS]),
                             (outbound, conv.get("remote_service_ports") or [])):
            for port in ports:
                row = store.setdefault((peer, str(int(port)), proto), {"packets": 0, "bytes": 0, "first": None, "last": None})
                row["packets"] += int(conv.get("packets", 0) or 0)
                row["bytes"] += int(conv.get("bytes", 0) or 0)
                for name, field_name, pick in (("first", "first_seen", min), ("last", "last_seen", max)):
                    value = conv.get(field_name)
                    if isinstance(value, (int, float)):
                        row[name] = value if row[name] is None else pick(row[name], value)
    rep.section("Remote access into this host", st.table(
        ["Peer", "Scope", "Port", "Service", "Proto", "Packets", "Bytes", "First", "Last"],
        [[st.bad(peer) if _is_public_ip(peer) else peer, st.bad("EXTERNAL") if _is_public_ip(peer) else "internal", port,
          _HD_REMOTE_ACCESS_PORTS.get(int(port), "-"), proto, st.count(d["packets"]), st.size(d["bytes"]), st.ts(d["first"]), st.ts(d["last"])]
         for (peer, port, proto), d in sorted(inbound.items(), key=lambda kv: -kv[1]["bytes"])],
        align="llrllrrll", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="session",
    ) + ([st.dim("  confirm each is authorized (jump box / admin session) vs. lateral movement or unauthorized access")] if inbound else []))

    def _access(peer: str, port: str, nbytes: int) -> str:
        flag, paint = _hd_remote_access_flag(port, nbytes, _is_public_ip(peer))
        return paint(flag) if flag != "-" else "-"

    rep.section("Services reached", st.table(
        ["Remote host", "Port", "Service", "Access", "Proto", "Packets", "Bytes", "First", "Last"],
        [[peer, port, COMMON_PORTS.get(int(port), "-") if port.isdigit() else "-", _access(peer, port, d["bytes"]), proto,
          st.count(d["packets"]), st.size(d["bytes"]), st.ts(d["first"]), st.ts(d["last"])]
         for (peer, port, proto), d in sorted(outbound.items(), key=lambda kv: -kv[1]["bytes"])],
        align="lrlllrrll", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="service",
    ))
    auth = list(getattr(summary, "auth_events", None) or [])
    auth_rows: dict[tuple, int] = {}
    for e in auth:  # identical events (same second, peer, account, kind) fold to one row
        key = (st.ts(e.get("ts")), str(e.get("protocol", "-")), str(e.get("direction", "-")), str(e.get("peer", "-")),
               _redact_in_text(str(e.get("username", "-"))), bool(e.get("secret_exposed")), str(e.get("kind", "-")))
        auth_rows[key] = auth_rows.get(key, 0) + 1
    rep.section("Authentication", st.table(
        ["Time", "Proto", "Direction", "Peer", "Account", "Secret", "Kind", "Times"],
        [[k[0], k[1], k[2], k[3], k[4], st.bad("EXPOSED") if k[5] else "-", k[6], n] for k, n in auth_rows.items()],
        align="lllllllr", max_rows=8, noun="event",
    ) + ([f"  {st.bad('!')} cleartext credential material exposed for this host: rotate the affected accounts"]
         if any(e.get("secret_exposed") for e in auth) else []))
    smb = list(getattr(summary, "smb_access", None) or [])

    def _admin(sa: dict) -> bool:
        return bool(sa.get("admin")) or any(m in str(sa.get("shares", "")) for m in ("ADMIN$", "C$", "D$"))

    rep.section("SMB share access", st.table(
        ["Role", "Peer", "Shares", "Account", "SMB", "Signing"],
        [[sa.get("role", "-"), sa.get("peer", "-"), st.bad(str(sa.get("shares", "-"))) if _admin(sa) else sa.get("shares", "-"),
          _redact_in_text(str(sa.get("user", "-"))), sa.get("version", "-"),
          st.bad("no") if str(sa.get("signing", "-")) == "no" else sa.get("signing", "-")] for sa in smb],
        max_rows=6, noun="share session",
    ) + ([st.dim("  administrative-share access: review for PsExec-style lateral movement")] if any(_admin(sa) for sa in smb) else []))

    web = [i for i in (summary.web_requests or []) if str(i.get("src_ip", "")) == target]
    dns = [i for i in (summary.dns_queries or []) if str(i.get("src_ip", "")) == target]
    downloads = [i for i in (summary.file_transfers or []) if str(i.get("direction", "")).lower() == "download"
                 and str(i.get("dst_ip", "")) == target]
    risky = sorted(web, key=lambda i: int(i.get("risk_score", 0) or 0), reverse=True)
    rep.section("Activity", st.kv([
        ("Web", f"{st.plural(len(web), 'request')} to {st.plural(len({i.get('dst_ip') for i in web}), 'server')}"
         + (f" · riskiest: {i0.get('method', '-')} {st.cut(str(i0.get('host', '-')) + str(i0.get('uri', '')), 60)} "
            f"({i0.get('risk_level', '-')} {i0.get('risk_score', 0)})" if (i0 := (risky[0] if risky else None)) else "") if web else ""),
        ("DNS", st.dim(f"{st.plural(len(dns), 'lookup')}: --dnsqueries -ip {target} lists them") if dns else ""),
        ("Downloads", f"{st.plural(len(downloads), 'file')} ({st.size(sum(int(i.get('size_bytes') or i.get('bytes') or 0) for i in downloads))}): "
                      + st.top(Counter(str(i.get("filename", "-")) for i in downloads), 4) if downloads else ""),
        ("TLS (as client)", st.top(Counter({str(f.get("sni", "-")): int(f.get("count", 0) or 0) for f in (summary.tls_fingerprints or [])}), 4)),
    ]))
    flagged_peers = [p for p in (getattr(summary, "peer_intel", None) or []) if str(p.get("intel", "-")) not in ("-", "")]
    rep.section("Peer intelligence", st.table(
        ["Peer", "Scope", "Geo / ASN / Org", "Flags", "Intel", "Packets"],
        [[st.bad(str(p.get("peer", "-"))), p.get("scope", "-"), p.get("geo", "-"), p.get("flags", "-"), st.bad(str(p.get("intel", "-"))),
          p.get("packets", "-")] for p in flagged_peers], max_rows=8, noun="peer",
    ))

    rep.section("Assessment", st.kv([
        ("Verdict", verdict), ("Confidence", f"{getattr(summary, 'host_confidence', 'low')} (score {int(getattr(summary, 'host_verdict_score', 0) or 0)})"),
        ("Role in detections", role),
    ]) + st.bullets([_redact_in_text(str(r)) for r in (getattr(summary, "host_verdict_reasons", None) or [])], max_items=None), detail=True)
    peer_risk = getattr(summary, "peer_risk", None) or Counter()
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.relevant_packets} relevant of {summary.total_packets} · {summary.packets_sent} sent / {summary.packets_recv} received"),
        ("Bytes", f"{summary.bytes_sent} sent / {summary.bytes_recv} received"),
        ("Window", f"{format_ts(summary.first_seen)} / {format_ts(summary.last_seen)}"),
        ("Duration", format_duration(summary.duration_seconds)),
        ("Peers", f"{len(peer_risk)} public of {len(summary.peer_counts or {})}" + (f" · top public: {st.top(peer_risk, None)}" if peer_risk else "")),
        ("All peers", st.top(Counter(summary.peer_counts or {}), None)),
        ("Protocols", st.top(Counter(summary.protocol_counts or {}), None)),
        ("Ports", st.top(Counter({str(k): v for k, v in (summary.port_counts or {}).items()}), None)),
        ("Attack categories", st.top(Counter(summary.attack_categories or {}), None)),
    ]), detail=True)
    rep.section("Web requests", st.table(
        ["Method", "Request", "Remote", "Status", "Risk", "Hits", "First", "Last", "Packet"],
        [[k[0], k[1], f"{k[2]}:{k[3]}", k[4], f"{k[5]} ({k[6]})", b["count"], format_ts(b["first"]), format_ts(b["last"]), b["packet"]]
         for k, b in sorted(_grouped(web, lambda i: (str(i.get("method", "-")), f"{i.get('host', '-')}{i.get('uri', '')}", str(i.get("dst_ip", "-")),
                                                     str(i.get("dst_port", "-")),
                                                     st.join([i.get("response_code"), i.get("response_name") if i.get("response_name") != "-" else ""], " ") or "-",
                                                     str(i.get("risk_level", "-")), str(i.get("risk_score", "-")))),
                            key=lambda kv: -kv[1]["count"])], max_rows=None,
    ), detail=True)

    def _hashes(i: dict) -> str:
        return st.join([f"sha256={i.get('sha256')}" if i.get("sha256") else "", f"md5={i.get('md5')}" if i.get("md5") else ""], " ") or "-"

    rep.section("Downloads", st.table(
        ["File", "Source", "Proto", "Type", "Hashes", "Events", "Size", "First", "Last", "Packet"],
        [[k[0], k[1], k[2], k[3], k[4], b["count"], st.size(b["bytes"]) if b["bytes"] else "-", format_ts(b["first"]), format_ts(b["last"]), b["packet"]]
         for k, b in sorted(_grouped(downloads, lambda i: (str(i.get("filename", "-") or "-"),
                                                           f"{i.get('src_ip', '-')}:{i.get('src_port') if i.get('src_port') is not None else '-'}",
                                                           str(i.get("protocol", "-")), str(i.get("file_type", "-") or "-"), _hashes(i)),
                                     first="first_seen", last="last_seen", size="size_bytes"), key=lambda kv: -kv[1]["bytes"])], max_rows=None,
    ), detail=True)
    rep.section("TLS fingerprints", st.table(["SNI", "Sessions", "JA3"], [[f.get("sni", "-"), f.get("count", "-"), f.get("ja3", "-")]
                                                                      for f in (summary.tls_fingerprints or [])], align="lrl", max_rows=None),
                detail=True)
    emails = list(getattr(summary, "email_activity", None) or [])
    rep.section("E-mail", st.kv([("Role", str(emails[0].get("role", "-")) if emails else "")])
                + st.table(["Field", "Value", "Count"], [[e.get("field", "-"), st.bad(str(e.get("value", "-"))) if e.get("field") == "Password"
                                                          else _redact_in_text(str(e.get("value", "-"))), e.get("count", "-")] for e in emails],
                           align="llr", max_rows=None), detail=True)
    rep.section("Peers", st.table(
        ["Peer", "Scope", "Geo / ASN / Org", "Flags", "Intel", "Packets"],
        [[p.get("peer", "-"), p.get("scope", "-"), p.get("geo", "-"), p.get("flags", "-"), p.get("intel", "-"), p.get("packets", "-")]
         for p in (getattr(summary, "peer_intel", None) or [])], max_rows=None,
    ), detail=True)
    rep.section("Hostname evidence", st.table(
        ["Hostname", "Method", "Protocol", "Confidence", "Count", "Details"],
        [[h.get("hostname", "-"), h.get("method", "-"), h.get("protocol", "-"), h.get("confidence", "-"), h.get("count", "-"), h.get("details", "-")]
         for h in (summary.hostname_findings or []) if isinstance(h, dict)], max_rows=None,
    ) + st.bullets([str(e) for e in (summary.os_evidence or [])], max_items=None), detail=True)

    def _records(items: object) -> list[str]:
        return [_redact_in_text("  ".join(f"{k}={v}" for k, v in i.items()) if isinstance(i, dict) else str(i)) for i in (items or [])]

    for title, field_name in (("Attack path", "attack_path_steps"), ("Sequence violations", "sequence_violations"),
                              ("Evidence anchors", "evidence_anchors"), ("Artifacts", "artifacts")):
        rep.section(title, st.bullets(_records(getattr(summary, field_name, None)), max_items=None), detail=True)
    return rep.render()
