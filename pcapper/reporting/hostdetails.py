"""Rendered output for hostdetails analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..utils import is_public_ip as _is_public_ip
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    orange,
    warn,
)
from ..hostdetails import HostDetailsSummary
from ..ipmac import mac_manufacturer
from ..services import COMMON_PORTS
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _apply_verbose_limit,
    _finalize_output,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
)


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
        return f"REMOTE-ACCESS ({_HD_REMOTE_ACCESS_PORTS[p]})", orange
    # Non-standard high port with sustained traffic = suspected C2 / reverse shell.
    if p >= 1024 and p not in COMMON_PORTS and byte_count >= 50_000:
        return ("SUSP-C2" if peer_external else "SUSP-SHELL"), danger
    return "-", (lambda t: t)


def render_hostdetails_summary(
    summary: HostDetailsSummary, limit: int = 20, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit)
    lines: list[str] = []
    target_ip = str(summary.target_ip)

    lines.append(SECTION_BAR)
    lines.append(header(f"HOST DETAILS :: {target_ip} :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Host Identity"))
    lines.append(
        _format_kv(
            "Hostname",
            ", ".join(summary.hostnames[: _limit_value(8)])
            if summary.hostnames
            else "-",
        )
    )
    lines.append(_format_kv("IP Address", target_ip))
    # MAC + manufacturer (OUI) is core host identification, so always annotate
    # the vendor here (not gated behind --oui) when scapy's manufdb knows it.
    mac_parts: list[str] = []
    for mac in summary.mac_addresses[: _limit_value(8)]:
        vendor = mac_manufacturer(mac)
        mac_parts.append(f"{mac} ({vendor})" if vendor and vendor != "-" else mac)
    lines.append(_format_kv("MAC Address", ", ".join(mac_parts) if mac_parts else "-"))
    lines.append(_format_kv("Inferred OS / Device", str(summary.operating_system)))
    # Browser (MS-BRWS) announced identity: server roles, domain, comment.
    nb_roles = list(getattr(summary, "netbios_roles", []) or [])
    nb_domain = str(getattr(summary, "netbios_domain", "") or "")
    nb_comment = str(getattr(summary, "netbios_comment", "") or "")
    if nb_roles:
        role_txt = ", ".join(nb_roles)
        is_infra = any(
            r in role_txt
            for r in ("Domain Controller", "Master Browser", "SQL Server")
        )
        lines.append(
            _format_kv("Announced Roles (Browser)", danger(role_txt) if is_infra else role_txt)
        )
    if nb_domain:
        lines.append(_format_kv("Domain / Workgroup", nb_domain))
    if nb_comment:
        lines.append(_format_kv("Announced Comment", nb_comment))
    host_uas = list(getattr(summary, "user_agents", []) or [])
    if host_uas:
        if len(host_uas) == 1:
            lines.append(_format_kv("Client User-Agent", _truncate_text(host_uas[0], 90)))
        else:
            lines.append(
                _format_kv(
                    "Client User-Agents",
                    f"{len(host_uas)} distinct (e.g. {_truncate_text(host_uas[0], 72)})",
                )
            )
            for ua in host_uas[1 : _limit_value(6)]:
                lines.append(muted(f"  - {_truncate_text(ua, 90)}"))
    user_evidence = list(getattr(summary, "user_evidence", []) or [])
    if user_evidence:
        user_text = ", ".join(
            sorted(
                {
                    str(u.get("username", "")).strip()
                    for u in user_evidence
                    if str(u.get("username", "")).strip()
                }
            )[: _limit_value(8)]
        )
        lines.append(_format_kv("Users Observed", user_text or "-"))
    if str(getattr(summary, "hostname_query", "") or "").strip():
        lines.append(_format_kv("Hostname Filter", str(summary.hostname_query)))
    if getattr(summary, "port_filter", None):
        lines.append(_format_kv("Port Filter", str(summary.port_filter)))
    if str(getattr(summary, "search_query", "") or "").strip():
        lines.append(_format_kv("Search Filter", str(summary.search_query)))

    # ---- Observed Usernames (identities attributed to this host) ------------
    # Accounts recovered for the host across every identity-bearing protocol:
    # NetBIOS <03>, Kerberos cname, NTLM, HTTP Basic/forms, FTP, SMTP/POP3/IMAP,
    # Telnet, SMB, etc. Consolidate the source method(s) per (username, domain).
    # Always render the section (even when empty) so the analyst can see the
    # check ran — "not shown" was being read as "broken".
    lines.append(SUBSECTION_BAR)
    lines.append(header("Observed Usernames"))
    grouped: dict[tuple[str, str], dict[str, object]] = {}
    for u in user_evidence:
        uname = str(u.get("username", "")).strip()
        if not uname:
            continue
        dom = str(u.get("domain", "")).strip()
        entry = grouped.setdefault(
            (uname.lower(), dom.lower()),
            {"username": uname, "domain": dom, "methods": [], "where": ""},
        )
        method = str(u.get("method", "")).strip()
        methods = entry["methods"]
        if isinstance(methods, list) and method and method not in methods:
            methods.append(method)
        if not entry["where"]:
            entry["where"] = str(u.get("location", "")).strip()
    if grouped:
        lines.append(
            muted(
                "Accounts recovered for this host across identity-bearing "
                "protocols (NetBIOS / Kerberos / NTLM / HTTP / FTP / mail / "
                "Telnet / SMB)."
            )
        )
        rows = [["Username", "Domain", "Source Method(s)", "Where"]]
        for entry in sorted(
            grouped.values(), key=lambda e: str(e["username"]).lower()
        )[: _limit_value(40)]:
            methods = entry["methods"]
            method_text = (
                ", ".join(str(m) for m in methods)
                if isinstance(methods, list)
                else "-"
            )
            rows.append(
                [
                    str(entry["username"]),
                    str(entry["domain"]) or "-",
                    method_text or "-",
                    _truncate_text(str(entry["where"]), 44) or "-",
                ]
            )
        lines.append(_format_table(rows))
    else:
        # Distinguish "feature ran, nothing to find" from a bug. Point the
        # analyst at the host/computer identity that IS available.
        host_names = [str(h) for h in (getattr(summary, "hostnames", []) or []) if str(h).strip()]
        note = (
            "No user accounts recovered for this host — no authenticated "
            "protocol carried a username (NetBIOS <03> logged-on user, Kerberos "
            "cname, NTLM, HTTP/FTP/mail/Telnet/SMB credentials)."
        )
        lines.append(muted(note))
        if host_names:
            lines.append(
                muted(
                    "This capture only exposes the host/computer name "
                    f"({', '.join(host_names[: _limit_value(3)])}), not a user account."
                )
            )

    # ---- Host Assessment (triage verdict, lead with it) --------------------
    host_detections = list(getattr(summary, "detections", []) or [])
    actor_dets = [d for d in host_detections if str(d.get("host_role", "")) == "actor"]
    target_dets = [d for d in host_detections if str(d.get("host_role", "")) == "target"]
    verdict = str(getattr(summary, "host_verdict", "") or "")
    if verdict:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Host Assessment"))
        if verdict.startswith(("LIKELY COMPROMISED", "HIGH RISK")):
            lines.append(danger(verdict))
        elif verdict.startswith("SUSPICIOUS"):
            lines.append(warn(verdict))
        else:
            lines.append(ok(verdict))
        lines.append(
            _format_kv(
                "Confidence",
                f"{str(getattr(summary, 'host_confidence', 'low')).capitalize()} "
                f"(score={int(getattr(summary, 'host_verdict_score', 0) or 0)})",
            )
        )
        role = "-"
        if actor_dets and target_dets:
            role = f"actor in {len(actor_dets)}, target in {len(target_dets)} detection(s)"
        elif actor_dets:
            role = f"ACTOR/source of {len(actor_dets)} detection(s)"
        elif target_dets:
            role = f"TARGET/victim of {len(target_dets)} detection(s)"
        lines.append(_format_kv("Role in Detections", role))
        for reason in (getattr(summary, "host_verdict_reasons", []) or [])[
            : _limit_value(6)
        ]:
            lines.append(muted(f"- {_redact_in_text(str(reason))}"))

    # ---- Host Detections (host-attributed threat signals) ------------------
    if host_detections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Detections Involving This Host"))
        rows = [["Sev", "Role", "Source", "Detection", "Detail"]]
        for det in host_detections[: _limit_value(15)]:
            sev = str(det.get("severity", "info") or "info").upper()[:4]
            rows.append(
                [
                    sev,
                    str(det.get("host_role", "-")),
                    str(det.get("source", "-")),
                    _truncate_text(
                        _redact_in_text(str(det.get("summary", "-"))), 46
                    ),
                    _truncate_text(
                        _highlight_public_ips(
                            _redact_in_text(str(det.get("details", "-")))
                        ),
                        70,
                    ),
                ]
            )
        lines.append(_format_table(rows))
        # Triage guidance for the highest-severity host detection.
        if actor_dets:
            lines.append(
                muted(
                    "This host is the SOURCE of attack activity above - scope it as a "
                    "likely-compromised/hostile origin: pull its sessions (--streams -ip "
                    f"{target_ip}), files (--files -ip {target_ip}), and endpoint/EDR + AD logs."
                )
            )
        elif target_dets:
            lines.append(
                muted(
                    "This host is the TARGET of activity above - assess exposure/impact "
                    "and whether any attempt succeeded (--streams -ip "
                    f"{target_ip}); confirm patch/segmentation state."
                )
            )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Traffic Statistics"))
    lines.append(_format_kv("Packets (Host Relevance)", str(summary.relevant_packets)))
    lines.append(
        _format_kv(
            "Sent / Received Packets",
            f"{summary.packets_sent} / {summary.packets_recv}",
        )
    )
    lines.append(
        _format_kv(
            "Bytes Sent / Received",
            f"{format_bytes_as_mb(summary.bytes_sent)} / {format_bytes_as_mb(summary.bytes_recv)}",
        )
    )
    lines.append(_format_kv("First Seen", format_ts(summary.first_seen)))
    lines.append(_format_kv("Last Seen", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))
    peer_risk = getattr(summary, "peer_risk", None) or Counter()
    total_peers = len(getattr(summary, "peer_counts", {}) or {})
    if total_peers:
        ext_text = f"{len(peer_risk)} public / {total_peers} total distinct peers"
        if peer_risk:
            top_ext = ", ".join(
                f"{_highlight_public_ips(ip)}"
                for ip, _ in peer_risk.most_common(_limit_value(4))
            )
            ext_text = f"{ext_text} (top public: {top_ext})"
        lines.append(_format_kv("Peers (public/total)", ext_text))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Services Hosted On This Host"))
    local_services = [
        item
        for item in (summary.services or [])
        if str(item.get("role", "")).lower() == "server"
        and str(item.get("asset", "")).startswith(f"{target_ip}:")
    ]
    if local_services:
        rows = [
            ["Service", "Port", "Proto", "Detection", "Software", "Packets", "Bytes", "Clients"]
        ]
        for item in local_services:
            # Be honest about how the listening service was confirmed: only TCP
            # services seen complete a 3-way handshake; UDP services are merely
            # observed by direction and are NOT SYN/ACK-confirmed.
            if bool(item.get("handshake_confirmed")):
                detection = "SYN/ACK"
            else:
                detection = str(item.get("discovery_method", "observed") or "observed")
            rows.append(
                [
                    str(item.get("service", "-")),
                    str(item.get("port", "-")),
                    str(item.get("protocol", "-")),
                    detection,
                    _truncate_text(str(item.get("software", "-") or "-"), 32),
                    str(item.get("packets", "-")),
                    format_bytes_as_mb(int(item.get("bytes", 0) or 0)),
                    _truncate_text(str(item.get("peers", "-") or "-"), 36),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No listening services were attributed to this host."))

    if not verbose:
        web_items = [
            item
            for item in (summary.web_requests or [])
            if str(item.get("src_ip", "")) == target_ip
        ]
        dns_items = [
            item
            for item in (summary.dns_queries or [])
            if str(item.get("src_ip", "")) == target_ip
        ]
        download_items = [
            item
            for item in (summary.file_transfers or [])
            if str(item.get("direction", "")).lower() == "download"
            and str(item.get("dst_ip", "")) == target_ip
        ]
        outbound_conversations = [
            item
            for item in (summary.conversations or [])
            if str(item.get("direction", "")).lower() == "outbound"
            and str(item.get("peer", ""))
            and str(item.get("peer", "")) != target_ip
        ]

        unique_web_targets = {
            str(item.get("dst_ip", "") or "")
            for item in web_items
            if str(item.get("dst_ip", "") or "")
        }
        unique_dns_names = {
            str(item.get("name", "") or "")
            for item in dns_items
            if str(item.get("name", "") or "")
        }
        remote_peers = {
            str(item.get("peer", "") or "")
            for item in outbound_conversations
            if str(item.get("peer", "") or "")
        }

        top_web_risk = sorted(
            web_items,
            key=lambda item: int(item.get("risk_score", 0) or 0),
            reverse=True,
        )[: _limit_value(3)]

        top_dns_counts: Counter[str] = Counter(
            str(item.get("name", "-") or "-") for item in dns_items
        )

        top_remote = sorted(
            outbound_conversations,
            key=lambda item: int(item.get("bytes", 0) or 0),
            reverse=True,
        )[: _limit_value(3)]

        total_download_bytes = 0
        download_names: Counter[str] = Counter()
        for item in download_items:
            total_download_bytes += int(
                item.get("size_bytes") or item.get("bytes") or 0
            )
            filename = str(item.get("filename", "-") or "-")
            download_names[filename] += 1

        lines.append(SUBSECTION_BAR)
        lines.append(header("Non-Essential Activity Summary"))
        lines.append(
            _format_kv(
                "Web Requests",
                f"{len(web_items)} events across {len(unique_web_targets)} remote targets",
            )
        )
        lines.append(
            _format_kv(
                "Remote Service Conversations",
                f"{len(outbound_conversations)} flows across {len(remote_peers)} peers",
            )
        )
        lines.append(
            _format_kv(
                "DNS Queries",
                f"{len(dns_items)} events across {len(unique_dns_names)} unique names",
            )
        )
        lines.append(
            _format_kv(
                "Downloads",
                f"{len(download_items)} events totaling {format_bytes_as_mb(total_download_bytes) if total_download_bytes else '-'}",
            )
        )

        if top_web_risk:
            lines.append(muted("Top risky web requests:"))
            for item in top_web_risk:
                req = f"{item.get('host', '-')}{item.get('uri', '')}"
                lines.append(
                    muted(
                        f"- {item.get('method', '-')} {_truncate_text(req, 64)} risk={item.get('risk_level', '-')}({item.get('risk_score', 0)}) status={item.get('response_code', '-')}"
                    )
                )

        top_dns = top_dns_counts.most_common(_limit_value(3))
        if top_dns:
            lines.append(muted("Top DNS queries:"))
            for name, count in top_dns:
                lines.append(muted(f"- {_truncate_text(name, 72)} ({count})"))

        if top_remote:
            lines.append(muted("Top remote services by bytes:"))
            for item in top_remote:
                lines.append(
                    muted(
                        f"- {item.get('peer', '-')} proto={item.get('protocol', '-')} bytes={format_bytes_as_mb(int(item.get('bytes', 0) or 0))} packets={item.get('packets', '-')}"
                    )
                )

        top_downloads = download_names.most_common(_limit_value(3))
        if top_downloads:
            lines.append(muted("Top downloaded filenames:"))
            for name, count in top_downloads:
                lines.append(muted(f"- {_truncate_text(name, 60)} ({count})"))

        lines.append(
            muted("Use -v to expand full rows, timestamps, and detailed context tables.")
        )
        lines.append(SECTION_BAR)
        return _finalize_output(lines, show_truncation_note=False)

    lines.append(SUBSECTION_BAR)
    lines.append(header("Web Requests Made By Host"))
    web_requests = [
        item
        for item in (summary.web_requests or [])
        if str(item.get("src_ip", "")) == target_ip
    ]
    ordered_requests: list[
        tuple[tuple[str, str, str, str, str, str, str], dict[str, object]]
    ] = []
    if web_requests:
        grouped_requests: dict[
            tuple[str, str, str, str, str, str, str], dict[str, object]
        ] = {}
        for item in web_requests:
            request_value = f"{item.get('host', '-')}{item.get('uri', '')}"
            status_code = item.get("response_code")
            status_name = str(item.get("response_name", "") or "")
            status_text = "-"
            if status_code:
                status_text = str(status_code)
                if status_name and status_name != "-":
                    status_text = f"{status_text} {status_name}"
            key = (
                str(item.get("method", "-")),
                request_value,
                str(item.get("dst_ip", "-")),
                str(item.get("dst_port", "-")),
                status_text,
                str(item.get("risk_level", "-")),
                str(item.get("risk_score", "-")),
            )
            bucket = grouped_requests.setdefault(
                key,
                {
                    "count": 0,
                    "first": item.get("ts"),
                    "last": item.get("ts"),
                    "first_packet": _packet_number_hint(item),
                },
            )
            bucket["count"] = int(bucket.get("count", 0) or 0) + 1
            packet_text = _packet_number_hint(item)
            if bucket.get("first_packet") in {None, "-", ""} and packet_text != "-":
                bucket["first_packet"] = packet_text
            ts = item.get("ts")
            if isinstance(ts, (int, float)) and (
                bucket.get("first") is None or ts < bucket.get("first")
            ):
                bucket["first"] = ts
            if isinstance(ts, (int, float)) and (
                bucket.get("last") is None or ts > bucket.get("last")
            ):
                bucket["last"] = ts

        rows = [
            ["Method", "Request", "Remote", "Status", "Risk", "Hits", "First", "Last"]
        ]
        ordered_requests = sorted(
            grouped_requests.items(),
            key=lambda item: int(item[1].get("count", 0) or 0),
            reverse=True,
        )
        for (
            method,
            request_value,
            dst_ip,
            dst_port,
            status_text,
            risk_level,
            risk_score,
        ), bucket in ordered_requests:
            rows.append(
                [
                    method,
                    _truncate_text(request_value, 58),
                    f"{dst_ip}:{dst_port}",
                    status_text,
                    f"{risk_level} ({risk_score})",
                    str(bucket.get("count", "-")),
                    format_ts(bucket.get("first")),
                    format_ts(bucket.get("last")),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No web requests from this host were identified."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Remote Services Established By Host"))
    remote_agg: dict[tuple[str, str, str], dict[str, object]] = {}
    sorted_rows: list[tuple[tuple[str, str, str], dict[str, object]]] = []
    for conv in summary.conversations or []:
        peer = str(conv.get("peer", "") or "")
        if not peer or peer == target_ip:
            continue
        proto = str(conv.get("protocol", "-") or "-")
        # Only the peer's confirmed service ports count as a remote service this
        # host connected to. This is role-aware (handshake-derived), so a host
        # that merely *received* inbound connections — its own responses share
        # the same IP-pair conversation — is not mislabeled as having reached
        # out, and the peer's/host's ephemeral source ports are never listed.
        service_ports = conv.get("remote_service_ports") or []
        ports = [str(int(p)) for p in service_ports]
        if not ports:
            continue
        for port in ports:
            service_name = COMMON_PORTS.get(int(port), "-") if port.isdigit() else "-"
            key = (peer, port, proto)
            row = remote_agg.setdefault(
                key,
                {
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": conv.get("first_seen"),
                    "last_seen": conv.get("last_seen"),
                    "service": service_name,
                    "first_packet": _packet_number_hint(conv),
                },
            )
            row["packets"] = int(row.get("packets", 0) or 0) + int(
                conv.get("packets", 0) or 0
            )
            row["bytes"] = int(row.get("bytes", 0) or 0) + int(
                conv.get("bytes", 0) or 0
            )
            packet_text = _packet_number_hint(conv)
            if row.get("first_packet") in {None, "-", ""} and packet_text != "-":
                row["first_packet"] = packet_text
            first_seen = conv.get("first_seen")
            if isinstance(first_seen, (int, float)) and (
                row.get("first_seen") is None or first_seen < row.get("first_seen")
            ):
                row["first_seen"] = first_seen
            last_seen = conv.get("last_seen")
            if isinstance(last_seen, (int, float)) and (
                row.get("last_seen") is None or last_seen > row.get("last_seen")
            ):
                row["last_seen"] = last_seen

    if remote_agg:
        rows = [
            [
                "Remote Host",
                "Port",
                "Service",
                "Access",
                "Proto",
                "Packets",
                "Bytes",
                "First",
                "Last",
            ]
        ]
        sorted_rows = sorted(
            remote_agg.items(),
            key=lambda item: int(item[1].get("bytes", 0) or 0),
            reverse=True,
        )
        for (peer, port, proto), data in sorted_rows:
            access_flag, access_paint = _hd_remote_access_flag(
                port, int(data.get("bytes", 0) or 0), _is_public_ip(peer)
            )
            peer_cell = access_paint(peer) if access_flag != "-" else peer
            rows.append(
                [
                    peer_cell,
                    port,
                    str(data.get("service", "-")),
                    access_paint(access_flag) if access_flag != "-" else "-",
                    proto,
                    str(data.get("packets", "-")),
                    format_bytes_as_mb(int(data.get("bytes", 0) or 0)),
                    format_ts(data.get("first_seen")),
                    format_ts(data.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))
        if any(
            _hd_remote_access_flag(
                p, int(d.get("bytes", 0) or 0), _is_public_ip(pe)
            )[0]
            not in ("-",)
            for (pe, p, _pr), d in sorted_rows
        ):
            lines.append(
                muted(
                    "Access column: REMOTE-ACCESS = interactive/admin protocol; "
                    "SUSP-C2 = sustained session to a non-standard high port."
                )
            )
    else:
        lines.append(
            muted("No remote services established by this host were identified.")
        )

    # ---- Remote Access INTO This Host (inbound sessions) -------------------
    lines.append(SUBSECTION_BAR)
    lines.append(header("Remote Access Into This Host"))
    inbound_agg: dict[tuple[str, str, str], dict[str, object]] = {}
    for conv in summary.conversations or []:
        peer = str(conv.get("peer", "") or "")
        if not peer or peer == target_ip:
            continue
        local_ports = conv.get("local_service_ports") or []
        proto = str(conv.get("protocol", "-") or "-")
        for port in local_ports:
            port = int(port)
            if port not in _HD_REMOTE_ACCESS_PORTS:
                continue
            key = (peer, str(port), proto)
            row = inbound_agg.setdefault(
                key,
                {
                    "packets": 0,
                    "bytes": 0,
                    "first_seen": conv.get("first_seen"),
                    "last_seen": conv.get("last_seen"),
                    "service": _HD_REMOTE_ACCESS_PORTS[port],
                },
            )
            row["packets"] = int(row.get("packets", 0) or 0) + int(conv.get("packets", 0) or 0)
            row["bytes"] = int(row.get("bytes", 0) or 0) + int(conv.get("bytes", 0) or 0)
            fs = conv.get("first_seen")
            if isinstance(fs, (int, float)) and (row.get("first_seen") is None or fs < row["first_seen"]):
                row["first_seen"] = fs
            ls = conv.get("last_seen")
            if isinstance(ls, (int, float)) and (row.get("last_seen") is None or ls > row["last_seen"]):
                row["last_seen"] = ls
    if inbound_agg:
        rows = [["Connecting Peer", "Scope", "Port", "Service", "Proto", "Packets", "Bytes", "First", "Last"]]
        for (peer, port, proto), data in sorted(
            inbound_agg.items(), key=lambda it: int(it[1].get("bytes", 0) or 0), reverse=True
        ):
            external = _is_public_ip(peer)
            paint = danger if external else orange
            rows.append(
                [
                    paint(peer),
                    danger("EXTERNAL") if external else "internal",
                    port,
                    paint(str(data.get("service", "-"))),
                    proto,
                    str(data.get("packets", "-")),
                    format_bytes_as_mb(int(data.get("bytes", 0) or 0)),
                    format_ts(data.get("first_seen")),
                    format_ts(data.get("last_seen")),
                ]
            )
        lines.append(_format_table(rows))
        lines.append(
            warn(
                "Inbound interactive/admin access to this host — confirm it is authorized "
                "(jump box / admin session) vs. lateral movement or unauthorized access."
            )
        )
    else:
        lines.append(muted("No inbound remote-access sessions to this host were identified."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("DNS Queries Made By Host"))
    dns_items = [
        item
        for item in (summary.dns_queries or [])
        if str(item.get("src_ip", "")) == target_ip
    ]
    sorted_dns: list[tuple[tuple[str, str], dict[str, object]]] = []
    if dns_items:
        dns_agg: dict[tuple[str, str], dict[str, object]] = {}
        for item in dns_items:
            name = str(item.get("name", "-") or "-")
            qtype = str(item.get("qtype", "-") or "-")
            key = (name, qtype)
            row = dns_agg.setdefault(
                key,
                {
                    "count": 0,
                    "first": item.get("ts"),
                    "last": item.get("ts"),
                    "first_packet": _packet_number_hint(item),
                },
            )
            row["count"] = int(row.get("count", 0) or 0) + 1
            packet_text = _packet_number_hint(item)
            if row.get("first_packet") in {None, "-", ""} and packet_text != "-":
                row["first_packet"] = packet_text
            ts = item.get("ts")
            if isinstance(ts, (int, float)) and (
                row.get("first") is None or ts < row.get("first")
            ):
                row["first"] = ts
            if isinstance(ts, (int, float)) and (
                row.get("last") is None or ts > row.get("last")
            ):
                row["last"] = ts

        rows = [["Query", "Type", "Count", "First", "Last"]]
        sorted_dns = sorted(
            dns_agg.items(),
            key=lambda item: int(item[1].get("count", 0) or 0),
            reverse=True,
        )
        for (name, qtype), data in sorted_dns:
            rows.append(
                [
                    _truncate_text(name, 56),
                    qtype,
                    str(data.get("count", "-")),
                    format_ts(data.get("first")),
                    format_ts(data.get("last")),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No DNS queries made by this host were identified."))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Files Downloaded By Host"))
    downloads = [
        item
        for item in (summary.file_transfers or [])
        if str(item.get("direction", "")).lower() == "download"
        and str(item.get("dst_ip", "")) == target_ip
    ]
    ordered_downloads: list[
        tuple[tuple[str, str, str, str, str], dict[str, object]]
    ] = []
    if downloads:
        grouped_downloads: dict[tuple[str, str, str, str, str], dict[str, object]] = {}
        for item in downloads:
            size_value = int(item.get("size_bytes") or item.get("bytes") or 0)
            src_port = item.get("src_port")
            src_port_text = str(src_port) if src_port is not None else "-"
            source_text = f"{item.get('src_ip', '-')}:{src_port_text}"
            hash_bits: list[str] = []
            sha = str(item.get("sha256", "") or "").strip()
            md5 = str(item.get("md5", "") or "").strip()
            if sha:
                hash_bits.append(f"sha256={sha[:12]}")
            if md5:
                hash_bits.append(f"md5={md5[:8]}")
            key = (
                str(item.get("filename", "-") or "-"),
                source_text,
                str(item.get("protocol", "-")),
                str(item.get("file_type", "-") or "-"),
                " ".join(hash_bits) if hash_bits else "-",
            )
            bucket = grouped_downloads.setdefault(
                key,
                {
                    "count": 0,
                    "total_bytes": 0,
                    "first": item.get("first_seen"),
                    "last": item.get("last_seen"),
                    "first_packet": _packet_number_hint(item),
                },
            )
            bucket["count"] = int(bucket.get("count", 0) or 0) + 1
            bucket["total_bytes"] = int(bucket.get("total_bytes", 0) or 0) + size_value
            packet_text = _packet_number_hint(item)
            if (
                bucket.get("first_packet") in {None, "-", ""}
                and packet_text != "-"
            ):
                bucket["first_packet"] = packet_text
            first_seen = item.get("first_seen")
            if isinstance(first_seen, (int, float)) and (
                bucket.get("first") is None or first_seen < bucket.get("first")
            ):
                bucket["first"] = first_seen
            last_seen = item.get("last_seen")
            if isinstance(last_seen, (int, float)) and (
                bucket.get("last") is None or last_seen > bucket.get("last")
            ):
                bucket["last"] = last_seen

        rows = [
            [
                "Filename",
                "Source",
                "Proto",
                "Type",
                "Hashes",
                "Events",
                "Total Size",
                "First",
                "Last",
            ]
        ]
        ordered_downloads = sorted(
            grouped_downloads.items(),
            key=lambda item: int(item[1].get("total_bytes", 0) or 0),
            reverse=True,
        )
        for (
            filename,
            source_text,
            proto,
            file_type,
            hashes,
        ), bucket in ordered_downloads:
            total_size = int(bucket.get("total_bytes", 0) or 0)
            rows.append(
                [
                    _truncate_text(filename, 36),
                    source_text,
                    proto,
                    _truncate_text(file_type, 20),
                    hashes,
                    str(bucket.get("count", "-")),
                    format_bytes_as_mb(total_size) if total_size else "-",
                    format_ts(bucket.get("first")),
                    format_ts(bucket.get("last")),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No downloaded files attributed to this host."))

    # ---- Authentication Activity (who authenticated where, cleartext creds) --
    auth_events = list(getattr(summary, "auth_events", []) or [])
    if auth_events:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Authentication Activity"))
        rows = [["Time", "Proto", "Dir", "Peer", "Account", "Secret", "Kind"]]
        for ev in auth_events[: _limit_value(20)]:
            secret_cell = danger("EXPOSED") if ev.get("secret_exposed") else "-"
            rows.append(
                [
                    format_ts(ev.get("ts")),
                    str(ev.get("protocol", "-")),
                    str(ev.get("direction", "-")),
                    str(ev.get("peer", "-")),
                    _redact_in_text(str(ev.get("username", "-"))),
                    secret_cell,
                    _truncate_text(str(ev.get("kind", "-")), 22),
                ]
            )
        lines.append(_format_table(rows))
        if any(ev.get("secret_exposed") for ev in auth_events):
            lines.append(danger("Cleartext credential material exposed for this host — rotate affected accounts."))

    # ---- TLS Fingerprints (SNI/JA3 this host presented as a client) ----------
    tls_fp = list(getattr(summary, "tls_fingerprints", []) or [])
    if tls_fp:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS / Encryption Fingerprints (as client)"))
        rows = [["SNI (server name)", "Sessions", "JA3"]]
        for fp in tls_fp[: _limit_value(15)]:
            rows.append(
                [
                    _truncate_text(_highlight_public_ips(str(fp.get("sni", "-"))), 52),
                    str(fp.get("count", "-")),
                    str(fp.get("ja3", "-")),
                ]
            )
        lines.append(_format_table(rows))

    # ---- SMB / File-Share Access --------------------------------------------
    smb_access = list(getattr(summary, "smb_access", []) or [])
    if smb_access:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB / File-Share Access"))
        rows = [["Role", "Peer", "Shares", "Account", "SMB Ver", "Signing"]]
        for sa in smb_access[: _limit_value(15)]:
            shares_txt = str(sa.get("shares", "-"))
            is_admin = bool(sa.get("admin")) or any(
                m in shares_txt for m in ("ADMIN$", "C$", "D$")
            )
            signing = str(sa.get("signing", "-"))
            rows.append(
                [
                    str(sa.get("role", "-")),
                    str(sa.get("peer", "-")),
                    danger(shares_txt) if is_admin else shares_txt,
                    _redact_in_text(str(sa.get("user", "-"))),
                    str(sa.get("version", "-")),
                    danger(signing) if signing == "no" else signing,
                ]
            )
        lines.append(_format_table(rows))
        if any(bool(sa.get("admin")) for sa in smb_access):
            lines.append(warn("Administrative-share access observed — review for lateral movement (PsExec-style)."))

    # ---- Email Activity ------------------------------------------------------
    email_activity = list(getattr(summary, "email_activity", []) or [])
    if email_activity:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Email Activity"))
        role_txt = str(email_activity[0].get("role", "-")) if email_activity else "-"
        lines.append(_format_kv("Host Email Role", role_txt))
        rows = [["Field", "Value", "Count"]]
        for em in email_activity[: _limit_value(18)]:
            field_name = str(em.get("field", "-"))
            value = str(em.get("value", "-"))
            value_cell = danger(value) if field_name == "Password" else _redact_in_text(value)
            rows.append(
                [field_name, _truncate_text(value_cell, 56), str(em.get("count", "-"))]
            )
        lines.append(_format_table(rows))

    # ---- Peer Intelligence (geo / ASN / IOC on the host's peers) -------------
    peer_intel = list(getattr(summary, "peer_intel", []) or [])
    if peer_intel:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Peer Intelligence (Geo / ASN / IOC)"))
        rows = [["Peer", "Scope", "Geo / ASN / Org", "Flags", "Intel", "Pkts"]]
        for pi in peer_intel[: _limit_value(20)]:
            external = str(pi.get("scope")) == "external"
            intel_txt = str(pi.get("intel", "-"))
            has_intel = intel_txt not in ("-", "")
            peer_cell = danger(str(pi.get("peer", "-"))) if (external and has_intel) else str(pi.get("peer", "-"))
            rows.append(
                [
                    peer_cell,
                    str(pi.get("scope", "-")),
                    _truncate_text(str(pi.get("geo", "-")), 34),
                    str(pi.get("flags", "-")),
                    danger(_truncate_text(intel_txt, 40)) if has_intel else "-",
                    str(pi.get("packets", "-")),
                ]
            )
        lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)
