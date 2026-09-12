"""Rendered output for smb analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from collections import Counter
from ..coloring import (
    danger,
    header,
    muted,
    ok,
    warn,
)
from ..smb import SmbSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _conv_value,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _limit_value,
    _redact_in_text,
    _render_deterministic_checks,
    _render_protocol_verdict,
    _truncate_text,
    _verbose_output,
)


def render_smb_summary(summary: SmbSummary, verbose: bool = False) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"SMB PROTOCOL ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_protocol_verdict(
        lines, label="SMB", anomalies=getattr(summary, "anomalies", None)
    )
    effective_verbose = _verbose_output() or verbose

    def _preview_values(
        values: object, limit: int = 3, max_len: int = 60, show_count: bool = True
    ) -> str:
        if not values:
            return "-"
        if effective_verbose:
            items: list[str]
            if isinstance(values, (set, list, tuple)):
                items = sorted(str(v) for v in values)
            else:
                try:
                    items = sorted(str(v) for v in list(values))
                except Exception:
                    items = [str(values)]
            if not items:
                return "-"
            return ", ".join(_redact_in_text(item) for item in items)
        items: list[str]
        if isinstance(values, (set, list, tuple)):
            items = sorted(str(v) for v in values)
        else:
            try:
                items = sorted(str(v) for v in list(values))
            except Exception:
                items = [str(values)]
        if not items:
            return "-"
        total = len(items)
        preview = items[:limit]
        text = ", ".join(_redact_in_text(item) for item in preview)
        if total > limit:
            text = f"{text} (+{total - limit} more)"
        if show_count and total > limit:
            text = f"{total}: {text}"
        return _truncate_text(text, max_len)

    def _looks_like_smb_token(value: str) -> bool:
        if not value:
            return False
        token = value.strip()
        if token in {"-", "(unknown)"}:
            return False
        if len(token) < 2 or len(token) > 64:
            return False
        if not any(ch.isalpha() for ch in token):
            return False
        allowed = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@$ "
        )
        if any(ch not in allowed for ch in token):
            return False
        return True

    def _smb_preview_tokens(
        values: object, limit: int = 3, max_len: int = 60
    ) -> tuple[str, bool]:
        if not values:
            return "-", False
        if effective_verbose:
            items: list[str]
            if isinstance(values, (set, list, tuple)):
                items = sorted(str(v) for v in values)
            else:
                try:
                    items = sorted(str(v) for v in list(values))
                except Exception:
                    items = [str(values)]
            if not items:
                return "-", False
            return ", ".join(_redact_in_text(item) for item in items), False
        items: list[str]
        if isinstance(values, (set, list, tuple)):
            items = sorted(str(v) for v in values)
        else:
            try:
                items = sorted(str(v) for v in list(values))
            except Exception:
                items = [str(values)]
        if not items:
            return "-", False
        total = len(items)
        filtered = [item for item in items if _looks_like_smb_token(item)]
        used = filtered if filtered else items
        preview = used[:limit]
        text = ", ".join(_redact_in_text(item) for item in preview)
        if len(used) > limit:
            text = f"{text} (+{len(used) - limit} more)"
        if total > limit:
            if filtered and len(filtered) != total:
                text = f"{total} ({len(filtered)} filtered): {text}"
            else:
                text = f"{total}: {text}"
        return _truncate_text(text, max_len), bool(filtered and len(filtered) != total)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    if getattr(summary, "analysis_notes", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes:
            lines.append(muted(f"- {note}"))

    lines.append(_format_kv("SMB Packets", str(summary.smb_packets)))
    if getattr(summary, "smb_ports", None):
        ports_text = (
            ", ".join(
                f"{port} ({count})"
                for port, count in summary.smb_ports.most_common(_limit_value(6))
            )
            if summary.smb_ports
            else "-"
        )
        lines.append(_format_kv("SMB Ports", ports_text))
    versions_text = (
        ", ".join([f"{k} ({v})" for k, v in summary.versions.items()])
        if summary.versions
        else "-"
    )
    lines.append(_format_kv("SMB Versions", versions_text))
    lines.append(_format_kv("Unique Clients", str(len(summary.clients))))
    lines.append(_format_kv("Unique Servers", str(len(summary.servers))))
    lines.append(_format_kv("Sessions", str(len(summary.sessions))))
    if getattr(summary, "signed_packets", 0) or getattr(summary, "unsigned_packets", 0):
        signed_text = (
            f"{summary.signed_packets} signed / {summary.unsigned_packets} unsigned"
        )
        lines.append(_format_kv("Signed Packets", signed_text))
    if getattr(summary, "encrypted_packets", 0):
        encrypted_sessions = sum(
            1 for sess in summary.sessions if getattr(sess, "encrypted", False)
        )
        lines.append(_format_kv("Encrypted Packets", str(summary.encrypted_packets)))
        lines.append(_format_kv("Encrypted Sessions", str(encrypted_sessions)))

    if summary.versions.get("SMB1"):
        lines.append(
            danger(
                f"SMBv1 DETECTED: {summary.versions['SMB1']} packets! Legacy/Insecure."
            )
        )

    # 0. Request/Response Summary
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Requests vs Responses"))
    if not summary.requests and not summary.responses:
        lines.append(muted("No SMB command directionality captured."))
    else:
        rows = [["Command", "Requests", "Responses"]]
        all_cmds = []
        for cmd in set(summary.requests.keys()).union(summary.responses.keys()):
            req = summary.requests.get(cmd, 0)
            resp = summary.responses.get(cmd, 0)
            total = req + resp
            all_cmds.append((cmd, req, resp, total))
        all_cmds.sort(key=lambda item: item[3], reverse=True)
        limit = _limit_value(20)
        for cmd, req, resp, _total in all_cmds[:limit]:
            rows.append([cmd, str(req), str(resp)])
        lines.append(_format_table(rows))
        if len(all_cmds) > limit:
            lines.append(muted(f"Showing top {limit} commands by volume."))

    # 1. Top Commands
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top SMB Commands"))
    if not summary.commands:
        lines.append(muted("No command usage stats."))
    else:
        lines.append(_counter_table(summary.commands, "Command", limit=_limit_value(10)))

    # 2. Shares Accessed
    if summary.shares:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Shares Accessed"))
        rows = [["Server", "Share Path", "Count", "Type"]]
        for s in summary.shares:
            stype = "Admin" if s.is_admin else "Normal"
            rows.append(
                [
                    s.server_ip,
                    _truncate_text(_redact_in_text(str(s.name)), 60),
                    str(s.connect_count),
                    stype,
                ]
            )
        lines.append(_format_table(rows))

    # 3. Top Clients/Servers
    lines.append(SUBSECTION_BAR)
    lines.append(header("Top Clients"))
    rows = [["Client IP", "Packets"]]
    for ip, count in summary.top_clients.most_common(_limit_value(5)):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))

    lines.append("")
    lines.append(header("Top Servers"))
    rows = [["Server IP", "Packets"]]
    for ip, count in summary.top_servers.most_common(_limit_value(5)):
        rows.append([ip, str(count)])
    lines.append(_format_table(rows))

    # 4. Error Codes / Failures
    if summary.error_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Error/Status Codes"))
        lines.append(_counter_table(summary.error_codes, "Status Code", limit=_limit_value(10)))

    # 5. Conversations
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Conversations"))
    if not summary.conversations:
        lines.append(muted("No SMB conversations summarized."))
    else:
        lines.append(
            _format_sessions_table(
                summary.conversations,
                _limit_value(10),
                extra_cols=[
                    ("Requests", lambda c: _conv_value(c, "requests") or 0),
                    ("Responses", lambda c: _conv_value(c, "responses") or 0),
                ],
            )
        )

    # 6. Server Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Servers"))
    if not summary.servers:
        lines.append(muted("No SMB servers identified."))
    else:
        rows = [["Server", "Dialects", "Signing Required", "Shares", "Capabilities"]]
        for srv in summary.servers:
            dialects = _preview_values(srv.dialects, limit=3, max_len=50)
            signing = (
                "Yes"
                if srv.signing_required
                else ("No" if srv.signing_required is not None else "-")
            )
            if effective_verbose:
                shares = _preview_values(
                    srv.shares,
                    limit=_FULL_OUTPUT_LIMIT,
                    max_len=_FULL_OUTPUT_LIMIT,
                    show_count=False,
                )
                caps = _preview_values(
                    srv.capabilities,
                    limit=_FULL_OUTPUT_LIMIT,
                    max_len=_FULL_OUTPUT_LIMIT,
                    show_count=False,
                )
            else:
                shares = _preview_values(srv.shares, limit=1, max_len=80)
                caps = _preview_values(srv.capabilities, limit=3, max_len=60)
            rows.append([srv.ip, dialects, signing, shares, caps])
        lines.append(_format_table(rows))

    # 7. Client Inventory
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Clients"))
    if not summary.clients:
        lines.append(muted("No SMB clients identified."))
    else:
        rows = [["Client", "Dialects", "Client GUID", "Users", "Domains"]]
        filtered_notice = False
        for cli in summary.clients:
            dialects = _preview_values(cli.dialects, limit=3, max_len=50)
            guid = cli.client_guid or "-"
            if effective_verbose:
                users = _preview_values(
                    cli.usernames,
                    limit=_FULL_OUTPUT_LIMIT,
                    max_len=_FULL_OUTPUT_LIMIT,
                    show_count=False,
                )
                domains = _preview_values(
                    cli.domains,
                    limit=_FULL_OUTPUT_LIMIT,
                    max_len=_FULL_OUTPUT_LIMIT,
                    show_count=False,
                )
                users_filtered = False
                domains_filtered = False
            else:
                users, users_filtered = _smb_preview_tokens(
                    cli.usernames, limit=3, max_len=60
                )
                domains, domains_filtered = _smb_preview_tokens(
                    cli.domains, limit=3, max_len=60
                )
                if users_filtered or domains_filtered:
                    filtered_notice = True
            rows.append([cli.ip, dialects, guid, users, domains])
        lines.append(_format_table(rows))
        noisy_clients = [
            cli.ip
            for cli in summary.clients
            if (
                len(getattr(cli, "usernames", [])) > 20
                or len(getattr(cli, "domains", [])) > 20
            )
        ]
        if noisy_clients:
            if not effective_verbose:
                lines.append(
                    muted(
                        "Large user/domain lists may include noisy string extraction; use -v for full lists."
                    )
                )
        if filtered_notice:
            if not effective_verbose:
                lines.append(
                    muted(
                        "User/domain previews are filtered for readable tokens; use -v for raw lists."
                    )
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Usernames"))
    if summary.observed_users:
        rows = [["Username", "Count"]]
        for name, count in summary.observed_users.most_common(_limit_value(25)):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No SMB usernames discovered."))

    discovered_hosts = Counter()
    for sess in summary.sessions:
        workstation = getattr(sess, "workstation", None)
        if workstation:
            discovered_hosts[str(workstation)] += 1
    for cli in summary.clients:
        for workstation in getattr(cli, "workstations", []) or []:
            if workstation not in discovered_hosts:
                discovered_hosts[str(workstation)] += 1
    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Hostnames"))
    if discovered_hosts:
        rows = [["Hostname", "Count"]]
        for name, count in discovered_hosts.most_common(_limit_value(25)):
            rows.append([_truncate_text(_redact_in_text(str(name)), 48), str(count)])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No SMB hostnames discovered."))

    # 8. Sessions
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Sessions"))
    if not summary.sessions:
        lines.append(muted("No SMB sessions decoded."))
    else:
        client_user_map = {}
        client_domain_map = {}
        client_workstation_map = {}
        client_workstation_candidates = {}
        for cli in summary.clients:
            if len(cli.usernames) == 1:
                client_user_map[cli.ip] = next(iter(cli.usernames))
            if len(cli.domains) == 1:
                client_domain_map[cli.ip] = next(iter(cli.domains))
            if getattr(cli, "workstations", None) and len(cli.workstations) == 1:
                client_workstation_map[cli.ip] = next(iter(cli.workstations))
            if getattr(cli, "workstation_candidates", None):
                client_workstation_candidates[cli.ip] = list(cli.workstation_candidates)
        rows = [
            [
                "Client",
                "Server",
                "Session",
                "Version",
                "User",
                "Domain",
                "Workstation",
                "Auth",
                "Signing Req",
                "Signing Used",
                "Encrypt Req",
                "Encrypted",
                "Packets",
                "Bytes",
                "First Seen",
                "Last Seen",
                "Duration",
            ]
        ]
        for sess in summary.sessions:
            display_user = sess.username or client_user_map.get(sess.client_ip) or "-"
            display_domain = sess.domain or client_domain_map.get(sess.client_ip) or "-"
            display_workstation = (
                sess.workstation or client_workstation_map.get(sess.client_ip) or "-"
            )
            signed_used = "-"
            if getattr(sess, "signed_packets", 0) and getattr(
                sess, "unsigned_packets", 0
            ):
                signed_used = "Mixed"
            elif getattr(sess, "signed_packets", 0):
                signed_used = "Yes"
            elif getattr(sess, "unsigned_packets", 0):
                signed_used = "No"
            encrypt_req = (
                "Yes"
                if getattr(sess, "encryption_required", None)
                else ("No" if sess.encryption_required is not None else "-")
            )
            encrypted = "Yes" if getattr(sess, "encrypted", False) else "No"
            duration = None
            if sess.start_ts and sess.last_seen:
                duration = max(0.0, sess.last_seen - sess.start_ts)
            rows.append(
                [
                    sess.client_ip,
                    sess.server_ip,
                    str(sess.session_id) if sess.session_id is not None else "-",
                    sess.smb_version or "-",
                    _truncate_text(_redact_in_text(str(display_user)), 30)
                    if display_user
                    else "-",
                    _truncate_text(_redact_in_text(str(display_domain)), 30)
                    if display_domain
                    else "-",
                    _truncate_text(_redact_in_text(str(display_workstation)), 30)
                    if display_workstation
                    else "-",
                    _truncate_text(_redact_in_text(str(sess.auth_type)), 20)
                    if sess.auth_type
                    else "-",
                    "Yes"
                    if sess.signing_required
                    else ("No" if sess.signing_required is not None else "-"),
                    signed_used,
                    encrypt_req,
                    encrypted,
                    str(sess.packets),
                    format_bytes_as_mb(sess.bytes) if sess.bytes else "-",
                    format_ts(sess.start_ts if sess.start_ts else None),
                    format_ts(sess.last_seen if sess.last_seen else None),
                    format_duration(duration),
                ]
            )
        lines.append(_format_table(rows))

        if verbose and client_workstation_candidates:
            lines.append(SUBSECTION_BAR)
            lines.append(header("Workstation Candidates (Raw)"))
            rows = [["Client", "Candidates"]]
            for ip in sorted(client_workstation_candidates.keys()):
                candidates = sorted(client_workstation_candidates.get(ip, []))
                preview = ", ".join(
                    _truncate_text(_redact_in_text(c), 30)
                    for c in candidates[: _limit_value(10)]
                )
                if len(candidates) > _limit_value(10):
                    preview += f" (+{len(candidates) - _limit_value(10)} more)"
                rows.append([ip, preview or "-"])
            lines.append(_format_table(rows))

    # 9. Files and Artifacts
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Files & Artifacts"))
    if summary.files:
        suspicious_ext = {
            ".exe",
            ".dll",
            ".ps1",
            ".bat",
            ".vbs",
            ".js",
            ".scr",
            ".sys",
            ".lnk",
            ".zip",
            ".rar",
            ".7z",
        }
        known_ops: dict[tuple[str, str, str, str], dict[str, object]] = {}
        unknown_ops: dict[tuple[str, str, str, str], dict[str, object]] = {}

        def _is_unknown(name: str | None) -> bool:
            if not name:
                return True
            lowered = name.lower()
            return lowered.startswith("(unknown") or lowered in {"-", "unknown"}

        for item in summary.files:
            filename = item.filename or "(unknown)"
            share = item.share or "-"
            client = item.client_ip or "-"
            server = item.server_ip or "-"
            size = int(item.size or 0)
            ts = item.ts or 0.0
            action = item.action or "Op"
            file_id = item.file_id or ""
            if _is_unknown(filename):
                ukey = (action, share, client, server)
                entry = unknown_ops.setdefault(
                    ukey,
                    {
                        "action": action,
                        "share": share,
                        "client": client,
                        "server": server,
                        "count": 0,
                        "bytes": 0,
                        "first_ts": None,
                        "last_ts": None,
                        "file_ids": set(),
                    },
                )
                entry["count"] = int(entry["count"]) + 1
                entry["bytes"] = int(entry["bytes"]) + size
                if file_id:
                    entry["file_ids"].add(file_id)
                first_ts = entry["first_ts"]
                last_ts = entry["last_ts"]
                if first_ts is None or (ts and ts < first_ts):
                    entry["first_ts"] = ts
                if last_ts is None or (ts and ts > last_ts):
                    entry["last_ts"] = ts
                continue

            key = (filename, share, client, server)
            entry = known_ops.setdefault(
                key,
                {
                    "filename": filename,
                    "share": share,
                    "client": client,
                    "server": server,
                    "actions": Counter(),
                    "bytes": 0,
                    "file_ids": set(),
                    "first_ts": None,
                    "last_ts": None,
                },
            )
            entry["actions"][action] += 1
            entry["bytes"] = int(entry["bytes"]) + size
            if item.file_id:
                entry["file_ids"].add(item.file_id)
            first_ts = entry["first_ts"]
            last_ts = entry["last_ts"]
            if first_ts is None or (ts and ts < first_ts):
                entry["first_ts"] = ts
            if last_ts is None or (ts and ts > last_ts):
                entry["last_ts"] = ts

        if known_ops or unknown_ops:
            lines.append(muted("File Operations (Aggregated)"))
            rows = [
                [
                    "File",
                    "Share",
                    "Activity",
                    "Bytes",
                    "Client",
                    "Server",
                    "First Seen",
                    "Last Seen",
                    "File IDs",
                    "Flags",
                ]
            ]

            def _known_sort(entry: dict[str, object]) -> tuple[int, int]:
                total_bytes = int(entry.get("bytes", 0))
                action_count = sum(
                    int(v) for v in entry.get("actions", Counter()).values()
                )
                return (total_bytes, action_count)

            for entry in sorted(known_ops.values(), key=_known_sort, reverse=True)[
                : _limit_value(20)
            ]:
                actions = entry.get("actions", Counter())
                action_text = (
                    ", ".join(
                        f"{name} x{count}" for name, count in actions.most_common(3)
                    )
                    if actions
                    else "-"
                )
                if actions and len(actions) > 3:
                    action_text += " …"
                filename = str(entry.get("filename", "-"))
                share = str(entry.get("share", "-"))
                flags: list[str] = []
                lower_name = filename.lower()
                if any(lower_name.endswith(ext) for ext in suspicious_ext):
                    flags.append("SuspiciousExt")
                if (
                    "admin$" in share.lower()
                    or "ipc$" in share.lower()
                    or share.lower().endswith("\\c$")
                ):
                    flags.append("AdminShare")
                if "\\pipe\\" in lower_name:
                    flags.append("NamedPipe")
                flag_text = ", ".join(flags) if flags else "-"
                file_ids = sorted(entry.get("file_ids", set()))
                file_id_text = ", ".join(file_ids[:3]) if file_ids else "-"
                if len(file_ids) > 3:
                    file_id_text += f" (+{len(file_ids) - 3} more)"
                rows.append(
                    [
                        _truncate_text(_redact_in_text(filename), 80),
                        _truncate_text(_redact_in_text(share), 60),
                        action_text,
                        format_bytes_as_mb(int(entry.get("bytes", 0)))
                        if entry.get("bytes")
                        else "-",
                        entry.get("client", "-"),
                        entry.get("server", "-"),
                        format_ts(entry.get("first_ts")),
                        format_ts(entry.get("last_ts")),
                        _truncate_text(file_id_text, 60),
                        flag_text,
                    ]
                )

            if unknown_ops:

                def _unknown_sort(entry: dict[str, object]) -> tuple[int, int]:
                    return (int(entry.get("bytes", 0)), int(entry.get("count", 0)))

                for entry in sorted(
                    unknown_ops.values(), key=_unknown_sort, reverse=True
                )[: _limit_value(15)]:
                    file_ids = sorted(entry.get("file_ids", set()))
                    file_id_text = ", ".join(file_ids[:3]) if file_ids else "-"
                    if len(file_ids) > 3:
                        file_id_text += f" (+{len(file_ids) - 3} more)"
                    rows.append(
                        [
                            "(unknown)",
                            _truncate_text(
                                _redact_in_text(str(entry.get("share", "-"))), 50
                            ),
                            f"{entry.get('action', '-')} x{entry.get('count', 0)}",
                            format_bytes_as_mb(int(entry.get("bytes", 0)))
                            if entry.get("bytes")
                            else "-",
                            entry.get("client", "-"),
                            entry.get("server", "-"),
                            format_ts(entry.get("first_ts")),
                            format_ts(entry.get("last_ts")),
                            _truncate_text(file_id_text, 60),
                            "UnknownName",
                        ]
                    )

            lines.append(_format_table(rows))

        if not known_ops and not unknown_ops:
            lines.append(muted("No SMB file operations extracted."))
    else:
        lines.append(muted("No SMB file operations extracted."))

    if summary.artifacts:
        pipes = [item for item in summary.artifacts if "\\pipe\\" in str(item).lower()]
        other = [item for item in summary.artifacts if item not in pipes]
        if pipes:
            pipe_text = ", ".join(
                _truncate_text(_redact_in_text(str(item)), 80)
                for item in pipes[: _limit_value(10)]
            )
            lines.append(muted(f"Named Pipes: {pipe_text}"))
        if other:
            safe_artifacts = ", ".join(
                _truncate_text(_redact_in_text(str(item)), 80)
                for item in other[: _limit_value(15)]
            )
            lines.append(muted(f"Artifacts: {safe_artifacts}"))

    # 10. Users & Domains
    if summary.observed_users or summary.observed_domains:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed Users & Domains"))
        if summary.observed_users:
            lines.append(_counter_table(summary.observed_users, "User", limit=_limit_value(10)))
        if summary.observed_domains:
            lines.append(_counter_table(summary.observed_domains, "Domain", limit=_limit_value(10)))

    # 11. Anomalies & Risks (summary by default, detailed with verbose)
    lines.append(SUBSECTION_BAR)
    lines.append(header("SMB Anomalies & Risks"))

    if not summary.anomalies:
        lines.append(ok("No SMB-specific anomalies detected."))
    else:
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = Counter(a.severity for a in summary.anomalies)
        rows = [["Severity", "Count", "Indicators"]]
        for sev in severity_order:
            if severity_counts.get(sev):
                indicators = Counter(
                    a.title for a in summary.anomalies if a.severity == sev
                )
                indicator_text = ", ".join(
                    f"{title} ({count})"
                    for title, count in indicators.most_common(_limit_value(5))
                )
                sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
                if sev == "LOW":
                    sev_color = muted
                rows.append(
                    [
                        sev_color(sev),
                        str(severity_counts[sev]),
                        muted(indicator_text) if indicator_text else muted("-"),
                    ]
                )
        lines.append(_format_table(rows))

        if verbose:
            lines.append("")
            for a in summary.anomalies:
                sev_color = danger if a.severity in ("CRITICAL", "HIGH") else warn
                lines.append(sev_color(f"[{a.severity}] {a.title}"))
                lines.append(f"  {a.description}")
                lines.append(muted(f"  Src: {a.src} -> Dst: {a.dst}"))
                lines.append("")

    if not summary.lateral_movement:
        lines.append(ok("No SMB lateral movement indicators detected."))
    else:
        lines.append(SUBSECTION_BAR)
        lines.append(header("SMB Lateral Movement Scoring"))
        top_scores = sorted(
            summary.lateral_movement, key=lambda x: x.get("score", 0), reverse=True
        )[: _limit_value(5)]
        rows = [["Client", "Servers", "Admin Shares", "Failures", "Score"]]
        for item in top_scores:
            rows.append(
                [
                    str(item.get("client", "-")),
                    str(item.get("servers", "-")),
                    str(item.get("admin_shares", "-")),
                    str(item.get("failures", "-")),
                    str(item.get("score", "-")),
                ]
            )
        lines.append(_format_table(rows))

        if verbose:
            lines.append(SUBSECTION_BAR)
            lines.append(header("SMB Lateral Movement Scoring (Detailed)"))
            rows = [["Client", "Servers", "Admin Shares", "Failures", "Score"]]
            for item in summary.lateral_movement[: _limit_value(10)]:
                rows.append(
                    [
                        str(item.get("client", "-")),
                        str(item.get("servers", "-")),
                        str(item.get("admin_shares", "-")),
                        str(item.get("failures", "-")),
                        str(item.get("score", "-")),
                    ]
                )
            lines.append(_format_table(rows))

    lines.append(SECTION_BAR)
    _render_deterministic_checks(
        lines, summary, "Deterministic SMB Security Checks", [
            ("smb_legacy_protocol", "Legacy SMB Protocol (SMBv1)"),
            ("smb_signing_or_encryption_gap", "Signing/Encryption Gap"),
            ("smb_auth_failure_burst", "Auth Failure Burst"),
            ("smb_admin_share_lateral", "Admin-Share Lateral Movement"),
            ("smb_sensitive_file_staging", "Sensitive File Staging"),
            ("smb_scanning_fanout", "Scanning Fan-out"),
            ("smb_beacon_or_periodicity", "Beacon/Periodicity"),
            ("smb_public_endpoint_exposure", "Public Endpoint Exposure"),
        ]
    )
    return _finalize_output(lines)
