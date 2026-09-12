"""Rendered output for enip analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
import re
from collections import Counter
from typing import TYPE_CHECKING
from ..coloring import (
    danger,
    header,
    highlight,
    label,
    muted,
    ok,
    warn,
)
from ..utils import (
    format_bytes_as_mb,
    format_speed_bps,
)
if TYPE_CHECKING:
    from ..enip import ENIPAnalysis

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _PROTO_SEV_RANK,
    _counter_table,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _normalize_finding,
    _ot_attack_for_title,
    _ot_full_render,
    _truncate_text,
)


def _render_enip_verdict(lines: list[str], summary: "ENIPAnalysis") -> None:
    """Always-on triage disposition for EtherNet/IP — states a verdict on every
    capture (incl. a benign read-only polling baseline) instead of going silent,
    mirroring the --modbus upgrade."""
    anoms = list(getattr(summary, "anomalies", []) or [])
    norm = [(_normalize_finding(a), a) for a in anoms]
    worst = max((_PROTO_SEV_RANK.get(n[0][0], 0) for n in norm), default=0)

    masters = list(getattr(summary, "masters", []) or [])
    servers = list(getattr(summary, "server_ips", {}) or {})
    reads = sum(getattr(summary, "tag_reads", Counter()).values())
    writes = int(getattr(summary, "write_service_count", 0))
    high_risk = sum(getattr(summary, "high_risk_services", Counter()).values())
    errs = int(getattr(summary, "cip_errors", 0))
    conns = len(getattr(summary, "connections", []) or [])

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if worst >= 4:
        lines.append(danger(
            "CRITICAL - EtherNet/IP: destructive control activity (Reset/Stop/"
            "program) observed; treat as potential active manipulation."
        ))
    elif worst >= 3:
        lines.append(danger(
            "HIGH - EtherNet/IP: state-changing CIP (tag/attribute write, control, "
            "program transfer) observed; confirm an authorized engineering source "
            "within a change window."
        ))
    elif worst >= 2:
        lines.append(warn(
            "REVIEW - EtherNet/IP: activity that deviates from a clean read-only "
            "polling baseline; triage the findings below."
        ))
    else:
        lines.append(ok(
            "BENIGN BASELINE - EtherNet/IP: read-only CIP polling with no writes, "
            "control, program transfers, or CIP errors. Consistent with routine "
            "HMI/SCADA tag acquisition."
        ))
    lines.append(muted(
        f"  Baseline: {len(masters)} master(s) -> {len(servers)} device(s); "
        f"{reads} tag reads / {writes} writes / {high_risk} high-risk services / "
        f"{errs} CIP errors / {conns} ForwardOpen over "
        f"{getattr(summary, 'duration', 0.0):.0f}s."
    ))
    if masters:
        lines.append(muted(f"  Master(s): {', '.join(masters[:6])}"))
    if len(masters) > 1:
        lines.append(warn(
            "  Note: >1 CIP master present — validate any that is not a known "
            "HMI/SCADA/EWS (new-master hunt hypothesis)."
        ))

    if worst >= 2:
        ranked = sorted(norm, key=lambda n: _PROTO_SEV_RANK.get(n[0][0], 0), reverse=True)
        lines.append(muted("Focus Here First:"))
        attack_ids: list[str] = []
        for (sev, title, detail), orig in ranked[: _limit_value(6)]:
            if _PROTO_SEV_RANK.get(sev, 0) < 2:
                continue
            mark = (
                danger(f"[{sev.upper()}]")
                if _PROTO_SEV_RANK.get(sev, 0) >= 3
                else warn(f"[{sev.upper()}]")
            )
            src = str(getattr(orig, "src", "") or "")
            dst = str(getattr(orig, "dst", "") or "")
            ev = f"{src} -> {dst}" if (src or dst) else _truncate_text(detail, 80)
            lines.append(f"  {mark} {title}" + (f" — {_truncate_text(ev, 90)}" if ev else ""))
        for (_sev, title, _detail), orig in ranked:
            tech = getattr(orig, "attack", "") or _ot_attack_for_title(title)
            if tech and tech not in attack_ids:
                attack_ids.append(tech)
        if attack_ids:
            lines.append(SUBSECTION_BAR)
            lines.append(header("ATT&CK for ICS Mapping"))
            for tid in attack_ids[: _limit_value(12)]:
                lines.append(muted(f"- {tid}"))


def _render_enip_baseline_sections(lines: list[str], summary: "ENIPAnalysis") -> None:
    """Forensic baseline: Tag Access Map (process fingerprint), CIP health
    (success/error), per-server RTT, and ForwardOpen connections."""
    # --- Tag Access Map ---
    tag_reads = getattr(summary, "tag_reads", Counter()) or Counter()
    tag_writes = getattr(summary, "tag_writes", Counter()) or Counter()
    tag_endpoints = getattr(summary, "tag_endpoints", {}) or {}
    all_tags = set(tag_reads) | set(tag_writes)
    if all_tags:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Tag Access Map (process fingerprint)"))
        rows = [["Tag", "Reads", "Writes", "Top endpoint"]]
        ranked_tags = sorted(
            all_tags, key=lambda t: -(tag_reads.get(t, 0) + tag_writes.get(t, 0))
        )
        for tag in ranked_tags[: _limit_value(20)]:
            w = tag_writes.get(tag, 0)
            eps = tag_endpoints.get(tag, Counter())
            top_ep = eps.most_common(1)[0][0] if eps else "-"
            rows.append([
                _truncate_text(tag, 40),
                str(tag_reads.get(tag, 0)),
                danger(str(w)) if w else "0",
                _truncate_text(top_ep, 34),
            ])
        lines.append(_format_table(rows))
        if len(all_tags) > 20:
            lines.append(muted(f"  ... and {len(all_tags) - 20} more tags"))

    # --- CIP Health (success vs error) ---
    success = int(getattr(summary, "cip_success", 0))
    errors = int(getattr(summary, "cip_errors", 0))
    if success or errors:
        total = success + errors
        err_rate = (errors / total) if total else 0.0
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Health"))
        lines.append(_format_kv("Successful responses", str(success)))
        lines.append(_format_kv(
            "Error responses",
            danger(f"{errors} ({err_rate:.1%})") if errors else "0 (0.0%)",
        ))
        err_counts = getattr(summary, "error_status_counts", Counter()) or Counter()
        if err_counts:
            lines.append(_format_kv(
                "Top CIP errors",
                ", ".join(f"{name} x{cnt}" for name, cnt in err_counts.most_common(4)),
            ))

    # --- Response Time by Server ---
    rtt = getattr(summary, "rtt_by_server", {}) or {}
    if rtt:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Response Time by Server (paired req->resp)"))
        rows = [["Server", "min ms", "p50 ms", "p95 ms", "max ms"]]
        for ip, st in sorted(rtt.items(), key=lambda kv: -kv[1].get("p95", 0))[: _limit_value(12)]:
            rows.append([
                ip,
                f"{st.get('min', 0):.0f}",
                f"{st.get('p50', 0):.0f}",
                f"{st.get('p95', 0):.0f}",
                f"{st.get('max', 0):.0f}",
            ])
        lines.append(_format_table(rows))

    # --- ForwardOpen Connections ---
    connections = getattr(summary, "connections", []) or []
    if connections:
        lines.append(SUBSECTION_BAR)
        lines.append(header("CIP Connections (ForwardOpen)"))
        rows = [["Originator -> Target", "O->T RPI ms", "T->O RPI ms", "Vendor", "Serial"]]
        for c in connections[: _limit_value(12)]:
            rows.append([
                f"{c.get('src','?')} -> {c.get('dst','?')}",
                str(c.get("ot_rpi_ms", "-")),
                str(c.get("to_rpi_ms", "-")),
                str(c.get("vendor_id", "-")),
                str(c.get("orig_serial", "-")),
            ])
        lines.append(_format_table(rows))


@_ot_full_render
def render_enip_summary(summary: "ENIPAnalysis") -> str:
    if not summary:
        return ""

    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"ETHERNET/IP ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)
    _render_enip_verdict(lines, summary)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    duration = summary.duration
    rate = (summary.enip_bytes / duration) if duration and duration > 0 else 0

    lines.append(_format_kv("Scan Duration", f"{duration:.2f}s"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("ENIP Packets", str(summary.enip_packets)))
    lines.append(_format_kv("Total Bytes", format_bytes_as_mb(summary.total_bytes)))
    lines.append(_format_kv("ENIP Bytes", format_bytes_as_mb(summary.enip_bytes)))
    lines.append(_format_kv("ENIP Throughput", format_speed_bps(int(rate * 8))))
    lines.append(_format_kv("Requests", str(summary.requests)))
    lines.append(_format_kv("Responses", str(summary.responses)))
    lines.append(
        _format_kv(
            "Connected/Unconnected",
            f"{summary.connected_packets}/{summary.unconnected_packets}",
        )
    )
    lines.append(_format_kv("I/O Packets (UDP/2222)", str(summary.io_packets)))
    lines.append(_format_kv("Unique Clients", str(len(summary.client_ips))))
    lines.append(_format_kv("Unique Servers", str(len(summary.server_ips))))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Endpoint Statistics"))
    if not summary.client_ips and not summary.server_ips:
        lines.append(muted("No ENIP endpoints detected."))
    else:
        col_width = 45
        lines.append(highlight(f"{'Clients':<{col_width}} | {'Servers'}"))
        lines.append(muted("-" * 90))
        clients = summary.client_ips.most_common(_limit_value(10))
        servers = summary.server_ips.most_common(_limit_value(10))
        max_rows = max(len(clients), len(servers))
        for i in range(max_rows):
            c_str = ""
            s_str = ""
            if i < len(clients):
                ip, cnt = clients[i]
                c_str = f"{ip} ({cnt})"
            if i < len(servers):
                ip, cnt = servers[i]
                s_str = f"{ip} ({cnt})"
            lines.append(f"{c_str:<{col_width}} | {s_str}")

    if summary.sessions:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Sessions"))
        rows = [["Session", "Packets"]]
        for sess, count in summary.sessions.most_common(_limit_value(12)):
            rows.append([str(sess), str(count)])
        lines.append(_format_table(rows))

    if summary.enip_commands:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP Encapsulation Commands"))
        rows = [["Command", "Count", "Risk"]]
        suspicious = {
            "ListServices",
            "ListIdentity",
            "ListInterfaces",
            "RegisterSession",
            "WriteObjectInstanceAttributes",
        }
        for cmd, count in summary.enip_commands.most_common(_limit_value(12)):
            risk = "Normal"
            display = cmd
            if cmd in suspicious:
                risk = "Suspicious"
                display = warn(cmd)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

    if summary.cip_services:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Observed CIP Services (OT Commands)"))
        rows = [["Service", "Count", "Risk"]]
        dangerous = {
            "Reset",
            "Start",
            "Stop",
            "ProgramDownload",
            "ProgramCommand",
            "WriteTag",
            "WriteTagFragmented",
            "ReadModifyWriteTag",
            "WriteData",
        }
        suspicious = {
            "Set_Attribute_List",
            "Set_Attribute_Single",
            "Set_Attributes_All",
            "Forward_Open",
            "Forward_Close",
            "Create",
            "Delete",
            "ProgramUpload",
        }
        for service, count in summary.cip_services.most_common(_limit_value(16)):
            if service == "Service 0x00":
                continue  # CIP parse-artifact, not an OT command
            risk = "Normal"
            display = service
            if service in dangerous:
                risk = "Dangerous"
                display = danger(service)
            elif service in suspicious:
                risk = "Suspicious"
                display = warn(service)
            rows.append([display, str(count), risk])
        lines.append(_format_table(rows))

        high_risk_total = sum(
            getattr(summary, "high_risk_services", Counter()).values()
        )
        suspicious_total = sum(
            getattr(summary, "suspicious_services", Counter()).values()
        )
        enumeration_total = sum(
            getattr(summary, "enumeration_services", Counter()).values()
        )
        total_services = sum(summary.cip_services.values())
        normal_total = max(
            0, total_services - high_risk_total - suspicious_total - enumeration_total
        )
        lines.append(SUBSECTION_BAR)
        lines.append(header("Command Risking Overview"))
        lines.append(_format_kv("Total Service Invocations", str(total_services)))
        lines.append(_format_kv(
            "High-Risk (write/control/program)",
            danger(str(high_risk_total)) if high_risk_total else "0",
        ))
        lines.append(_format_kv(
            "Suspicious (config/connection/lifecycle)",
            warn(str(suspicious_total)) if suspicious_total else "0",
        ))
        lines.append(_format_kv(
            "Enumeration/Discovery reads", str(enumeration_total)
        ))
        lines.append(_format_kv("Normal (tag reads/other)", str(normal_total)))

    _render_enip_baseline_sections(lines, summary)

    if summary.service_endpoints:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Service Endpoints (client -> server)"))
        rows = [["Service", "Top Endpoints"]]
        for service, count in summary.cip_services.most_common(_limit_value(12)):
            if service == "Service 0x00":
                continue  # CIP parse-artifact for fragment/continuation packets
            endpoints = summary.service_endpoints.get(service, Counter())
            if not endpoints:
                continue
            top_eps = ", ".join(
                f"{ep} ({cnt})" for ep, cnt in endpoints.most_common(_limit_value(3))
            )
            rows.append([service, top_eps or "-"])
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if summary.status_codes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("ENIP/CIP Status Codes"))
        lines.append(_counter_table(summary.status_codes, "Status", limit=_limit_value(12)))

    if getattr(summary, "identities", None):
        lines.append(SUBSECTION_BAR)
        lines.append(header("Device Inventory (ListIdentity)"))
        rows = [
            [
                "IP",
                "Vendor ID",
                "Device Type",
                "Product Code",
                "Revision",
                "Serial",
                "Product Name",
            ]
        ]

        def _format_identity_label(
            name: object | None, code: object | None, label: str
        ) -> str:
            if name:
                return f"{name} ({code})"
            if code is None or code == "-":
                return "-"
            try:
                code_val = int(code)
            except Exception:
                return str(code)
            if code_val == 0:
                return f"Unknown {label} (0)"
            return f"{label} {code_val}"

        for ident in summary.identities[: _limit_value(20)]:
            vendor_id = getattr(ident, "vendor_id", "-")
            vendor_name = getattr(ident, "vendor_name", None)
            vendor_display = _format_identity_label(vendor_name, vendor_id, "Vendor")

            device_type = getattr(ident, "device_type", "-")
            device_type_name = getattr(ident, "device_type_name", None)
            device_display = _format_identity_label(
                device_type_name, device_type, "DeviceType"
            )

            product_code = getattr(ident, "product_code", "-")
            product_name = getattr(ident, "product_code_name", None)
            product_display = _format_identity_label(
                product_name, product_code, "Product"
            )

            rows.append(
                [
                    str(getattr(ident, "src_ip", "?")),
                    vendor_display,
                    device_display,
                    product_display,
                    str(getattr(ident, "revision", "-")),
                    str(getattr(ident, "serial_number", "-")),
                    _truncate_text(str(getattr(ident, "product_name", "-")), 32),
                ]
            )
        lines.append(_format_table(rows))

    if summary.artifacts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Artifacts & Observations"))
        rows = [[label("Type"), label("Detail"), label("Src"), label("Dst")]]
        for artifact in summary.artifacts[: _limit_value(12)]:
            kind = str(getattr(artifact, "kind", "artifact"))
            detail = str(getattr(artifact, "detail", ""))
            detail = " ".join(detail.split())
            if kind == "tag":
                tokens = re.findall(r"[A-Za-z0-9_]{3,}", detail)
                if tokens:
                    unique = []
                    seen = set()
                    for tok in tokens:
                        if tok in seen:
                            continue
                        unique.append(tok)
                        seen.add(tok)
                    preview = ", ".join(unique[: _limit_value(4)])
                    extra = len(unique) - 4
                    if extra > 0:
                        preview = f"{preview} (+{extra})"
                    detail = preview
                else:
                    detail = _truncate_text(detail, 32)
            detail_lines = [detail]
            if kind == "tag":
                kind_display = highlight(kind)
            elif kind == "identity":
                kind_display = warn(kind)
            else:
                kind_display = label(kind)
            src = str(getattr(artifact, "src", "?"))
            dst = str(getattr(artifact, "dst", "?"))
            rows.append([kind_display, detail_lines[0], src, dst])
            for extra in detail_lines[1:]:
                rows.append([muted("·"), muted(extra), "", ""])
        lines.append(_format_table(rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Anomalies & Threats"))
    if summary.anomalies:
        sev_map = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_anoms = sorted(
            summary.anomalies, key=lambda x: sev_map.get(x.severity, 99)
        )
        for anomaly in sorted_anoms[: _limit_value(20)]:
            sev = getattr(anomaly, "severity", "INFO")
            sev_color = danger if sev in ("CRITICAL", "HIGH") else warn
            if sev == "LOW":
                sev_color = muted
            lines.append(
                sev_color(
                    f"[{sev}] {getattr(anomaly, 'title', 'Event')}: {getattr(anomaly, 'description', '')}"
                )
            )
            lines.append(
                muted(
                    f"  Src: {getattr(anomaly, 'src', '?')} -> Dst: {getattr(anomaly, 'dst', '?')}"
                )
            )
    else:
        lines.append(muted("No ENIP anomalies detected."))

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
