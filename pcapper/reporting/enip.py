"""Rendered output for EtherNet/IP (ENIP/CIP) analysis.

Default view: findings, the CIP services by risk, the tags written, the
device inventory (ListIdentity), CIP errors and the endpoints. -v adds the
full tag access map, connections, response times, status codes,
encapsulation commands, sessions, per-source command counts, CIP object IDs
and low-level protocol artifacts.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

from ..utils import format_bytes_as_mb, format_speed_bps
from . import _style as st
from ._common import _ot_attack_for_title

if TYPE_CHECKING:
    from ..enip import ENIPAnalysis

_DANGEROUS = {
    "Reset", "Start", "Stop", "ProgramDownload", "ProgramCommand", "WriteTag",
    "WriteTagFragmented", "ReadModifyWriteTag", "WriteData",
}
_SUSPICIOUS = {
    "Set_Attribute_List", "Set_Attribute_Single", "Set_Attributes_All", "Forward_Open",
    "Forward_Close", "Create", "Delete", "ProgramUpload",
}
_SUSPICIOUS_ENCAP = {
    "ListServices", "ListIdentity", "ListInterfaces", "RegisterSession",
    "WriteObjectInstanceAttributes",
}
# Artifact kinds that are protocol plumbing rather than evidence (-v only).
_LOW_LEVEL_KINDS = {"enip_session", "enip_cpf", "cip_object", "cip_multi_service", "tag"}


def _service_class(name: str) -> str:
    return "dangerous" if name in _DANGEROUS else "suspicious" if name in _SUSPICIOUS else "normal"


def _styled(klass: str, text: str) -> str:
    return st.bad(text) if klass == "dangerous" else st.caution(text) if klass == "suspicious" else text


def _identity_label(name: object, code: object, label_text: str) -> str:
    if name:
        return f"{name} ({code})"
    if code is None or code == "-":
        return "-"
    try:
        value = int(code)  # type: ignore[arg-type]
    except Exception:
        return str(code)
    return f"Unknown {label_text} (0)" if value == 0 else f"{label_text} {value}"


def _artifact_detail(kind: str, detail: str) -> str:
    detail = " ".join(detail.split())
    if kind != "tag":
        return detail
    tokens = list(dict.fromkeys(re.findall(r"[A-Za-z0-9_]{3,}", detail)))
    if not tokens:
        return st.cut(detail, 32)
    shown = tokens if st.verbose() else tokens[:4]
    return ", ".join(shown) + (f" (+{len(tokens) - len(shown)})" if len(tokens) > len(shown) else "")


def render_enip_summary(summary: "ENIPAnalysis") -> str:
    if not summary:
        return ""
    return cip_family_report(summary, name="EtherNet/IP", unit="ENIP",
                             packets=summary.enip_packets, size_bytes=summary.enip_bytes)


def cip_family_report(summary: object, *, name: str, unit: str, packets: int, size_bytes: int) -> str:
    """The EtherNet/IP and CIP reports (one analyzer family, the same fields;
    CIP adds legacy PCCC commands)."""
    rep = st.Report(name, summary.path)  # type: ignore[attr-defined]
    findings = [st.finding(a, _ot_attack_for_title) for a in (summary.anomalies or [])]  # type: ignore[attr-defined]
    if not packets and not st.material(findings):
        return rep.absent(f"{name} traffic", summary.errors)  # type: ignore[attr-defined]

    masters = list(getattr(summary, "masters", []) or [])
    servers = list(getattr(summary, "server_ips", {}) or {})
    tag_reads: Counter = getattr(summary, "tag_reads", None) or Counter()
    tag_writes: Counter = getattr(summary, "tag_writes", None) or Counter()
    tag_endpoints: dict = getattr(summary, "tag_endpoints", {}) or {}
    reads = sum(tag_reads.values())
    writes = int(getattr(summary, "write_service_count", 0))
    high_risk = sum((getattr(summary, "high_risk_services", None) or Counter()).values())
    cip_ok = int(getattr(summary, "cip_success", 0))
    cip_err = int(getattr(summary, "cip_errors", 0))
    connections = list(getattr(summary, "connections", []) or [])

    severity, text = st.verdict(
        findings,
        high=("destructive control (Reset/Stop/program): treat as active manipulation"
              if st.worst(findings) >= 4 else
              "state-changing CIP (writes, control, program transfer): confirm it is authorized"),
        medium="activity outside a read-only polling baseline",
        clean="read-only CIP polling baseline: no writes, control, program transfers or CIP errors",
    )
    pccc: Counter = getattr(summary, "pccc_commands", None) or Counter()
    rep.headline(severity, text, st.join([
        f"{st.count(packets)} {unit} packets", st.size(size_bytes), st.duration(summary.duration),
    ]))
    rep.scope(st.join([
        f"{st.plural(len(masters), 'master')} -> {st.plural(len(servers), 'device')}",
        f"{st.count(reads)} tag reads / {st.count(writes)} writes / {st.count(high_risk)} high-risk services",
        f"{st.plural(cip_err, 'CIP error')}",
        f"{st.count(len(connections))} ForwardOpen" if hasattr(summary, "connections") else "",
        f"{st.count(sum(pccc.values()))} PCCC" if hasattr(summary, "pccc_commands") else "",
    ]))
    if len(masters) > 1:
        rep.note("NOTE", f"{st.plural(len(masters), 'CIP master')} present: validate any that is not a known HMI/SCADA/EWS")

    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {err}" for err in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rank = {"dangerous": 0, "suspicious": 1, "normal": 2}
    services = [(name, cnt) for name, cnt in summary.cip_services.items() if name != "Service 0x00"]
    rows = [[_styled(_service_class(n), n), st.count(c), _service_class(n)]
            for n, c in sorted(services, key=lambda kv: (rank[_service_class(kv[0])], -kv[1], kv[0]))]
    rep.section("CIP services", st.ranked(["Service", "Count", "Class"], rows, align="lrl", noun="service"))

    if pccc:
        pccc_eps: dict = getattr(summary, "pccc_endpoints", {}) or {}

        def _pccc_write(cmd: str) -> bool:
            return any(k in cmd.lower() for k in ("write", "download", "mode", "edit resource", "apply"))

        rep.section("PCCC commands", st.ranked(
            ["Command (legacy Allen-Bradley)", "Count", "Class", "Top endpoint"],
            [[st.bad(c) if _pccc_write(c) else c, st.count(n), "write" if _pccc_write(c) else "read",
              ((pccc_eps.get(c) or Counter()).most_common(1) or [("-", 0)])[0][0]]
             for c, n in sorted(pccc.items(), key=lambda kv: (not _pccc_write(kv[0]), -kv[1], kv[0]))],
            align="lrll", widths=(48, None, None, 40),
        ))

    written = sorted(tag_writes, key=lambda t: (-tag_writes[t], str(t)))
    rep.section("Tags written", st.ranked(
        ["Tag", "Writes", "Reads", "Endpoint"],
        [[t, st.bad(st.count(tag_writes[t])), st.count(tag_reads.get(t, 0)),
          ((tag_endpoints.get(t) or Counter()).most_common(1) or [("-", 0)])[0][0]] for t in written],
        align="lrrl", widths=(48, None, None, 40),
    ))

    identities = list(getattr(summary, "identities", None) or [])
    rep.section("Devices", st.table(
        ["Address", "Vendor", "Device type", "Product", "Revision", "Serial", "Name"],
        [[getattr(i, "src_ip", "?"),
          _identity_label(getattr(i, "vendor_name", None), getattr(i, "vendor_id", "-"), "Vendor"),
          _identity_label(getattr(i, "device_type_name", None), getattr(i, "device_type", "-"), "DeviceType"),
          _identity_label(getattr(i, "product_code_name", None), getattr(i, "product_code", "-"), "Product"),
          getattr(i, "revision", "-"), getattr(i, "serial_number", "-"), getattr(i, "product_name", "-")]
         for i in identities],
        widths=(None, 28, 28, 28, None, None, 32),
    ))

    if cip_err:
        total = cip_ok + cip_err
        err_counts: Counter = getattr(summary, "error_status_counts", None) or Counter()
        rep.section("CIP errors", st.kv([
            ("Responses", f"{st.count(cip_ok)} ok · {st.bad(st.count(cip_err))} errors ({cip_err / total:.1%})"),
            ("Top errors", st.top(err_counts, 6, lambda k, v: f"{k} ×{st.count(v)}")),
        ]))

    relevant = [a for a in summary.artifacts if str(getattr(a, "kind", "")) not in _LOW_LEVEL_KINDS]
    rep.section("Artifacts", st.table(
        ["Kind", "Detail", "Flow"],
        [[a.kind, _artifact_detail(str(a.kind), str(a.detail)), st.flow(a.src, a.dst)] for a in relevant],
        widths=(None, 80),
    ))

    per_role = None if st.verbose() else 6
    endpoint_rows = [["client", ip, st.count(n)] for ip, n in summary.client_ips.most_common(per_role)]
    endpoint_rows += [["server", ip, st.count(n)] for ip, n in summary.server_ips.most_common(per_role)]
    hidden = 0 if per_role is None else (max(0, len(summary.client_ips) - per_role) + max(0, len(summary.server_ips) - per_role))
    rep.section("Endpoints", st.table(["Role", "Address", "Packets"], endpoint_rows, align="llr", max_rows=None)
                + ([st.more(hidden, "endpoint")] if hidden else []))

    # ---- reference material (-v) ----------------------------------------
    duration = summary.duration
    rate = (size_bytes / duration) if duration and duration > 0 else 0
    rep.section("Traffic", st.kv([
        ("Duration", f"{duration:.2f}s"),
        ("Packets", f"{summary.total_packets} total · {packets} {unit}"),
        ("Bytes", f"{format_bytes_as_mb(summary.total_bytes)} total · {format_bytes_as_mb(size_bytes)} {unit}"),
        ("Throughput", format_speed_bps(int(rate * 8))),
        ("Requests / responses", f"{summary.requests} / {summary.responses}"),
        ("Connected / unconnected", f"{summary.connected_packets}/{summary.unconnected_packets}"),
        ("I/O packets (UDP/2222)", str(summary.io_packets)),
        ("Clients / servers", f"{len(summary.client_ips)} / {len(summary.server_ips)}"),
    ]), detail=True)

    suspicious_total = sum((getattr(summary, "suspicious_services", None) or Counter()).values())
    enumeration_total = sum((getattr(summary, "enumeration_services", None) or Counter()).values())
    total_services = sum(summary.cip_services.values())
    rep.section("Service risk", st.kv([
        ("Service invocations", str(total_services)),
        ("High-risk (write/control/program)", st.bad(str(high_risk)) if high_risk else "0"),
        ("Suspicious (config/connection/lifecycle)", st.caution(str(suspicious_total)) if suspicious_total else "0"),
        ("Enumeration/discovery reads", str(enumeration_total)),
        ("Normal (tag reads/other)", str(max(0, total_services - high_risk - suspicious_total - enumeration_total))),
    ]), detail=True)

    all_tags = sorted(set(tag_reads) | set(tag_writes), key=lambda t: (-(tag_reads.get(t, 0) + tag_writes.get(t, 0)), str(t)))
    rep.section("Tag access map", st.table(
        ["Tag", "Reads", "Writes", "Top endpoint"],
        [[t, st.count(tag_reads.get(t, 0)), st.bad(str(tag_writes[t])) if tag_writes.get(t) else "0",
          ((tag_endpoints.get(t) or Counter()).most_common(1) or [("-", 0)])[0][0]] for t in all_tags],
        align="lrrl", max_rows=None,
    ), detail=True)

    rep.section("Connections (ForwardOpen)", st.table(
        ["Originator -> target", "O->T RPI ms", "T->O RPI ms", "Vendor", "Serial"],
        [[st.flow(c.get("src", "?"), c.get("dst", "?")), c.get("ot_rpi_ms", "-"), c.get("to_rpi_ms", "-"),
          c.get("vendor_id", "-"), c.get("orig_serial", "-")] for c in connections],
        align="lrrll", max_rows=None,
    ), detail=True)

    rtt = getattr(summary, "rtt_by_server", {}) or {}
    rep.section("Response times", st.table(
        ["Server", "Min ms", "p50 ms", "p95 ms", "Max ms"],
        [[ip, st.stat(v, "min"), st.stat(v, "p50"), st.stat(v, "p95"), st.stat(v, "max")]
         for ip, v in sorted(rtt.items(), key=lambda kv: (-kv[1].get("p95", 0), kv[0]))],
        align="lrrrr", max_rows=None,
    ), detail=True)

    if cip_ok or cip_err:
        total = cip_ok + cip_err
        rep.section("CIP health", st.kv([
            ("Successful responses", st.count(cip_ok)),
            ("Error responses", f"{st.count(cip_err)} ({(cip_err / total if total else 0.0):.1%})"),
            ("Top errors", st.top(getattr(summary, "error_status_counts", None) or Counter(), None,
                                  lambda k, v: f"{k} ×{st.count(v)}")),
        ]), detail=True)

    pairing = getattr(summary, "pairing", {}) or {}
    rep.section("Transaction pairing", st.kv([(k.replace("_", " ").capitalize(), str(v)) for k, v in pairing.items()]),
                detail=True)

    rep.section("Encapsulation commands", st.table(
        ["Command", "Count", "Class"],
        [[st.caution(c) if c in _SUSPICIOUS_ENCAP else c, st.count(n), "suspicious" if c in _SUSPICIOUS_ENCAP else "normal"]
         for c, n in summary.enip_commands.most_common()],
        align="lrl", max_rows=None,
    ), detail=True)

    rep.section("Service endpoints", st.table(
        ["Service", "Endpoints"],
        [[name, st.top(summary.service_endpoints.get(name) or Counter(), 3)]
         for name, _ in summary.cip_services.most_common()
         if name != "Service 0x00" and summary.service_endpoints.get(name)],
        max_rows=None,
    ), detail=True)

    by_source = []
    for label_text, field_name in (("Risky commands", "source_risky_commands"), ("Enumeration (CIP)", "source_enum_commands"),
                                   ("Enumeration (ENIP)", "source_enip_enum_commands"), ("Recon", "source_recon_commands"),
                                   ("Requests", "request_sources")):
        counter = getattr(summary, field_name, None) or Counter()
        if counter:
            by_source.append((label_text, st.top(counter, None)))
    rep.section("By source", st.kv(by_source), detail=True)

    errors_by = []
    for label_text, field_name in (("Server error responses", "server_error_responses"),
                                   ("Errors by service", "service_error_counts")):
        counter = getattr(summary, field_name, None) or Counter()
        if counter:
            errors_by.append((label_text, st.top(counter, None)))
    rep.section("Error breakdown", st.kv(errors_by), detail=True)

    rep.section("Status codes", st.table(
        ["Status", "Count"], [[k, st.count(v)] for k, v in summary.status_codes.most_common()], align="lr", max_rows=None,
    ), detail=True)

    objects = [(label_text, st.top(getattr(summary, field_name, None) or Counter(), None))
               for label_text, field_name in (("Class IDs", "class_ids"), ("Instance IDs", "instance_ids"),
                                              ("Attribute IDs", "attribute_ids"))
               if getattr(summary, field_name, None)]
    rep.section("CIP objects", st.kv(objects), detail=True)

    rep.section("Sessions", st.table(
        ["Session", "Packets"], [[s, st.count(n)] for s, n in summary.sessions.most_common()], align="lr", max_rows=None,
    ), detail=True)

    low_level = [a for a in summary.artifacts if str(getattr(a, "kind", "")) in _LOW_LEVEL_KINDS]
    rep.section("Protocol artifacts", st.table(
        ["Kind", "Detail", "Flow"],
        [[a.kind, _artifact_detail(str(a.kind), str(a.detail)), st.flow(a.src, a.dst)] for a in low_level],
        max_rows=None,
    ), detail=True)
    return rep.render()
