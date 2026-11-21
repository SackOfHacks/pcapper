"""The shared report for OT/ICS protocols without a dedicated renderer.

About thirty protocols (BACnet, S7, PROFINET, IEC-104, OPC UA, KNX, ...) are
analysed by the generic industrial loop and rendered here, in the house style
of :mod:`._style`: findings and state-changing commands first, then the
devices and endpoints involved; traffic statistics, sessions and size
distributions are -v reference material.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Callable, Optional

from . import _style as st
from ._common import _ot_attack_for_title, _ot_command_risk

# Artifact kinds that describe a device rather than an action.
_DEVICE_KINDS = {"equipment", "device", "software", "firmware", "system", "identity"}
_DEVICE_HINTS = (
    "vendor=", "model=", "product=", "software=", "firmware=", "simatic", "siemens",
    "plc", "hmi", "scada", "dcs", "rtu",
)


def _bucket_summary(buckets: list) -> Optional[str]:
    total = sum(b.count for b in buckets)
    if not total:
        return None
    avg = sum(b.avg * b.count for b in buckets) / total
    lo = min(b.min for b in buckets if b.count)
    hi = max(b.max for b in buckets if b.count)
    return f"{st.count(total)} · min/avg/max {lo}/{avg:.1f}/{hi} · {st.sparkline_of([b.count for b in buckets])}"


def _classifier(
    dangerous: Optional[set[str]], suspicious: Optional[set[str]]
) -> Callable[[str], str]:
    """The command classes each path has always used: the protocol's own
    danger/suspicion tokens, else the shared OT keyword classifier."""
    if dangerous is None and suspicious is None:
        return lambda cmd: {"CONTROL": "control", "REVIEW": "review"}.get(_ot_command_risk(cmd), "normal")
    dangerous = dangerous or set()
    suspicious = suspicious or set()

    def classify(cmd: str) -> str:
        low = cmd.lower()
        if any(t in low for t in dangerous):
            return "dangerous"
        if any(t in low for t in suspicious):
            return "suspicious"
        return "normal"

    return classify


def _class_style(klass: str) -> Callable[[str], str]:
    if klass in ("control", "dangerous"):
        return st.bad
    if klass in ("review", "suspicious"):
        return st.caution
    return lambda text: text


def ot_report(
    title: str,
    summary: object,
    *,
    packet_label: str = "Protocol Packets",
    dangerous_tokens: Optional[set[str]] = None,
    suspicious_tokens: Optional[set[str]] = None,
    include_detected_devices: bool = False,
) -> str:
    if not summary:
        return ""
    path = getattr(summary, "path", "")
    rep = st.Report(title, path)
    anomalies = list(getattr(summary, "anomalies", []) or [])
    findings = [st.finding(a, _ot_attack_for_title) for a in anomalies]
    errors = list(getattr(summary, "errors", []) or [])
    protocol_packets = int(getattr(summary, "protocol_packets", 0) or 0)
    if not protocol_packets and not st.material(findings):
        return rep.absent(f"{title} traffic", errors)

    total_packets = int(getattr(summary, "total_packets", 0) or 0)
    protocol_bytes = int(getattr(summary, "protocol_bytes", 0) or 0)
    total_bytes = int(getattr(summary, "total_bytes", 0) or 0)
    duration = float(getattr(summary, "duration", 0.0) or 0.0)
    commands: Counter = getattr(summary, "commands", None) or Counter()
    sessions: Counter = getattr(summary, "sessions", None) or Counter()
    service_endpoints: dict = getattr(summary, "service_endpoints", None) or {}
    artifacts = list(getattr(summary, "artifacts", []) or [])
    client_ips: Counter = getattr(summary, "client_ips", None) or Counter()
    server_ips: Counter = getattr(summary, "server_ips", None) or Counter()
    directional = bool(client_ips or server_ips)
    clients = client_ips if directional else (getattr(summary, "src_ips", None) or Counter())
    servers = server_ips if directional else (getattr(summary, "dst_ips", None) or Counter())

    classify = _classifier(dangerous_tokens, suspicious_tokens)
    classes = {str(cmd): classify(str(cmd)) for cmd in commands}
    n_state = sum(1 for k in classes.values() if k in ("control", "dangerous"))

    severity, text = st.verdict(
        findings,
        high="high-severity activity: confirm an authorized source and change window",
        medium="notable activity to review",
        clean=st.join(["no findings", f"{st.plural(n_state, 'state-changing command type')} seen" if n_state else ""]),
    )
    rep.headline(
        severity,
        text,
        st.join([
            f"{st.count(protocol_packets)} {title} packets",
            st.size(protocol_bytes) if protocol_bytes else "",
            st.duration(duration),
        ]),
    )
    rep.scope(
        f"{st.plural(len(clients), 'client')} -> {st.plural(len(servers), 'server')}"
        if directional else
        f"{st.plural(len(clients), 'source')} -> {st.plural(len(servers), 'destination')}"
    )

    if errors:
        rep.section("Errors", [f"  {st.bad('!')} {err}" for err in errors])
    rep.section("Findings", st.findings_block(findings))

    if commands:
        # State-changing commands first, then review-worthy ones, then the
        # rest (where transport framing such as TPKT/COTP would otherwise lead).
        rank = {"control": 0, "dangerous": 0, "review": 1, "suspicious": 1}
        rows = []
        for cmd, cnt in sorted(commands.items(), key=lambda kv: (rank.get(classes[str(kv[0])], 2), -kv[1], str(kv[0]))):
            klass = classes[str(cmd)]
            rows.append([_class_style(klass)(str(cmd)), st.count(cnt), klass])
        rep.section("Commands", st.table(["Command", "Count", "Class"], rows, align="lrl", widths=(60,)))

    # Devices: device-like artifacts. Generic payload keyword hits and (for
    # S7) COTP TSAP connection profiles are -v reference material.
    device_counts: Counter[str] = Counter()
    device_eps: dict[str, Counter[str]] = defaultdict(Counter)
    other: Counter[tuple[str, str, str, str]] = Counter()
    keywords: Counter[tuple[str, str, str]] = Counter()
    profiles: Counter[str] = Counter()
    profile_eps: dict[str, Counter[str]] = defaultdict(Counter)
    for art in artifacts:
        kind = str(getattr(art, "kind", "") or "artifact").strip()
        detail = str(getattr(art, "detail", "") or "").strip()
        src, dst = str(getattr(art, "src", "?")), str(getattr(art, "dst", "?"))
        is_device = kind.lower() in _DEVICE_KINDS or (
            include_detected_devices and any(h in detail.lower() for h in _DEVICE_HINTS)
        )
        if detail.startswith("COTP Session Profile"):
            # S7 files these as "device"; they describe a connection.
            profiles[detail] += 1
            profile_eps[detail][st.flow(src, dst)] += 1
        elif is_device and detail:
            device_counts[detail] += 1
            device_eps[detail][st.flow(src, dst)] += 1
        elif kind == "keyword":
            keywords[(detail, src, dst)] += 1
        else:
            other[(kind, detail, src, dst)] += 1
    if include_detected_devices:
        for cmd, cnt in commands.items():
            text = str(cmd)
            if "SrcTSAP=" in text and "DstTSAP=" in text:
                profile = text.replace("COTP:CR:", "COTP CR ").replace("COTP:CC:", "COTP CC ")
                profiles[profile] += int(cnt)
                for ep, n in (service_endpoints.get(text) or Counter()).items():
                    profile_eps[profile][ep] += int(n)
    rep.section("Devices", st.ranked(
        ["Device", "Seen", "Endpoints"],
        [[d, st.count(n), st.top(device_eps[d], 2)] for d, n in device_counts.most_common()],
        align="lrl", widths=(72,), noun="device",
    ))
    rep.section("Artifacts", st.ranked(
        ["Kind", "Detail", "Flow"],
        [[kind, detail + (st.dim(f" ×{n}") if n > 1 else ""), st.flow(src, dst)]
         for (kind, detail, src, dst), n in other.most_common()],
        widths=(None, 80), noun="artifact",
    ))

    # Up to six of each role by default, so servers are not pushed out by a
    # long client list.
    per_role = None if st.verbose() else 6
    endpoint_rows = [["client" if directional else "source", ip, st.count(n)] for ip, n in clients.most_common(per_role)]
    endpoint_rows += [["server" if directional else "destination", ip, st.count(n)] for ip, n in servers.most_common(per_role)]
    hidden = 0 if per_role is None else max(0, len(clients) - per_role) + max(0, len(servers) - per_role)
    rep.section("Endpoints", st.table(["Role", "Address", "Packets"], endpoint_rows, align="llr", max_rows=None)
                + ([st.more(hidden, "endpoint")] if hidden else []))
    rep.section("Connection profiles", st.table(
        ["COTP connection profile", "Seen", "Endpoints"],
        [[p, st.count(n), st.top(profile_eps[p], 2)] for p, n in profiles.most_common()],
        align="lrl", max_rows=None,
    ), detail=True)
    rep.section("Keyword hits", st.table(
        ["Payload text", "Flow"],
        [[detail + (st.dim(f" ×{n}") if n > 1 else ""), st.flow(src, dst)] for (detail, src, dst), n in keywords.most_common()],
        max_rows=None,
    ), detail=True)

    # ---- reference material (-v) ----------------------------------------
    traffic = [
        ("Duration", f"{duration:.2f}s"),
        ("Packets", f"{total_packets} total · {protocol_packets} {packet_label.lower()}"),
        ("Bytes", f"{total_bytes} total · {protocol_bytes} {title}" if (total_bytes or protocol_bytes) else ""),
        ("Avg packet", f"{protocol_bytes / protocol_packets:.1f} bytes" if protocol_packets and protocol_bytes else ""),
    ]
    rep.section("Traffic", st.kv(traffic), detail=True)
    rep.section("Sessions", st.table(
        ["Session", "Packets"], [[s, st.count(n)] for s, n in sessions.most_common()],
        align="lr", max_rows=None if st.verbose() else 25,
    ), detail=True)
    if service_endpoints:
        rep.section("Command endpoints", st.table(
            ["Command", "Endpoints"],
            [[str(cmd), st.top(service_endpoints.get(str(cmd)) or Counter(), 3)] for cmd, _ in commands.most_common()],
            max_rows=None,
        ), detail=True)
    sizes = []
    for label_text, buckets in (("Packet sizes", getattr(summary, "packet_size_buckets", None) or []),
                                ("Payload sizes", getattr(summary, "payload_size_buckets", None) or [])):
        text = _bucket_summary(buckets) if buckets else None
        if text:
            sizes.append((label_text, text))
    rep.section("Sizes", st.kv(sizes), detail=True)
    return rep.render()
