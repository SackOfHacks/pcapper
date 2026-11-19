from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .industrial_helpers import IndustrialCommandEvent, _strip_padding
from .pcap_cache import PcapMeta, iter_packets
from .tristation import (
    CONFIG_CHANGE,
    MODE_CHANGE,
    POINT_WRITE,
    PROGRAM_CHANGE,
    PROGRAM_UPLOAD,
    SAFETY_DISABLE,
    STATUS_READ,
    function_name,
    parse_frame,
)
from .utils import extract_packet_endpoints, is_public_ip, memoize_analysis, safe_float

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore


SAFETY_PORTS: dict[int, str] = {
    1500: "Triconex TSAA",        # Triconex System Access Application
    1501: "Triconex TSAA",
    1502: "Triconex/TriStation",  # the engineering protocol Triton/TRISIS abused
}
_MAX_SAFETY_HITS = 200
_MAX_TIMELINE = 5000


@dataclass(frozen=True)
class SafetyHit:
    ts: Optional[float]
    protocol: str
    src: str
    dst: str
    src_port: int
    dst_port: int
    service: str


@dataclass(frozen=True)
class SafetySummary:
    path: Path
    total_packets: int
    hits: list[SafetyHit]
    source_counts: Counter[str]
    destination_counts: Counter[str]
    service_counts: Counter[str]
    detections: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # Decoded TriStation (Triconex engineering protocol)
    tristation_frames: int = 0
    tristation_requests: Counter[str] = field(default_factory=Counter)
    tristation_replies: Counter[str] = field(default_factory=Counter)
    tristation_rejects: Counter[str] = field(default_factory=Counter)
    tristation_tcm: Counter[str] = field(default_factory=Counter)
    key_states: Counter[str] = field(default_factory=Counter)
    run_states: Counter[str] = field(default_factory=Counter)
    projects: Counter[str] = field(default_factory=Counter)
    tristation_timeline: list[tuple[float | None, str, str, str]] = field(default_factory=list)
    # IndustrialAnalysis-compatible views for --ot-commands / --overview.
    commands: Counter[str] = field(default_factory=Counter)
    command_events: list[object] = field(default_factory=list)

    @property
    def protocol_packets(self) -> int:
        return self.tristation_frames or len(self.hits)


def merge_safety_summaries(summaries: list[SafetySummary]) -> SafetySummary:
    if not summaries:
        return SafetySummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            service_counts=Counter(),
            detections=[],
            errors=[],
        )
    total_packets = sum(item.total_packets for item in summaries)
    hits: list[SafetyHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    counters = {
        name: Counter()
        for name in (
            "tristation_requests", "tristation_replies", "tristation_rejects",
            "tristation_tcm", "key_states", "run_states", "projects", "commands",
        )
    }
    timeline: list = []
    events: list = []
    frames = 0
    for summary in summaries:
        hits.extend(summary.hits)
        source_counts.update(summary.source_counts)
        destination_counts.update(summary.destination_counts)
        service_counts.update(summary.service_counts)
        detections.extend(summary.detections)
        errors.extend(summary.errors)
        frames += summary.tristation_frames
        for name, counter in counters.items():
            counter.update(getattr(summary, name))
        timeline.extend(summary.tristation_timeline)
        events.extend(summary.command_events)
    return SafetySummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        hits=hits[:200],
        source_counts=source_counts,
        destination_counts=destination_counts,
        service_counts=service_counts,
        detections=detections,
        errors=sorted({err for err in errors if err}),
        tristation_frames=frames,
        tristation_timeline=timeline[:_MAX_TIMELINE],
        command_events=events[:_MAX_TIMELINE],
        **counters,
    )


def _safety_service(
    sport: int, dport: int, extra: frozenset[int] = frozenset()
) -> Optional[str]:
    """Service name when a safety-system port is on the server side: the
    destination, or the source paired with an ephemeral destination.
    ``extra`` are --decode-as ports for TriStation."""
    service = SAFETY_PORTS.get(dport) or ("Triconex/TriStation" if dport in extra else None)
    if service:
        return service
    if dport >= 1024:
        return SAFETY_PORTS.get(sport) or ("Triconex/TriStation" if sport in extra else None)
    return None


@memoize_analysis
def analyze_safety(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> SafetySummary:
    if TCP is None and UDP is None:
        return SafetySummary(
            path=path,
            total_packets=0,
            hits=[],
            source_counts=Counter(),
            destination_counts=Counter(),
            service_counts=Counter(),
            detections=[],
            errors=["Scapy TCP/UDP unavailable"],
        )

    total_packets = 0
    hits: list[SafetyHit] = []
    source_counts: Counter[str] = Counter()
    destination_counts: Counter[str] = Counter()
    service_counts: Counter[str] = Counter()
    errors: list[str] = []
    total_hits = 0
    public_hit_seen = False
    public_evidence_hits: list[SafetyHit] = []

    from .port_overrides import extra_ports

    tristation_extra = extra_ports("safety", "udp", path) | extra_ports("safety", "tcp", path)
    ts_frames = 0
    ts_requests: Counter[str] = Counter()
    ts_replies: Counter[str] = Counter()
    ts_rejects: Counter[str] = Counter()
    ts_tcm: Counter[str] = Counter()
    key_states: Counter[str] = Counter()
    run_states: Counter[str] = Counter()
    projects: Counter[str] = Counter()
    timeline: list[tuple[float | None, str, str, str]] = []
    command_events: list[object] = []
    category_hosts: dict[str, Counter[str]] = {}
    category_first: dict[str, float | None] = {}

    def decode_tristation(payload: bytes, src: str, dst: str, ts: float | None) -> None:
        nonlocal ts_frames
        frame = parse_frame(payload)
        if frame is None:
            return
        ts_frames += 1
        ts_tcm[frame.tcm_name] += 1
        if frame.command is None:
            return
        name = function_name(frame.command)
        if frame.is_reply:
            ts_replies[name] += 1
            if frame.is_reject:
                ts_rejects[name] += 1
            if frame.key_state:
                key_states[frame.key_state] += 1
            if frame.run_state:
                run_states[frame.run_state] += 1
            if frame.project_name:
                projects[frame.project_name] += 1
            return
        ts_requests[name] += 1
        category = _category(frame.command)
        if category:
            category_hosts.setdefault(category, Counter())[f"{src} -> {dst}"] += 1
            category_first.setdefault(category, ts)
        if len(timeline) < _MAX_TIMELINE and category != "status":
            timeline.append((ts, src, dst, name))
        if len(command_events) < _MAX_TIMELINE:
            command_events.append(IndustrialCommandEvent(ts=ts or 0.0, src=src, dst=dst, command=name))

    def record_hit(hit: SafetyHit) -> None:
        nonlocal total_hits, public_hit_seen
        total_hits += 1
        if len(hits) < _MAX_SAFETY_HITS:
            hits.append(hit)
        elif "Safety hit detail limit reached; counters include all matches." not in errors:
            errors.append("Safety hit detail limit reached; counters include all matches.")
        source_counts[hit.src] += 1
        destination_counts[hit.dst] += 1
        service_counts[hit.service] += 1
        if is_public_ip(hit.src) or is_public_ip(hit.dst):
            public_hit_seen = True
            if len(public_evidence_hits) < 8:
                public_evidence_hits.append(hit)

    skipped = 0
    first_error = None
    for pkt in iter_packets(path, packets=packets, meta=meta, show_status=show_status):
        try:
            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                service = _safety_service(sport, dport, tristation_extra)
                if service:
                    record_hit(
                        SafetyHit(
                            ts=ts, protocol="TCP", src=src_ip, dst=dst_ip,
                            src_port=sport, dst_port=dport, service=service,
                        )
                    )
                    if service == "Triconex/TriStation":
                        decode_tristation(_strip_padding(tcp.payload), src_ip, dst_ip, ts)

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                service = _safety_service(sport, dport, tristation_extra)
                if service:
                    record_hit(
                        SafetyHit(
                            ts=ts, protocol="UDP", src=src_ip, dst=dst_ip,
                            src_port=sport, dst_port=dport, service=service,
                        )
                    )
                    if service == "Triconex/TriStation":
                        decode_tristation(_strip_padding(udp.payload), src_ip, dst_ip, ts)
        except Exception as exc:  # noqa: BLE001 - one bad packet must not end the pass
            skipped += 1
            if first_error is None:
                first_error = f"{type(exc).__name__}: {exc}"
    if skipped:
        errors.append(
            f"{skipped} packet(s) skipped by the safety parser (first error: {first_error})."
        )

    detections: list[dict[str, object]] = []
    if total_hits:
        severity = "high" if public_hit_seen else "warning"
        # When public endpoints drive the high-severity escalation, show them
        # first in the evidence sample — otherwise hits[:8] can omit the very
        # hosts the "Public endpoints observed" claim is about.
        ordered_hits = public_evidence_hits + [
            hit for hit in hits if not (is_public_ip(hit.src) or is_public_ip(hit.dst))
        ]
        evidence = [
            f"{hit.protocol} {hit.src}:{hit.src_port}->{hit.dst}:{hit.dst_port} {hit.service}"
            for hit in ordered_hits[:8]
        ]
        details = (
            f"{total_hits} packet(s) across {len(service_counts)} safety service(s). "
            "Safety Instrumented Systems are the highest-consequence OT target "
            "(Triton/TRISIS) — any TriStation/SIS engineering traffic from a "
            "non-engineering host, or program-download activity, warrants "
            "investigation (ATT&CK ICS T0843 Program Download to a SIS)."
        )
        if public_hit_seen:
            details = f"{details} Public endpoints observed."
        detections.append(
            {
                "severity": severity,
                "summary": "Safety PLC/SIS protocol traffic observed",
                "details": details,
                "source": "Safety",
                "top_sources": source_counts.most_common(5),
                "top_destinations": destination_counts.most_common(5),
                "evidence": evidence,
            }
        )

    detections.extend(
        _tristation_detections(
            ts_requests, ts_rejects, key_states, projects, category_hosts, category_first
        )
    )
    return SafetySummary(
        path=path,
        total_packets=total_packets,
        hits=hits,
        source_counts=source_counts,
        destination_counts=destination_counts,
        service_counts=service_counts,
        detections=detections,
        errors=errors,
        tristation_frames=ts_frames,
        tristation_requests=ts_requests,
        tristation_replies=ts_replies,
        tristation_rejects=ts_rejects,
        tristation_tcm=ts_tcm,
        key_states=key_states,
        run_states=run_states,
        projects=projects,
        tristation_timeline=timeline,
        commands=Counter(ts_requests),
        command_events=command_events,
    )


def _category(code: int) -> str | None:
    if code in PROGRAM_CHANGE:
        return "program_change"
    if code in MODE_CHANGE:
        return "mode_change"
    if code in POINT_WRITE:
        return "point_write"
    if code in SAFETY_DISABLE:
        return "safety_disable"
    if code in PROGRAM_UPLOAD:
        return "program_upload"
    if code in CONFIG_CHANGE:
        return "config_change"
    if code in STATUS_READ:
        return "status"
    return None


def _hosts(category_hosts: dict[str, Counter[str]], category: str) -> str:
    return ", ".join(f"{pair} ({n})" for pair, n in category_hosts[category].most_common(3))


def _tristation_detections(
    requests: Counter[str],
    rejects: Counter[str],
    key_states: Counter[str],
    projects: Counter[str],
    category_hosts: dict[str, Counter[str]],
    category_first: dict[str, float | None],
) -> list[dict[str, object]]:
    """Findings for a Triconex SIS, worst first.

    The TRITON sequence (Nozomi/Mandiant/Dragos write-ups): the key switch
    left in PROGRAM, repeated 'Get CP status' polling, program/function
    upload to learn the controller, a 'download change' that allocates a new
    program (the implant appended to the running logic), then Run.
    """
    found: list[dict[str, object]] = []
    if not requests:
        return found

    def ops(codes: set[int]) -> str:
        names = {function_name(code) for code in codes}
        return ", ".join(f"{name} x{requests[name]}" for name in sorted(names) if requests.get(name))

    def evidence(category: str) -> list[str]:
        return [f"{pair}: {count}" for pair, count in category_hosts.get(category, Counter()).most_common(5)]

    program = "program_change" in category_hosts
    if program and ("mode_change" in category_hosts or "program_upload" in category_hosts):
        first_upload = category_first.get("program_upload")
        first_change = category_first.get("program_change")
        ordered = first_upload is not None and first_change is not None and first_upload <= first_change
        found.append(
            {
                "severity": "critical",
                "summary": "TRITON-pattern safety controller reprogramming (TriStation)",
                "details": (
                    "Program/function upload"
                    + (" followed by" if ordered else " and")
                    + f" a program download/change ({ops(PROGRAM_CHANGE)})"
                    + (f" and {ops(MODE_CHANGE)}" if "mode_change" in category_hosts else "")
                    + (f" while the key switch read {', '.join(key_states)}" if key_states else "")
                    + ". This is the TRITON/TRISIS sequence against a Triconex SIS "
                    "(ATT&CK for ICS T0845 Program Upload, T0843 Program Download, "
                    "T0821 Modify Controller Tasking, T0880 Loss of Safety)."
                ),
                "evidence": evidence("program_change") + evidence("program_upload")[:2],
            }
        )
    elif program:
        found.append(
            {
                "severity": "high",
                "summary": "Safety controller program download/change (TriStation)",
                "details": f"{ops(PROGRAM_CHANGE)} (ATT&CK for ICS T0843 Program Download).",
                "evidence": evidence("program_change"),
            }
        )
    if "safety_disable" in category_hosts:
        found.append(
            {
                "severity": "high",
                "summary": "Safety diagnostics disabled (TriStation OVD)",
                "details": f"{ops(SAFETY_DISABLE)} (ATT&CK for ICS T0880 Loss of Safety).",
                "evidence": evidence("safety_disable"),
            }
        )
    if "point_write" in category_hosts:
        found.append(
            {
                "severity": "high",
                "summary": "Safety controller point/retentive values written (TriStation)",
                "details": f"{ops(POINT_WRITE)} (ATT&CK for ICS T0836 Modify Parameter, T0855 Unauthorized Command Message).",
                "evidence": evidence("point_write"),
            }
        )
    if "mode_change" in category_hosts:
        found.append(
            {
                "severity": "high",
                "summary": "Safety controller run state changed (TriStation)",
                "details": f"{ops(MODE_CHANGE)} (ATT&CK for ICS T0858 Change Operating Mode).",
                "evidence": evidence("mode_change"),
            }
        )
    if "program_upload" in category_hosts:
        found.append(
            {
                "severity": "warning",
                "summary": "Safety controller logic uploaded (TriStation)",
                "details": f"{ops(PROGRAM_UPLOAD)} (ATT&CK for ICS T0845 Program Upload).",
                "evidence": evidence("program_upload"),
            }
        )
    if "config_change" in category_hosts:
        found.append(
            {
                "severity": "warning",
                "summary": "Safety controller configuration changed (TriStation)",
                "details": f"{ops(CONFIG_CHANGE)} (ATT&CK for ICS T0836 Modify Parameter).",
                "evidence": evidence("config_change"),
            }
        )
    risky_keys = [state for state in ("PROGRAM", "REMOTE") if key_states.get(state)]
    if risky_keys:
        found.append(
            {
                "severity": "warning",
                "summary": f"Triconex key switch in {'/'.join(risky_keys)} (accepts remote changes)",
                "details": (
                    "CP status replies report the key switch in "
                    + ", ".join(f"{state} x{key_states[state]}" for state in risky_keys)
                    + "; TRITON needed PROGRAM to write logic. RUN would have blocked it."
                    + (f" Project: {', '.join(projects)}." if projects else "")
                ),
            }
        )
    polls = requests.get("Get CP status", 0)
    if polls:
        found.append(
            {
                "severity": "info",
                "summary": "TriStation status polling",
                "details": f"{polls} 'Get CP status' request(s); {_hosts(category_hosts, 'status') if 'status' in category_hosts else ''}.",
            }
        )
    if rejects:
        found.append(
            {
                "severity": "info",
                "summary": "TriStation commands rejected by the controller",
                "details": ", ".join(f"{name} x{count}" for name, count in rejects.most_common(6)) + ".",
            }
        )
    return found
