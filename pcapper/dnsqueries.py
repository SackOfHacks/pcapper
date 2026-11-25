"""--dnsqueries: every DNS lookup in a capture with the response observed for
it -- who asked which resolver, for what name and type, and what came back
(the answers, NXDOMAIN or another error, or no response at all). LLMNR and
mDNS lookups use the same wire format and are included, labelled."""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .dns import _qtype_name, rcode_name
from .pcap_cache import PcapMeta, iter_packets
from .utils import (
    dns_answers,
    dns_message,
    dns_questions,
    env_int,
    extract_packet_endpoints,
    memoize_analysis,
    safe_float,
)
from .utils import vt_api_key

try:  # pragma: no cover - scapy is a hard dependency; keep import errors readable
    from scapy.layers.dns import DNS
    from scapy.layers.inet import TCP, UDP
except Exception:  # noqa: BLE001
    DNS = TCP = UDP = None  # type: ignore[assignment]

# Records kept per capture (each is one question and its response); further
# lookups are counted in ``dropped``.
MAX_QUERY_RECORDS = env_int("PCAPPER_MAX_DNS_QUERY_RECORDS", 200_000, minimum=1)
_MAX_PENDING = 100_000
_MAX_QUESTIONS = 16  # per packet (mDNS packs many)
_MAX_ANSWERS = 20  # per record
_MDNS_GROUPS = {"224.0.0.251", "ff02::fb"}
_LLMNR_GROUPS = {"224.0.0.252", "ff02::1:3"}


@dataclass(frozen=True)
class DnsQuerySummary:
    path: Path
    total_packets: int = 0
    dns_packets: int = 0
    # One record per question: ts, packet, client, client_port, server,
    # server_port, transport, protocol, id, name, qtype, status ("answered",
    # "no response", "response only"), rcode, answers, rtt_ms.
    queries: list[dict[str, object]] = field(default_factory=list)
    dropped: int = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    duration_seconds: Optional[float] = None
    vt_results: dict[str, dict[str, object]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _answer_text(rrtype: int, value: str) -> str:
    if rrtype in (1, 28):  # A / AAAA: the address says it all
        return value
    return f"{_qtype_name(rrtype)} {value}".strip()


def _protocol(src: str, dst: str, sport: Optional[int], dport: Optional[int]) -> str:
    if 5353 in (sport, dport) or dst in _MDNS_GROUPS or src in _MDNS_GROUPS:
        return "mDNS"
    if 5355 in (sport, dport) or dst in _LLMNR_GROUPS:
        return "LLMNR"
    return "DNS"


def _vt_lookups(names: list[str]) -> tuple[dict[str, dict[str, object]], list[str]]:
    from .dns import _vt_lookup_domains

    api_key = vt_api_key()
    if not api_key:
        return {}, ["VT_API_KEY is not set; skipping VirusTotal lookups."]
    try:
        results, errors = _vt_lookup_domains(names, api_key)
    except Exception as exc:  # noqa: BLE001
        return {}, [f"VirusTotal lookup failed: {type(exc).__name__}: {exc}"]
    return {str(k).strip(".").lower(): dict(v) for k, v in (results or {}).items()}, [str(e) for e in errors or []]


@memoize_analysis
def analyze_dns_queries(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
    vt_lookup: bool = False,
) -> DnsQuerySummary:
    """Every DNS / LLMNR / mDNS question in ``path`` paired with its response:
    by (client, transaction ID, name, type), or for a multicast query by
    (transaction ID, name, type) since any host may answer it."""
    if DNS is None:
        return DnsQuerySummary(path=path, errors=["Scapy DNS layers unavailable; install scapy for DNS analysis."])
    records: list[dict[str, object]] = []
    pending: "OrderedDict[tuple, int]" = OrderedDict()
    pending_multicast: "OrderedDict[tuple, int]" = OrderedDict()
    total_packets = dns_packets = dropped = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    errors: list[str] = []

    def _remember(index: OrderedDict, key: tuple, position: int) -> None:
        index[key] = position
        if len(index) > _MAX_PENDING:
            index.popitem(last=False)

    for packet_no, pkt in enumerate(iter_packets(path, packets=packets, meta=meta, show_status=show_status), start=1):
        total_packets += 1
        try:
            dns_layer = dns_message(pkt)
        except Exception:  # noqa: BLE001
            dns_layer = None
        if dns_layer is None:
            continue
        dns_packets += 1
        try:
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                first_seen = ts if first_seen is None else min(first_seen, ts)
                last_seen = ts if last_seen is None else max(last_seen, ts)
            src, dst = extract_packet_endpoints(pkt)
            transport, sport, dport = "-", None, None
            for layer, label in ((UDP, "UDP"), (TCP, "TCP")):
                if layer is not None and pkt.haslayer(layer):  # type: ignore[truthy-bool]
                    seg = pkt[layer]  # type: ignore[index]
                    transport = label
                    sport = int(getattr(seg, "sport", 0) or 0) or None
                    dport = int(getattr(seg, "dport", 0) or 0) or None
                    break
            protocol = _protocol(str(src or ""), str(dst or ""), sport, dport)
            txid = int(getattr(dns_layer, "id", 0) or 0)
            questions = dns_questions(dns_layer)[:_MAX_QUESTIONS] or [("", 0)]
            if int(getattr(dns_layer, "qr", 0) or 0) == 0:  # a query
                for name, qtype in questions:
                    if not name:
                        continue
                    if len(records) >= MAX_QUERY_RECORDS:
                        dropped += 1
                        continue
                    records.append({
                        "ts": ts, "packet": packet_no, "client": src or "-", "client_port": sport,
                        "server": dst or "-", "server_port": dport, "transport": transport, "protocol": protocol,
                        "id": txid, "name": name, "qtype": _qtype_name(qtype), "status": "no response",
                        "rcode": "", "answers": [], "rtt_ms": None,
                    })
                    key = (name.lower(), qtype, txid)
                    if dst in _MDNS_GROUPS or dst in _LLMNR_GROUPS:
                        _remember(pending_multicast, key, len(records) - 1)
                    else:
                        _remember(pending, (src,) + key, len(records) - 1)
                continue
            # A response: fill in the query it answers, or record it alone.
            rcode = rcode_name(int(getattr(dns_layer, "rcode", 0) or 0))
            answers = [_answer_text(rrtype, value) for rrtype, _name, value in dns_answers(dns_layer, _MAX_ANSWERS) if value]
            for name, qtype in questions:
                key = (name.lower(), qtype, txid)
                position = pending.pop((dst,) + key, None)
                if position is None:
                    position = pending_multicast.get(key)
                record = records[position] if position is not None else None
                if record is not None and record["status"] == "no response":
                    record.update(status="answered", rcode=rcode, answers=answers)
                    if record["server"] in _MDNS_GROUPS or record["server"] in _LLMNR_GROUPS:
                        record["server"] = src or "-"  # the host that answered the multicast query
                    if ts is not None and record.get("ts") is not None:
                        record["rtt_ms"] = round(max(0.0, ts - float(record["ts"])) * 1000.0, 3)  # type: ignore[arg-type]
                    continue
                if record is not None:  # another answer to a multicast query
                    record["answers"] = list(dict.fromkeys([*record["answers"], *answers]))[:_MAX_ANSWERS]  # type: ignore[list-item]
                    continue
                if len(records) >= MAX_QUERY_RECORDS:
                    dropped += 1
                    continue
                records.append({
                    "ts": ts, "packet": packet_no, "client": dst or "-", "client_port": dport,
                    "server": src or "-", "server_port": sport, "transport": transport, "protocol": protocol,
                    "id": txid, "name": name or (answers and "-") or "-", "qtype": _qtype_name(qtype) if qtype else "-",
                    "status": "response only", "rcode": rcode, "answers": answers, "rtt_ms": None,
                })
        except Exception as exc:  # noqa: BLE001 - one malformed message must not end the pass
            if len(errors) < 5:
                errors.append(f"packet {packet_no}: {type(exc).__name__}: {exc}")

    vt_results: dict[str, dict[str, object]] = {}
    if vt_lookup and records:
        names = list(dict.fromkeys(str(r["name"]).strip(".").lower() for r in records
                                   if r.get("protocol") == "DNS" and r.get("name") not in (None, "", "-")))
        vt_results, vt_errors = _vt_lookups(names)
        errors.extend(vt_errors)

    return DnsQuerySummary(
        path=path,
        total_packets=total_packets,
        dns_packets=dns_packets,
        queries=records,
        dropped=dropped,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=(last_seen - first_seen) if first_seen is not None and last_seen is not None else None,
        vt_results=vt_results,
        errors=errors,
    )
