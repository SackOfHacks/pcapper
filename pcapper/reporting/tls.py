"""Rendered output for TLS/HTTPS: findings, then the hunting pivots --
server names (SNI), client fingerprints (JA3/JA4) and server fingerprints
(JA4S) with the hosts behind them, per-client and per-destination handshake
profiles, certificates and VirusTotal hits. Versions and weak ciphers are
in the headline; conversations, cipher inventory, HTTP-over-TLS counters and
the scored assessment are -v."""

from __future__ import annotations

from collections import Counter

from ..tls import TlsSummary
from ..utils import format_duration, is_public_ip
from . import _style as st
from ._common import _redact_in_text
from ._kv import counter_line, findings_for

_LEGACY = {"SSL2.0", "SSL3.0", "TLS1.0", "TLS1.1", "SSLv2", "SSLv3"}


def _assessment(summary: TlsSummary) -> tuple[str, str, int, list[str]]:
    detections = list(getattr(summary, "detections", []) or [])
    score = 0
    reasons: list[str] = []
    crit = sum(1 for d in detections if str(d.get("severity", "")).lower() == "critical")
    high = sum(1 for d in detections if str(d.get("severity", "")).lower() == "high")
    warn = sum(1 for d in detections if str(d.get("severity", "")).lower() == "warning")
    for hit, weight, text in (
        (crit, min(4, crit * 2), f"critical TLS findings ({crit})"),
        (high, min(3, high), f"high-severity TLS findings ({high})"),
        (warn >= 2, 1, f"multiple warning-level TLS findings ({warn})"),
        (summary.weak_certs, 2, f"weak certificate keys ({summary.weak_certs})"),
        (summary.expired_certs, 2, f"expired certificates ({summary.expired_certs})"),
        (summary.self_signed_certs, 1, f"self-signed certificates ({summary.self_signed_certs})"),
        (summary.weak_ciphers, 1, f"weak cipher suites ({sum(summary.weak_ciphers.values())})"),
        (summary.sni_missing_no_ech >= 10 and summary.client_hellos, 1,
         f"SNI missing (no ECH) in {summary.sni_missing_no_ech}/{summary.client_hellos} client hellos"),
    ):
        if hit:
            score += weight
            reasons.append(text)
    if score >= 7:
        return "YES - high-confidence TLS risks or compromise indicators", "High", score, reasons
    if score >= 4:
        return "LIKELY - significant TLS issues warranting response", "Medium", score, reasons
    if score >= 2:
        return "POSSIBLE - TLS issues; corroboration recommended", "Low", score, reasons
    return "NO STRONG SIGNAL from the current heuristics", "Low", score, reasons


def _top(counter: object, n: int = 2) -> str:
    return st.top(counter or Counter(), n)


def render_tls_summary(summary: TlsSummary, limit: int = 12, verbose: bool = False) -> str:
    rep = st.Report("TLS", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.tls_packets and not summary.client_hellos and not st.material(findings):
        return rep.absent("TLS traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity TLS activity: investigate", medium="TLS activity to review")
    versions = ", ".join((st.caution(f"{v} ({n})") if v in _LEGACY else f"{v} ({n})") for v, n in summary.versions.most_common())
    rep.headline(severity, text, st.join([
        f"{st.count(summary.tls_packets)} TLS packets",
        f"{summary.client_hellos} ClientHello / {summary.server_hellos} ServerHello",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.join([
        f"{st.plural(len(summary.client_counts), 'client')} -> {st.plural(len(summary.server_counts), 'server')}",
        st.plural(len(summary.sni_counts), "server name"), versions,
    ]))
    extras = st.join([
        f"{summary.ech_hellos} ECH" if getattr(summary, "ech_hellos", 0) else "",
        st.caution(f"{summary.sni_missing_no_ech} without SNI") if getattr(summary, "sni_missing_no_ech", 0) else "",
        st.caution("weak ciphers " + st.top(summary.weak_ciphers, 3)) if summary.weak_ciphers else "",
    ])
    if extras:
        rep.scope(extras)
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    sni_clients = getattr(summary, "sni_to_clients", None) or {}
    sni_servers = getattr(summary, "sni_to_servers", None) or {}
    sni_ja3 = getattr(summary, "sni_to_ja3", None) or {}
    rep.section("Server names", st.table(
        ["SNI", "Hellos", "Clients", "Servers", "JA3"],
        [[_redact_in_text(str(sni)), st.count(n), _top(sni_clients.get(sni)), _top(sni_servers.get(sni)), _top(sni_ja3.get(sni), 1)]
         for sni, n in summary.sni_counts.most_common()],
        align="lrlll", widths=(48, None, 36, 36, 40), max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="server name",
    ))
    ja3_sni = getattr(summary, "ja3_to_sni", None) or {}
    ja4_sni = getattr(summary, "ja4_to_sni", None) or {}
    ja3_clients: dict[str, Counter] = {}
    for client, counter in (getattr(summary, "client_ja3_counts", None) or {}).items():
        for ja3, n in counter.items():
            ja3_clients.setdefault(ja3, Counter())[client] += n
    fp_rows = [["JA3", h, n, _top(ja3_clients.get(h), 3), _top(ja3_sni.get(h), 3)] for h, n in summary.ja3_counts.most_common()]
    ja4_clients: dict[str, Counter] = {}
    for client, counter in (getattr(summary, "client_ja4_counts", None) or {}).items():
        for ja4, n in counter.items():
            ja4_clients.setdefault(ja4, Counter())[client] += n
    fp_rows += [["JA4", h, n, _top(ja4_clients.get(h), 3), _top(ja4_sni.get(h), 3)] for h, n in summary.ja4_counts.most_common()]
    ja4s_servers: dict[str, Counter] = {}
    for server, counter in (getattr(summary, "server_endpoint_ja4s_counts", None) or {}).items():
        for ja4s, n in counter.items():
            ja4s_servers.setdefault(ja4s, Counter())[server] += n
    fp_rows += [["JA4S", h, n, _top(ja4s_servers.get(h), 3), ""] for h, n in summary.ja4s_counts.most_common()]
    # One ranking across JA3/JA4/JA4S, so its bottom rows are the rarest fingerprints.
    fp_rows = [[t, h, st.count(n), hosts, names] for t, h, n, hosts, names in sorted(fp_rows, key=lambda r: -int(r[2]))]
    rep.section("Fingerprints", st.ranked(["Type", "Fingerprint", "Count", "Hosts", "Server names"], fp_rows,
                                          align="llrll", widths=(None, 38, None, 40, 50), noun="fingerprint"))

    # Per-client handshake profile: volume, name diversity, missing SNI, ECH,
    # failures -- the shape of a beacon or a scanner differs from a browser.
    sni_by_client = getattr(summary, "client_sni_counts", None) or {}
    ja3_by_client = getattr(summary, "client_ja3_counts", None) or {}
    alpn_by_client = getattr(summary, "client_alpn_counts", None) or {}
    missing = getattr(summary, "client_missing_sni", None) or Counter()
    ech = getattr(summary, "client_ech_counts", None) or Counter()
    fails = getattr(summary, "client_handshake_failures", None) or Counter()
    hello_counts = getattr(summary, "client_hello_counts", None) or Counter()
    rep.section("Clients", st.table(
        ["Client", "Hellos", "Names", "JA3s", "No SNI", "ECH", "Failed", "Top names"] + (["ALPN"] if st.verbose() else []),
        [[c, st.count(n), st.count(len(sni_by_client.get(c, {}) or {})), st.count(len(ja3_by_client.get(c, {}) or {})),
          st.caution(str(missing.get(c))) if missing.get(c) else "0", ech.get(c, 0),
          st.caution(str(fails.get(c))) if fails.get(c) else "0", _top(sni_by_client.get(c), 2)]
         + ([_top(alpn_by_client.get(c), 3)] if st.verbose() else []) for c, n in hello_counts.most_common()],
        align="lrrrrrrl", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="client",
    ))
    endpoint_sni = getattr(summary, "server_endpoint_sni_counts", None) or {}
    endpoint_ja4s = getattr(summary, "server_endpoint_ja4s_counts", None) or {}
    server_fails = getattr(summary, "server_handshake_failures", None) or Counter()
    endpoint_stats: dict[str, dict] = {}
    hello_servers = set(getattr(summary, "server_hello_counts", None) or {})
    for conv in summary.conversations:
        # A server->client half on the client's ephemeral port, with no
        # hellos of its own, is not a destination.
        if (not conv.client_hellos and not conv.server_hellos and int(conv.server_port) >= 1024
                and conv.server_ip not in hello_servers):
            continue
        key = f"{conv.server_ip}:{conv.server_port}"
        e = endpoint_stats.setdefault(key, {"clients": set(), "hellos": 0, "bytes": 0, "ip": conv.server_ip})
        e["clients"].add(conv.client_ip)
        e["hellos"] += int(conv.client_hellos or 0)
        e["bytes"] += int(conv.bytes or 0)
    rep.section("Destinations", st.table(
        ["Service", "Scope", "Clients", "Hellos", "Bytes", "Top names", "JA4S", "Failed"],
        [[k, "public" if is_public_ip(e["ip"]) else "private", st.count(len(e["clients"])), st.count(e["hellos"]), st.size(e["bytes"]),
          _top(endpoint_sni.get(k), 2), _top(endpoint_ja4s.get(k), 1), server_fails.get(e["ip"], 0)]
         for k, e in sorted(endpoint_stats.items(), key=lambda kv: (-kv[1]["bytes"], kv[0]))],
        align="llrrrllr", widths=(None, None, None, None, None, 40, 30), max_rows=st.TOP_ROWS, tail=st.TOP_ROWS, noun="destination",
    ))

    certs = list(getattr(summary, "cert_artifacts", None) or [])
    verbose_view = st.verbose()
    rep.section("Certificates", st.table(
        ["Subject", "Issuer", "Not after", "Key", "SNI", "Flow"] + (["Serial", "SHA256", "SHA1"] if verbose_view else []),
        [[_redact_in_text(str(getattr(c, "subject", "-"))), _redact_in_text(str(getattr(c, "issuer", "-"))), getattr(c, "not_after", "-"),
          f"{getattr(c, 'pubkey_type', '')} {getattr(c, 'pubkey_size', '')}".strip() or "-", getattr(c, "sni", "") or "-",
          st.flow(getattr(c, "src_ip", "?"), getattr(c, "dst_ip", "?"))]
         + ([getattr(c, "serial", "-"), getattr(c, "sha256", "-"), getattr(c, "sha1", "-")] if verbose_view else []) for c in certs],
        widths=(40, 40), max_rows=8, noun="certificate",
    ) + (st.kv([("Posture", st.join([f"{summary.cert_count} certificates", f"{summary.self_signed_certs} self-signed",
                                     f"{summary.expired_certs} expired", f"{summary.weak_certs} weak key"]))]) if summary.cert_count else []))
    vt = dict(getattr(summary, "vt_results", None) or {})
    ranked = sorted(vt.items(), key=lambda kv: (int(kv[1].get("malicious", 0) or 0), int(kv[1].get("suspicious", 0) or 0),
                                                int(kv[1].get("reputation", 0) or 0)), reverse=True)
    rep.section("VirusTotal", st.table(
        ["Domain", "Malicious", "Suspicious", "Reputation", "Report"],
        [[d, st.bad(str(i.get("malicious", 0))) if int(i.get("malicious", 0) or 0) else "0", i.get("suspicious", 0),
          i.get("reputation", "-"), i.get("report_url", "-")] for d, i in ranked
         if verbose_view or int(i.get("malicious", 0) or 0) or int(i.get("suspicious", 0) or 0)],
        align="lrrrl", max_rows=15, noun="domain",
    ) + st.bullets([str(e) for e in (getattr(summary, "vt_errors", None) or [])], max_items=None))

    # ---- reference (-v) --------------------------------------------------
    verdict, confidence, score, reasons = _assessment(summary)
    rep.section("Assessment", st.kv([("Verdict", verdict), ("Confidence", f"{confidence} (score={score})")])
                + st.bullets(reasons, max_items=None), detail=True)
    tls_bytes = sum(max(0, int(c.bytes)) for c in summary.conversations)
    rep.section("Posture", st.kv([
        ("Packets", f"{summary.total_packets} total · {summary.tls_packets} TLS"
                    + (f" ({summary.tls_packets / summary.total_packets:.1%})" if summary.total_packets else "")),
        ("TLS-like packets", str(summary.tls_like_packets) if getattr(summary, "tls_like_packets", 0) != summary.tls_packets else ""),
        ("Raw parsed hellos", f"client {getattr(summary, 'raw_client_hellos', 0)} · server {getattr(summary, 'raw_server_hellos', 0)}"),
        ("Handshake success", f"{summary.server_hellos / max(summary.client_hellos, 1):.1%}" if summary.client_hellos else ""),
        ("Missing SNI", f"{getattr(summary, 'sni_missing_total', 0)} total · {getattr(summary, 'sni_missing_no_ech', 0)} without ECH"),
        ("Conversations", f"{len(summary.conversations)} · {st.size(tls_bytes)}"),
        ("Duration", format_duration(summary.duration_seconds) if summary.duration_seconds is not None else ""),
        counter_line("Versions", summary.versions, None),
        counter_line("ALPN", summary.alpn_counts, None),
        counter_line("Ports", summary.server_ports, None),
        counter_line("Clients", summary.client_counts, None),
        counter_line("Servers", summary.server_counts, None),
        counter_line("Non-standard TLS clients", getattr(summary, "nonstandard_tls_clients", None), None),
        counter_line("Non-standard TLS servers", getattr(summary, "nonstandard_tls_servers", None), None),
    ]), detail=True)
    weak = set(summary.weak_ciphers or {})
    rep.section("Cipher suites", st.table(
        ["Cipher", "Count", "Class"], [[c, st.count(n), "weak" if c in weak else "-"] for c, n in summary.cipher_suites.most_common()],
        align="lrl", max_rows=None,
    ), detail=True)
    rep.section("Conversations", st.table(
        ["Client", "Server", "Packets", "Bytes", "CH/SH", "First", "Last", "SNI", "JA3/JA4", "ALPN", "Versions", "JA4S"],
        [[c.client_ip, f"{c.server_ip}:{c.server_port}", st.count(c.packets), st.size(c.bytes), f"{c.client_hellos}/{c.server_hellos}",
          st.ts(c.first_seen), st.ts(c.last_seen), _redact_in_text(str(c.sni or "-")),
          " / ".join(str(x) for x in (c.ja3, c.ja4) if x) or "-", ", ".join(c.alpn) if isinstance(c.alpn, (list, tuple, set)) else (c.alpn or "-"),
          ", ".join(c.versions) if isinstance(c.versions, (list, tuple, set)) else (c.versions or "-"), c.ja4s or "-"]
         for c in sorted(summary.conversations, key=lambda c: c.bytes, reverse=True)],
        align="llrrllllllll", max_rows=None, noun="conversation",
    ), detail=True)
    rep.section("HTTP over this transport", st.kv([
        ("Requests / responses", f"{summary.http_requests} / {summary.http_responses}" if summary.http_requests or summary.http_responses else ""),
        counter_line("Methods", summary.http_methods, None), counter_line("Statuses", summary.http_statuses, None),
        counter_line("URLs", summary.http_urls, None), counter_line("User agents", summary.http_user_agents, None),
        counter_line("Files", summary.http_files, None), counter_line("Referrers", summary.http_referrers, None),
        counter_line("HTTP clients", summary.http_clients, None), counter_line("HTTP servers", summary.http_servers, None),
    ]), detail=True)
    rep.section("Notes", st.bullets([str(n) for n in (summary.analysis_notes or [])], max_items=None), detail=True)
    rep.section("Artifacts", st.bullets([_redact_in_text(str(a)) for a in (summary.artifacts or [])], max_items=None), detail=True)
    return rep.render()
