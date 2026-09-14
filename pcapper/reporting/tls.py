"""Rendered output for tls analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations
from ..utils import is_public_ip as _is_public_ip
from collections import Counter, defaultdict
from datetime import datetime, timezone
from ..coloring import (
    danger,
    header,
    label,
    muted,
    ok,
    warn,
)
from ..tls import TlsSummary
from ..utils import (
    format_bytes_as_mb,
    format_duration,
    format_ts,
)

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _apply_verbose_limit,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_counter,
    _format_kv,
    _format_table,
    _highlight_public_ips,
    _limit_value,
    _redact_in_text,
    _truncate_text,
    _verbose_output,
    set_verbose_output,
)


def _render_tls_summary_impl(
    summary: TlsSummary, limit: int = 12, verbose: bool = False
) -> str:
    limit = _apply_verbose_limit(limit) or limit
    concise_mode = not verbose
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"TLS/HTTPS ANALYSIS :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    lines.append(SUBSECTION_BAR)
    lines.append(header("TLS Posture"))
    lines.append(_format_kv("Total Packets", str(summary.total_packets)))
    lines.append(_format_kv("TLS Packets", str(summary.tls_packets)))
    if summary.total_packets:
        lines.append(
            _format_kv(
                "TLS Share",
                f"{(summary.tls_packets / max(summary.total_packets, 1)) * 100.0:.1f}%",
            )
        )
    if (
        getattr(summary, "tls_like_packets", 0)
        and summary.tls_like_packets != summary.tls_packets
    ):
        lines.append(_format_kv("TLS-Like Packets", str(summary.tls_like_packets)))
    lines.append(_format_kv("Client Hellos", str(summary.client_hellos)))
    lines.append(_format_kv("Server Hellos", str(summary.server_hellos)))
    if getattr(summary, "raw_client_hellos", 0) or getattr(
        summary, "raw_server_hellos", 0
    ):
        lines.append(
            _format_kv(
                "Raw Parsed Hellos",
                f"client={getattr(summary, 'raw_client_hellos', 0)}, server={getattr(summary, 'raw_server_hellos', 0)}",
            )
        )
    if summary.client_hellos:
        lines.append(
            _format_kv(
                "Handshake Success",
                f"{(summary.server_hellos / max(summary.client_hellos, 1)) * 100.0:.1f}%",
            )
        )
    lines.append(_format_kv("Unique TLS Clients", str(len(summary.client_counts))))
    lines.append(_format_kv("Unique TLS Servers", str(len(summary.server_counts))))
    lines.append(_format_kv("Unique SNI", str(len(summary.sni_counts))))
    lines.append(_format_kv("Unique JA3", str(len(summary.ja3_counts))))
    lines.append(_format_kv("Unique JA4", str(len(summary.ja4_counts))))
    if getattr(summary, "ech_hellos", 0):
        lines.append(_format_kv("ECH Client Hellos", str(summary.ech_hellos)))
    if getattr(summary, "sni_missing_no_ech", 0):
        lines.append(
            _format_kv(
                "Missing SNI (No ECH)",
                f"{summary.sni_missing_no_ech}/{summary.client_hellos}",
            )
        )
    lines.append(_format_kv("TLS Conversations", str(len(summary.conversations))))
    lines.append(_format_kv("Start", format_ts(summary.first_seen)))
    lines.append(_format_kv("End", format_ts(summary.last_seen)))
    lines.append(_format_kv("Duration", format_duration(summary.duration_seconds)))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Deterministic TLS Security Checks"))

    detection_items = list(getattr(summary, "detections", []) or [])

    def _matching_tls_detections(keywords: tuple[str, ...]) -> list[dict[str, object]]:
        matches: list[dict[str, object]] = []
        for det in detection_items:
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            blob = f"{summary_text} {details_text}".lower()
            if any(key in blob for key in keywords):
                matches.append(det)
        return matches

    def _matching_tls_lines(
        keywords: tuple[str, ...], limit_lines: int = 4
    ) -> list[str]:
        out: list[str] = []
        for det in _matching_tls_detections(keywords):
            summary_text = str(det.get("summary", "") or "")
            details_text = str(det.get("details", "") or "")
            line = summary_text
            if details_text:
                line = f"{summary_text}: {details_text}"
            out.append(_redact_in_text(line))
            if len(out) >= limit_lines:
                break
        return out[:limit_lines]

    tls_checks: list[tuple[str, tuple[str, ...]]] = [
        ("Certificate Pinning Drift", ("certificate pinning drift", "cert rotation")),
        ("JA3/JA4 Novelty", ("ja3 novelty", "ja4 novelty", "rarity spike")),
        (
            "Fingerprint Cardinality Anomalies",
            ("cardinality anomaly", "ja3 to sni", "sni to ja3"),
        ),
        ("Cipher Downgrade Inconsistency", ("cipher downgrade inconsistency",)),
        (
            "ALPN Mismatch/Anomalies",
            ("alpn mismatch", "alpn missing anomaly", "uncommon protocol tokens"),
        ),
        ("Certificate Validity Outliers", ("certificate validity outliers",)),
        ("Issuer/SAN Impersonation", ("impersonation heuristics", "issuer/san")),
        ("Handshake Periodicity", ("handshake periodicity",)),
        (
            "Session Resumption Abuse",
            ("session resumption-heavy", "session resumption"),
        ),
        (
            "SNI Evasion/Anomaly",
            (
                "sni missing",
                "sni suppression",
                "high-entropy sni",
                "suspicious sni",
                "sni uses ip literal",
            ),
        ),
        (
            "Non-Standard TLS Service Ports",
            ("non-standard ports", "non-standard tls"),
        ),
        (
            "Legacy/Weak TLS Crypto",
            ("legacy tls versions", "weak tls cipher", "weak tls certificate keys"),
        ),
        (
            "TLS Handshake Failure Pattern",
            ("tls handshake failures", "without server hello"),
        ),
    ]

    for label_text, keywords in tls_checks:
        lines.append(label(label_text))
        evidence_lines = _matching_tls_lines(keywords)
        if evidence_lines:
            lines.append(
                warn(
                    f"Yes, there is evidence for {label_text.lower()}, here is the evidence:"
                )
            )
            for item in evidence_lines:
                lines.append(muted(f"- {item}"))
        else:
            lines.append(
                ok(
                    f"No, there is no strong evidence for {label_text.lower()} in this capture."
                )
            )

    tls_total_bytes = sum(max(0, int(conv.bytes)) for conv in summary.conversations)
    lines.append(_format_kv("TLS Bytes (Conversations)", str(tls_total_bytes)))
    if summary.conversations:
        lines.append(
            _format_kv(
                "Avg Bytes / Conversation",
                f"{tls_total_bytes / max(len(summary.conversations), 1):.1f}",
            )
        )
        lines.append(
            _format_kv(
                "Avg Packets / Conversation",
                f"{sum(int(conv.packets) for conv in summary.conversations) / max(len(summary.conversations), 1):.1f}",
            )
        )

    def _tls_verdict() -> tuple[str, str, list[str], int]:
        score = 0
        reasons: list[str] = []
        detections = list(getattr(summary, "detections", []) or [])

        critical_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "critical"
        )
        high_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "high"
        )
        warning_count = sum(
            1 for d in detections if str(d.get("severity", "")).lower() == "warning"
        )
        if critical_count:
            score += min(4, critical_count * 2)
            reasons.append(f"Critical TLS findings detected ({critical_count})")
        if high_count:
            score += min(3, high_count)
            reasons.append(f"High-severity TLS findings detected ({high_count})")
        if warning_count >= 2:
            score += 1
            reasons.append(
                f"Multiple warning-level TLS findings detected ({warning_count})"
            )

        if summary.weak_certs:
            score += 2
            reasons.append(f"Weak certificate keys detected ({summary.weak_certs})")
        if summary.expired_certs:
            score += 2
            reasons.append(f"Expired certificates detected ({summary.expired_certs})")
        if summary.self_signed_certs:
            score += 1
            reasons.append(
                f"Self-signed certificates detected ({summary.self_signed_certs})"
            )
        if summary.weak_ciphers:
            score += 1
            reasons.append(
                f"Weak cipher suites detected ({sum(summary.weak_ciphers.values())})"
            )
        if summary.sni_missing_no_ech >= 10 and summary.client_hellos:
            score += 1
            reasons.append(
                f"SNI missing (excluding ECH) for {summary.sni_missing_no_ech}/{summary.client_hellos} client hellos"
            )

        if score >= 7:
            verdict = "YES - high-confidence TLS security risks or compromise indicators are present."
            confidence = "High"
        elif score >= 4:
            verdict = "LIKELY - significant TLS security issues are present and warrant response."
            confidence = "Medium"
        elif score >= 2:
            verdict = (
                "POSSIBLE - TLS security issues are present; corroboration recommended."
            )
            confidence = "Low"
        else:
            verdict = "NO STRONG SIGNAL - no convincing high-risk TLS compromise pattern from current heuristics."
            confidence = "Low"

        if not reasons:
            reasons.append("No high-confidence TLS threat heuristic crossed threshold")
        return verdict, confidence, reasons, score

    verdict, confidence, verdict_reasons, verdict_score = _tls_verdict()
    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    if verdict.startswith("YES"):
        lines.append(danger(verdict))
    elif verdict.startswith("LIKELY") or verdict.startswith("POSSIBLE"):
        lines.append(warn(verdict))
    else:
        lines.append(ok(verdict))
    lines.append(_format_kv("Confidence", f"{confidence} (score={verdict_score})"))
    lines.append(muted("Why confidence:"))
    for reason in verdict_reasons[: _limit_value(10)]:
        lines.append(muted(f"- {_redact_in_text(reason)}"))

    # Add concrete context for immediate triage.
    if verbose:
        if summary.server_counts:
            lines.append(muted("Where:"))
            lines.append(muted("- Top TLS servers"))
            for server, count in summary.server_counts.most_common(_limit_value(8)):
                lines.append(
                    muted(f"- {_highlight_public_ips(str(server))}: {int(count)}")
                )
        if summary.client_counts:
            lines.append(muted("Who:"))
            lines.append(muted("- Top TLS clients"))
            for client, count in summary.client_counts.most_common(_limit_value(8)):
                lines.append(
                    muted(f"- {_highlight_public_ips(str(client))}: {int(count)}")
                )
        if summary.sni_counts:
            lines.append(muted("Where:"))
            lines.append(muted("- Top SNI targets"))
            for sni, count in summary.sni_counts.most_common(_limit_value(8)):
                lines.append(muted(f"- {_redact_in_text(str(sni))}: {int(count)}"))
        if summary.weak_ciphers:
            lines.append(muted("What:"))
            lines.append(muted("- Weak cipher evidence"))
            for cipher_name, count in summary.weak_ciphers.most_common(_limit_value(6)):
                lines.append(
                    muted(f"- {_redact_in_text(str(cipher_name))}: {int(count)}")
                )
        if summary.detections:
            lines.append(muted("What:"))
            lines.append(muted("- Top TLS detections"))
            for det in summary.detections[: _limit_value(6)]:
                lines.append(
                    muted(
                        f"- [{str(det.get('severity', 'info')).upper()}] "
                        f"{_redact_in_text(str(det.get('summary', '-')))}"
                    )
                )

    def _as_counter(value: object) -> Counter[str]:
        if isinstance(value, Counter):
            return value
        if isinstance(value, dict):
            counter: Counter[str] = Counter()
            for key, count in value.items():
                try:
                    counter[str(key)] = int(count)
                except Exception:
                    continue
            return counter
        return Counter()

    def _nested_counter(mapping: object, key: str) -> Counter[str]:
        if not isinstance(mapping, dict):
            return Counter()
        return _as_counter(mapping.get(key, {}))

    def _top_counter_text(counter: Counter[str], limit_items: int, width: int) -> str:
        if not counter:
            return "-"
        return ", ".join(
            f"{_truncate_text(_redact_in_text(str(name)), width)}({int(count)})"
            for name, count in counter.most_common(_limit_value(limit_items))
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Server Name"))
    if summary.sni_counts:
        rows = [["Server Name (SNI)", "Count", "Clients", "Services"]]
        for sni, count in summary.sni_counts.most_common(
            _limit_value(limit if verbose else min(10, limit))
        ):
            sni_text = str(sni)
            client_counter = _nested_counter(
                getattr(summary, "sni_to_clients", {}), sni_text
            )
            service_counter = _nested_counter(
                getattr(summary, "sni_to_servers", {}), sni_text
            )
            rows.append(
                [
                    _truncate_text(_redact_in_text(sni_text), 56),
                    str(int(count)),
                    _top_counter_text(client_counter, 3, 24),
                    _top_counter_text(service_counter, 3, 30),
                ]
            )
        lines.append(_format_table(rows))
    else:
        lines.append(
            muted(
                "No TLS Server Name Indication (SNI) values were parsed from ClientHello messages."
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Version"))
    if summary.versions:
        total_versions = sum(int(count) for count in summary.versions.values())
        rows = [["Version", "Count", "%", "Assessment"]]
        legacy_versions = {"SSLv2", "SSLv3", "TLS1.0", "TLS1.1"}
        for version, count in summary.versions.most_common(
            _limit_value(limit if verbose else min(10, limit))
        ):
            count_int = int(count)
            pct = (count_int / max(total_versions, 1)) * 100.0
            assessment = "legacy" if str(version) in legacy_versions else "modern"
            rows.append([str(version), str(count_int), f"{pct:.1f}%", assessment])
        lines.append(_format_table(rows))
    else:
        lines.append(muted("No TLS protocol versions were parsed from this capture."))

    profile_clients = set(getattr(summary, "client_counts", {}).keys()) | set(
        getattr(summary, "client_hello_counts", {}).keys()
    )
    ranked_profile_clients = sorted(
        profile_clients,
        key=lambda client: (
            int(getattr(summary, "client_handshake_failures", {}).get(client, 0) or 0),
            int(getattr(summary, "client_missing_sni_no_ech", {}).get(client, 0) or 0),
            int(getattr(summary, "client_hello_counts", {}).get(client, 0) or 0),
            int(getattr(summary, "client_counts", {}).get(client, 0) or 0),
        ),
        reverse=True,
    )
    if ranked_profile_clients:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Client Hunt Pivots"))
        rows = [
            [
                "Client",
                "Hellos",
                "SNI",
                "JA3",
                "No SNI",
                "ECH",
                "Failed",
                "Top SNI / ALPN",
            ]
        ]
        client_cap = _limit_value(limit if verbose else min(8, limit))
        for client in ranked_profile_clients[:client_cap]:
            client_text = str(client)
            sni_counter = _nested_counter(
                getattr(summary, "client_sni_counts", {}), client_text
            )
            ja3_counter = _nested_counter(
                getattr(summary, "client_ja3_counts", {}), client_text
            )
            alpn_counter = _nested_counter(
                getattr(summary, "client_alpn_counts", {}), client_text
            )
            top_sni = _top_counter_text(sni_counter, 2, 34)
            top_alpn = _top_counter_text(alpn_counter, 2, 18)
            rows.append(
                [
                    _highlight_public_ips(client_text),
                    str(int(getattr(summary, "client_hello_counts", {}).get(client, 0) or 0)),
                    str(len(sni_counter)),
                    str(len(ja3_counter)),
                    str(
                        int(
                            getattr(summary, "client_missing_sni_no_ech", {}).get(
                                client, 0
                            )
                            or 0
                        )
                    ),
                    str(int(getattr(summary, "client_ech_counts", {}).get(client, 0) or 0)),
                    str(
                        int(
                            getattr(summary, "client_handshake_failures", {}).get(
                                client, 0
                            )
                            or 0
                        )
                    ),
                    _truncate_text(f"{top_sni} / {top_alpn}", 70),
                ]
            )
        lines.append(_format_table(rows))

    if summary.conversations:
        endpoint_clients: dict[str, set[str]] = defaultdict(set)
        endpoint_bytes: Counter[str] = Counter()
        endpoint_packets: Counter[str] = Counter()
        endpoint_hellos: Counter[str] = Counter()
        endpoint_server_ip: dict[str, str] = {}
        for conv in summary.conversations:
            endpoint = f"{conv.server_ip}:{conv.server_port}"
            endpoint_server_ip[endpoint] = str(conv.server_ip)
            endpoint_clients[endpoint].add(str(conv.client_ip))
            endpoint_bytes[endpoint] += int(conv.bytes)
            endpoint_packets[endpoint] += int(conv.packets)
            endpoint_hellos[endpoint] += int(getattr(conv, "client_hellos", 0) or 0)
        ranked_endpoints = sorted(
            endpoint_bytes.keys(),
            key=lambda endpoint: (
                int(endpoint_hellos.get(endpoint, 0)),
                int(endpoint_bytes.get(endpoint, 0)),
                int(endpoint_packets.get(endpoint, 0)),
            ),
            reverse=True,
        )
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Destination Hunt Pivots"))
        rows = [["Service", "Zone", "Clients", "Hellos", "Bytes", "Top SNI", "JA4S"]]
        endpoint_cap = _limit_value(limit if verbose else min(8, limit))
        for endpoint in ranked_endpoints[:endpoint_cap]:
            server_ip = endpoint_server_ip.get(endpoint, "")
            zone = "public" if _is_public_ip(server_ip) else "private"
            sni_counter = _nested_counter(
                getattr(summary, "server_endpoint_sni_counts", {}), endpoint
            )
            ja4s_counter = _nested_counter(
                getattr(summary, "server_endpoint_ja4s_counts", {}), endpoint
            )
            rows.append(
                [
                    _highlight_public_ips(endpoint),
                    zone,
                    str(len(endpoint_clients.get(endpoint, set()))),
                    str(int(endpoint_hellos.get(endpoint, 0))),
                    format_bytes_as_mb(int(endpoint_bytes.get(endpoint, 0))),
                    _top_counter_text(sni_counter, 2, 38),
                    _top_counter_text(ja4s_counter, 1, 32),
                ]
            )
        lines.append(_format_table(rows))

    if (
        getattr(summary, "vt_lookup_enabled", False)
        or getattr(summary, "vt_results", None)
        or getattr(summary, "vt_errors", None)
    ):
        lines.append(_format_kv("VT Lookup Enabled", "Yes" if summary.vt_lookup_enabled else "No"))
        lines.append(_format_kv("VT Enriched Domains", str(len(summary.vt_results or {}))))
        if summary.vt_results:
            lines.append(SUBSECTION_BAR)
            lines.append(header("VirusTotal Reputation"))
            rows = [["Domain", "Mal", "Susp", "Rep", "Report"]]
            ranked = sorted(
                summary.vt_results.items(),
                key=lambda item: (
                    int(item[1].get("malicious", 0) or 0),
                    int(item[1].get("suspicious", 0) or 0),
                    int(item[1].get("reputation", 0) or 0),
                ),
                reverse=True,
            )
            for domain, info in ranked[: _limit_value(15)]:
                malicious = int(info.get("malicious", 0) or 0)
                suspicious = int(info.get("suspicious", 0) or 0)
                if not verbose and malicious <= 0 and suspicious <= 0:
                    continue
                rows.append(
                    [
                        _truncate_text(str(domain), 40),
                        str(malicious),
                        str(suspicious),
                        str(info.get("reputation", "-")),
                        _truncate_text(str(info.get("report_url", "-")), 72),
                    ]
                )
            if len(rows) > 1:
                lines.append(_format_table(rows))
            else:
                lines.append(
                    muted("No malicious/suspicious VirusTotal hits in sampled domains.")
                )

    lines.append(SUBSECTION_BAR)
    lines.append(header("TLS/HTTPS Certificates Summary"))
    lines.append(_format_kv("Certificates Observed", str(summary.cert_count)))
    lines.append(_format_kv("Expired", str(summary.expired_certs)))
    lines.append(_format_kv("Self-Signed", str(summary.self_signed_certs)))
    lines.append(_format_kv("Weak Key", str(summary.weak_certs)))

    def _parse_cert_not_after(value: str) -> datetime | None:
        text = str(value or "").strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except Exception:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _cert_issue_tags(cert) -> list[str]:
        tags: list[str] = []
        if str(cert.subject or "").strip() and str(cert.subject) == str(cert.issuer):
            tags.append("self-signed")
        if int(getattr(cert, "pubkey_size", 0) or 0) and int(
            getattr(cert, "pubkey_size", 0) or 0
        ) < 2048:
            tags.append("weak-key")
        sig_blob = str(getattr(cert, "sig_algo", "") or "").lower()
        if any(marker in sig_blob for marker in ("sha1", "md5")):
            tags.append("weak-signature")
        expiry_dt = _parse_cert_not_after(str(getattr(cert, "not_after", "") or ""))
        if expiry_dt is not None:
            now = datetime.now(timezone.utc)
            if expiry_dt < now:
                tags.append("expired")
            elif (expiry_dt - now).days <= 30:
                tags.append("expiring<=30d")
        return tags

    cert_issue_totals: Counter[str] = Counter()
    cert_rows = [
        ["Certificate", "Issuer/Signer", "Expires", "Typical Issues", "Service/Flow"]
    ]
    cert_seen: set[str] = set()
    cert_items = list(getattr(summary, "cert_artifacts", []) or [])
    for cert in cert_items:
        fingerprint = str(getattr(cert, "sha256", "") or "").strip()
        if fingerprint and fingerprint in cert_seen:
            continue
        if fingerprint:
            cert_seen.add(fingerprint)
        issue_tags = _cert_issue_tags(cert)
        cert_issue_totals.update(issue_tags)
        cert_rows.append(
            [
                _truncate_text(_redact_in_text(str(getattr(cert, "subject", "-") or "-")), 36),
                _truncate_text(
                    _redact_in_text(str(getattr(cert, "issuer", "-") or "-")), 34
                ),
                str(getattr(cert, "not_after", "-") or "-"),
                ", ".join(issue_tags) if issue_tags else "none-observed",
                _truncate_text(
                    _redact_in_text(
                        str(getattr(cert, "sni", "") or getattr(cert, "src_ip", "") or "-")
                    ),
                    28,
                ),
            ]
        )
        if len(cert_rows) >= (_limit_value(8) + 1 if concise_mode else _limit_value(limit) + 1):
            break
    if len(cert_rows) > 1:
        lines.append(_format_table(cert_rows))
    else:
        lines.append(muted("No parsed certificate artifacts were captured."))

    if cert_issue_totals:
        lines.append(_format_kv("Issue Totals", _format_counter(cert_issue_totals, 6)))
    else:
        lines.append(muted("No common certificate hygiene issues identified in parsed artifacts."))

    if cert_items:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Forensic Pivots"))
        hash_width = 64 if verbose else 32
        rows = [["Service/SNI", "Serial", "SHA256", "SHA1", "Issues"]]
        seen_hashes: set[str] = set()
        cert_cap = _limit_value(limit if verbose else min(8, limit))
        for cert in cert_items:
            sha256 = str(getattr(cert, "sha256", "") or "").strip()
            if sha256 and sha256 in seen_hashes:
                continue
            if sha256:
                seen_hashes.add(sha256)
            issue_tags = _cert_issue_tags(cert)
            rows.append(
                [
                    _truncate_text(
                        _redact_in_text(
                            str(
                                getattr(cert, "sni", "")
                                or getattr(cert, "src_ip", "")
                                or "-"
                            )
                        ),
                        34,
                    ),
                    _truncate_text(str(getattr(cert, "serial", "") or "-"), 24),
                    _truncate_text(sha256 or "-", hash_width),
                    _truncate_text(str(getattr(cert, "sha1", "") or "-"), 40),
                    ", ".join(issue_tags) if issue_tags else "none-observed",
                ]
            )
            if len(rows) >= cert_cap + 1:
                break
        if len(rows) > 1:
            lines.append(_format_table(rows))

    if getattr(summary, "analysis_notes", None) and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Notes"))
        for note in summary.analysis_notes[: _limit_value(8)]:
            lines.append(muted(f"- {note}"))

    if summary.client_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Clients"))
        rows = [["Client", "SNI", "Sessions"]]
        client_sni_map = getattr(summary, "client_sni_counts", {}) or {}
        for client, count in summary.client_counts.most_common(limit):
            sni_counter = client_sni_map.get(client, Counter())
            sni_text = "-"
            if sni_counter:
                top_sni, _scount = sni_counter.most_common(1)[0]
                extra = len(sni_counter) - 1
                sni_text = f"{top_sni} (+{extra} more)" if extra > 0 else top_sni
            rows.append([client, _redact_in_text(sni_text), str(count)])
        lines.append(_format_table(rows))

    if summary.server_counts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Top Servers"))
        rows = [["Server", "SNI", "Sessions"]]
        server_sni_map = getattr(summary, "server_sni_counts", {}) or {}
        for server, count in summary.server_counts.most_common(limit):
            sni_counter = server_sni_map.get(server, Counter())
            sni_text = "-"
            if sni_counter:
                top_sni, _scount = sni_counter.most_common(1)[0]
                extra = len(sni_counter) - 1
                sni_text = f"{top_sni} (+{extra} more)" if extra > 0 else top_sni
            rows.append([server, _redact_in_text(sni_text), str(count)])
        lines.append(_format_table(rows))

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Systems Communicating Over TLS"))
        if summary.client_counts or summary.server_counts:
            lines.append(
                _format_client_server_table(summary.client_counts, summary.server_counts)
            )
        else:
            lines.append(muted("No TLS client/server pairs detected."))

    if summary.server_ports and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Service Ports"))
        port_total = sum(summary.server_ports.values())
        rows = [["Port", "Count", "% TLS"]]
        for port, count in summary.server_ports.most_common(_limit_value(limit)):
            pct = (count / max(port_total, 1)) * 100.0
            rows.append([str(port), str(count), f"{pct:.1f}%"])
        lines.append(_format_table(rows))

    if summary.conversations and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Traffic Statistics"))
        rows = [
            [
                "Client",
                "Server",
                "Port",
                "Packets",
                "Bytes",
                "CH/SH",
                "First",
                "Last",
                "SNI",
                "JA3/JA4",
                "ALPN",
            ]
        ]
        for conv in summary.conversations[: _limit_value(limit)]:
            fp_text = " / ".join(
                part
                for part in (
                    ", ".join(getattr(conv, "ja3", ())[:2]),
                    ", ".join(getattr(conv, "ja4", ())[:2]),
                )
                if part
            )
            rows.append(
                [
                    conv.client_ip,
                    conv.server_ip,
                    str(conv.server_port),
                    str(conv.packets),
                    str(conv.bytes),
                    f"{getattr(conv, 'client_hellos', 0)}/{getattr(conv, 'server_hellos', 0)}",
                    format_ts(conv.first_seen),
                    format_ts(conv.last_seen),
                    _truncate_text(_redact_in_text(conv.sni or "-"), 64),
                    _truncate_text(fp_text or "-", 60),
                    _truncate_text(", ".join(getattr(conv, "alpn", ())[:4]) or "-", 36),
                ]
            )
        lines.append(_format_table(rows))

        repeated = [conv for conv in summary.conversations if int(conv.packets) >= 20]
        if repeated:
            lines.append(muted("Repeated TLS conversations (>=20 packets):"))
            for conv in repeated[: _limit_value(10)]:
                lines.append(
                    muted(
                        f"- {conv.client_ip} -> {conv.server_ip}:{conv.server_port} packets={conv.packets} bytes={conv.bytes}"
                    )
                )

    if verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Certificate Posture"))
        lines.append(_format_kv("Certificates", str(summary.cert_count)))
        lines.append(_format_kv("Self-Signed", str(summary.self_signed_certs)))
        lines.append(_format_kv("Expired", str(summary.expired_certs)))
        lines.append(_format_kv("Weak Keys", str(summary.weak_certs)))
        if summary.cert_issuers:
            rows = [["Issuer", "Count"]]
            for issuer, count in summary.cert_issuers.most_common(_limit_value(limit)):
                rows.append([_truncate_text(_redact_in_text(issuer), 96), str(count)])
            lines.append(_format_table(rows))
        if summary.cert_artifacts:
            rows = [["Subject", "Issuer", "Not After", "Key", "SNI", "Flow"]]
            for cert in summary.cert_artifacts[: _limit_value(limit)]:
                key_text = (
                    f"{cert.pubkey_type} {cert.pubkey_size}" if cert.pubkey_type else "-"
                )
                rows.append(
                    [
                        _truncate_text(_redact_in_text(cert.subject), 40),
                        _truncate_text(_redact_in_text(cert.issuer), 34),
                        cert.not_after,
                        key_text,
                        _truncate_text(_redact_in_text(cert.sni or "-"), 28),
                        f"{cert.src_ip}->{cert.dst_ip}",
                    ]
                )
            lines.append(_format_table(rows))
    if summary.cipher_suites and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Cipher Suites"))
        rows = [["Cipher", "Count", "Class"]]
        for name, count in summary.cipher_suites.most_common(_limit_value(limit)):
            klass = "weak" if name in summary.weak_ciphers else "modern"
            rows.append([str(name), str(count), klass])
        lines.append(_format_table(rows))

    if summary.weak_ciphers and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Weak/Legacy Ciphers"))
        lines.append(_counter_table(summary.weak_ciphers, "Cipher", limit=_limit_value(limit)))

    detections = _filtered_detections(summary, verbose)
    noisy_info = {
        "ECH (Encrypted ClientHello) observed",
        "SNI hidden by ECH",
        "HTTP/2 ALPN observed",
        "HTTP/3 ALPN observed",
        "No ALPN advertised",
        "TLS handshakes without SNI",
    }
    actionable: list[dict[str, object]] = []
    for item in detections:
        summary_text = str(item.get("summary", "")).strip()
        if summary_text in noisy_info:
            continue
        actionable.append(item)

    if summary.http_requests or summary.http_responses:
        actionable.append(
            {
                "severity": "warning",
                "summary": "Plaintext HTTP also present in this capture",
                "details": (
                    f"Observed {summary.http_requests} plaintext request(s) and {summary.http_responses} response(s). "
                    "Review --http output for potential downgrade/mixed-security exposure."
                ),
            }
        )

    if actionable:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Most Likely TLS Findings"))
        if concise_mode:
            ranked: list[dict[str, object]] = []
            for item in actionable:
                sev = str(item.get("severity", "info")).lower()
                if sev in {"critical", "high", "warning"}:
                    ranked.append(item)
            actionable = ranked or actionable
        for item in actionable[: _limit_value(limit if verbose else max(5, limit // 3))]:
            severity = str(item.get("severity", "info")).lower()
            summary_text = str(item.get("summary", ""))
            details = str(item.get("details", ""))
            if severity == "critical":
                marker = danger("[CRIT]")
            elif severity == "high":
                marker = danger("[HIGH]")
            elif severity == "warning":
                marker = warn("[WARN]")
            else:
                marker = ok("[INFO]")
            lines.append(f"{marker} {summary_text}")
            if details:
                lines.append(muted(f"  {details}"))

    if summary.ja3_counts or summary.ja4_counts or summary.ja4s_counts:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Fingerprint Intelligence"))
        fp_cap = _limit_value(limit)
        if summary.ja3_counts:
            rows = [["JA3", "Count"]]
            for fp, count in summary.ja3_counts.most_common(fp_cap):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA3"))
            lines.append(_format_table(rows))
        if summary.ja4_counts:
            rows = [["JA4", "Count"]]
            for fp, count in summary.ja4_counts.most_common(fp_cap):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA4"))
            lines.append(_format_table(rows))
        if summary.ja4s_counts and verbose:
            rows = [["JA4S", "Count"]]
            for fp, count in summary.ja4s_counts.most_common(fp_cap):
                rows.append([str(fp), str(count)])
            lines.append(label("Top JA4S"))
            lines.append(_format_table(rows))

    if summary.artifacts and verbose:
        lines.append(SUBSECTION_BAR)
        lines.append(header("TLS Artifacts"))
        for item in summary.artifacts[: _limit_value(limit)]:
            lines.append(muted(f"- {_truncate_text(_redact_in_text(str(item)), 96)}"))

    lines.append(SECTION_BAR)
    return _finalize_output(lines, show_truncation_note=False)


def render_tls_summary(
    summary: TlsSummary, limit: int = 12, verbose: bool = False
) -> str:
    """Render TLS in full-detail mode by default.

    --tls is a forensic/IR surface, so its report should not require -v to show
    the deterministic checks, conversations, certificate detail, and artifacts.
    Temporarily enabling the module verbose flag preserves the existing "full"
    limit behavior for TLS without changing any other analyzer in chained runs.
    """
    del verbose
    previous_verbose_state = _verbose_output()
    if not previous_verbose_state:
        set_verbose_output(True)
    try:
        return _render_tls_summary_impl(
            summary, limit=_FULL_OUTPUT_LIMIT if limit is not None else limit, verbose=True
        )
    finally:
        if not previous_verbose_state:
            set_verbose_output(False)
