"""Rendered output for creds analysis.

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
from ..creds import CredentialSummary

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _finalize_output,
    _format_kv,
    _format_table,
    _limit_value,
    _render_deterministic_checks,
    _truncate_text,
)


def render_creds_summary(summary: CredentialSummary) -> str:
    lines: list[str] = []
    lines.append(SECTION_BAR)
    lines.append(header(f"CREDENTIAL EXPOSURE :: {summary.path.name}"))
    lines.append(SECTION_BAR)

    if summary.errors:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Errors"))
        for err in summary.errors:
            lines.append(danger(f"- {err}"))

    def _display_secret(value: str | None) -> str:
        if value is None:
            return "-"
        return value

    def _format_packets(packet_values: set[int]) -> str:
        if not packet_values:
            return "-"
        ordered = sorted(packet_values)
        slice_limit = _limit_value(8)
        shown = ordered[:slice_limit]
        text = ", ".join(str(v) for v in shown)
        if len(ordered) > len(shown):
            return f"{text} (+{len(ordered) - len(shown)})"
        return text

    def _format_protocols(protocol_counts: Counter[str]) -> str:
        if not protocol_counts:
            return "-"
        parts = [
            f"{name}({count})"
            for name, count in protocol_counts.most_common(_limit_value(5))
        ]
        remaining = len(protocol_counts) - len(parts)
        if remaining > 0:
            parts.append(f"+{remaining}")
        return ", ".join(parts)

    ot_protocol_tokens = {
        "ethernet/ip",
        "enip",
        "cip",
        "modbus",
        "dnp3",
        "iec-104",
        "iec104",
        "profinet",
        "s7",
        "bacnet",
        "opc ua",
        "opc-ua",
        "mms",
        "srtp",
        "fins",
        "ethercat",
        "hart",
        "iccp",
        "pcworx",
        "melsec",
        "codesys",
        "niagara",
        "proconos",
        "pccc",
        "modicon",
        "yokogawa",
        "honeywell",
        "goose",
    }
    it_protocol_tokens = {
        "http",
        "ftp",
        "smtp",
        "pop3",
        "imap",
        "telnet",
        "ssh",
        "ldap",
        "kerberos",
        "ntlm",
        "smb",
        "rdp",
        "winrm",
        "rpc",
        "nfs",
        "dns",
        "dhcp",
        "snmp",
        "tls",
        "quic",
        "mqtt",
        "coap",
        "syslog",
        "netbios",
        "vnc",
    }
    family_rank = {"OT": 0, "IT": 1, "Mixed": 2, "Other": 3}

    def _protocol_family(protocol_name: str) -> str:
        text = protocol_name.lower()
        if any(token in text for token in ot_protocol_tokens):
            return "OT"
        if any(token in text for token in it_protocol_tokens):
            return "IT"
        return "Other"

    def _entry_family(protocol_counts: Counter[str]) -> str:
        ot_hits = 0
        it_hits = 0
        for proto, count in protocol_counts.items():
            family = _protocol_family(str(proto))
            if family == "OT":
                ot_hits += int(count)
            elif family == "IT":
                it_hits += int(count)
        if ot_hits and it_hits:
            return "Mixed"
        if ot_hits:
            return "OT"
        if it_hits:
            return "IT"
        return "Other"

    username_groups: dict[str, dict[str, object]] = {}
    secret_groups: dict[str, dict[str, object]] = {}
    pair_groups: dict[tuple[str, str], dict[str, object]] = {}
    protocol_totals: Counter[str] = Counter()

    # Offline-crackable authentication hashes (NetNTLMv1/v2, Kerberos pre-auth)
    # are pulled into their own section — they are not cleartext and the long
    # hash string would otherwise flood the Discovered Secrets table.
    crackable_hashes: list[dict[str, object]] = []
    for hit in summary.hits:
        protocol = str(hit.protocol or "-")
        packet_num = int(hit.packet_number)
        user = str(hit.username or "").strip()
        secret = str(hit.secret or "").strip()
        evidence = str(hit.evidence or "")
        kind = str(hit.kind or "")
        if "hashcat -m" in evidence or kind.endswith("Hash"):
            mode = ""
            if "hashcat -m" in evidence:
                mode = evidence.split("hashcat -m", 1)[1].strip().split()[0]
            crackable_hashes.append(
                {
                    "account": user or "-",
                    "type": kind,
                    "mode": mode,
                    "hash": secret,
                    "pkt": packet_num,
                }
            )
            protocol_totals[protocol] += 1
            continue

        protocol_totals[protocol] += 1

        if user:
            user_entry = username_groups.setdefault(
                user,
                {"hits": 0, "protocols": Counter(), "packets": set()},
            )
            user_entry["hits"] = int(user_entry["hits"]) + 1
            cast_protocols = user_entry["protocols"]
            if isinstance(cast_protocols, Counter):
                cast_protocols[protocol] += 1
            cast_packets = user_entry["packets"]
            if isinstance(cast_packets, set):
                cast_packets.add(packet_num)

        if secret:
            secret_entry = secret_groups.setdefault(
                secret,
                {"hits": 0, "protocols": Counter(), "packets": set()},
            )
            secret_entry["hits"] = int(secret_entry["hits"]) + 1
            cast_protocols = secret_entry["protocols"]
            if isinstance(cast_protocols, Counter):
                cast_protocols[protocol] += 1
            cast_packets = secret_entry["packets"]
            if isinstance(cast_packets, set):
                cast_packets.add(packet_num)

        if user and secret:
            pair_key = (user, secret)
            pair_entry = pair_groups.setdefault(
                pair_key,
                {"hits": 0, "protocols": Counter(), "packets": set()},
            )
            pair_entry["hits"] = int(pair_entry["hits"]) + 1
            cast_protocols = pair_entry["protocols"]
            if isinstance(cast_protocols, Counter):
                cast_protocols[protocol] += 1
            cast_packets = pair_entry["packets"]
            if isinstance(cast_packets, set):
                cast_packets.add(packet_num)

    lines.append(_format_kv("Packets Scanned", str(summary.total_packets)))
    lines.append(_format_kv("Credential Hits", str(summary.matches)))

    # ---- Analyst Verdict -------------------------------------------------
    # Lead with the triage call derived from the computed risk dimensions, in
    # descending order of severity. This is the line an IR analyst reads first.
    ext = list(summary.external_exposures or [])
    priv = list(summary.privileged_exposures or [])
    abuse = list(summary.auth_abuse_sequences or [])
    replay = list(summary.replay_candidates or [])
    fanout = list(summary.token_fanout or [])
    benign = list(
        (summary.deterministic_checks or {}).get("likely_benign_test_credentials", [])
    )
    reasons: list[str] = []
    if ext:
        reasons.append(
            f"{len(ext)} credential(s) sent to a PUBLIC internet destination"
        )
    if priv:
        priv_users = sorted({str(p.get("user", "-")) for p in priv})
        reasons.append(
            f"privileged account(s) exposed (cleartext or captured hash): "
            f"{', '.join(priv_users[:6])}"
        )
    if abuse:
        pats = sorted(
            {str(p) for seq in abuse for p in (seq.get("patterns") or [])}
        )
        reasons.append(
            f"active credential attack ({', '.join(pats) or 'auth abuse'}) from "
            f"{len(abuse)} source(s)"
        )
    if replay:
        reasons.append(
            f"credential reuse across multiple hosts ({len(replay)} value(s))"
        )
    if fanout:
        reasons.append(f"token reused across multiple destinations ({len(fanout)})")
    if crackable_hashes:
        hash_accounts = sorted(
            {str(h.get("account", "-")) for h in crackable_hashes if h.get("account")}
        )
        reasons.append(
            f"{len(crackable_hashes)} offline-crackable authentication hash(es) "
            f"captured for: {', '.join(hash_accounts[:6])}"
        )

    # Distinguish a real cleartext exposure from only-hashes-captured: cleartext
    # secrets (non-hash hits) mean immediate compromise; hashes are crackable but
    # not yet plaintext.
    has_cleartext = summary.matches > len(crackable_hashes)
    if ext or priv:
        verdict_text, verdict_fn = "CREDENTIAL COMPROMISE — IMMEDIATE ACTION", danger
    elif abuse:
        verdict_text, verdict_fn = "ACTIVE CREDENTIAL ATTACK", danger
    elif replay or fanout:
        verdict_text, verdict_fn = "CREDENTIAL REUSE / TOKEN MISUSE", warn
    elif has_cleartext:
        verdict_text, verdict_fn = "CLEARTEXT CREDENTIALS EXPOSED", warn
    elif crackable_hashes:
        verdict_text, verdict_fn = "CAPTURED AUTH HASHES (offline-crackable)", warn
    else:
        verdict_text, verdict_fn = "NO CLEARTEXT CREDENTIALS DETECTED", ok

    lines.append(SUBSECTION_BAR)
    lines.append(header("Analyst Verdict"))
    lines.append(verdict_fn(f"[VERDICT] {verdict_text}"))
    for reason in reasons:
        lines.append(warn(f"- {reason}"))
    if not reasons and summary.matches > 0:
        lines.append(
            muted(
                "Cleartext credential material is present but no high-risk pattern "
                "(external exposure, privileged account, brute-force, reuse) fired."
            )
        )
    if benign and summary.matches > 0:
        lines.append(
            muted(
                f"Note: {len(benign)} hit(s) use known placeholder/test secrets "
                "(e.g. password/admin/test) — likely benign."
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Summary"))
    lines.append(_format_kv("Unique Usernames", str(len(username_groups))))
    lines.append(_format_kv("Unique Secrets/Tokens", str(len(secret_groups))))
    lines.append(_format_kv("Unique Username+Secret Pairs", str(len(pair_groups))))
    lines.append(_format_kv("Protocols with Hits", str(len(protocol_totals))))
    conf = summary.confidence_counts or Counter()
    if conf:
        lines.append(
            _format_kv(
                "Hit Confidence",
                f"high={int(conf.get('high', 0))} "
                f"medium={int(conf.get('medium', 0))} "
                f"low={int(conf.get('low', 0))}",
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Protocol Coverage"))
    if not protocol_totals:
        lines.append(
            muted(
                "No credential material detected across supported IT/OT protocol decoders."
            )
        )
    else:
        protocol_rows = [["Family", "Protocol", "Hits"]]
        sorted_protocols = sorted(
            protocol_totals.items(),
            key=lambda item: (
                family_rank.get(_protocol_family(str(item[0])), 99),
                -int(item[1]),
                str(item[0]).lower(),
            ),
        )
        for proto, count in sorted_protocols[: _limit_value(24)]:
            protocol_rows.append([_protocol_family(str(proto)), str(proto), str(count)])
        lines.append(_format_table(protocol_rows))

    # ---- High-risk exposures --------------------------------------------
    if ext:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credentials Sent to Public Internet"))
        lines.append(
            danger(
                "Cleartext credentials were transmitted to a routable internet "
                "destination — treat as exposed and rotate."
            )
        )
        ext_rows = [["Source", "Public Dst", "Account", "Kind", "Pkt"]]
        for item in ext[: _limit_value(20)]:
            ext_rows.append(
                [
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("user", "-")),
                    str(item.get("kind", "-")),
                    str(item.get("pkt", "-")),
                ]
            )
        lines.append(_format_table(ext_rows))

    if priv:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Privileged Account Exposure"))
        lines.append(
            danger(
                "Administrative/privileged account credentials observed "
                "(root/admin/sa/etc.) — cleartext or captured authentication hash."
            )
        )
        priv_rows = [["Account", "Source", "Destination", "Kind", "Pkt"]]
        for item in priv[: _limit_value(20)]:
            priv_rows.append(
                [
                    str(item.get("user", "-")),
                    str(item.get("src", "-")),
                    str(item.get("dst", "-")),
                    str(item.get("kind", "-")),
                    str(item.get("pkt", "-")),
                ]
            )
        lines.append(_format_table(priv_rows))

    # ---- Suspicious authentication activity -----------------------------
    if abuse:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Suspicious Authentication Activity"))
        abuse_rows = [
            ["Source", "Pattern", "Attempts", "Accounts", "Passwords", "Targets"]
        ]
        for seq in abuse[: _limit_value(20)]:
            abuse_rows.append(
                [
                    str(seq.get("src", "-")),
                    ", ".join(str(p) for p in (seq.get("patterns") or [])) or "-",
                    str(seq.get("events", "-")),
                    str(seq.get("users", "-")),
                    str(seq.get("secrets", "-")),
                    str(seq.get("dsts", "-")),
                ]
            )
        lines.append(_format_table(abuse_rows))
        for seq in abuse[: _limit_value(20)]:
            lines.append(
                warn(
                    f"- {seq.get('src', '-')}: {seq.get('events', 0)} attempts vs "
                    f"account '{seq.get('sample_user', '-')}' / target "
                    f"{seq.get('sample_dst', '-')} "
                    f"({seq.get('secrets', 0)} distinct passwords)"
                )
            )

    if replay:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Credential Reuse Across Hosts"))
        lines.append(
            warn(
                "The same credential/secret authenticated to 3+ distinct "
                "destinations — possible lateral movement or shared-secret reuse."
            )
        )
        replay_rows = [["Type", "Value", "Dst Count", "Destinations"]]
        for item in replay[: _limit_value(20)]:
            replay_rows.append(
                [
                    str(item.get("type", "-")),
                    str(item.get("value", "-")),
                    str(item.get("dst_count", "-")),
                    ", ".join(str(d) for d in (item.get("dsts") or [])),
                ]
            )
        lines.append(_format_table(replay_rows))

    if fanout:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Token Reuse / Fan-out"))
        fan_rows = [["Token (truncated)", "Dst Count", "Destinations"]]
        for item in fanout[: _limit_value(20)]:
            fan_rows.append(
                [
                    str(item.get("token", "-")),
                    str(item.get("dst_count", "-")),
                    ", ".join(str(d) for d in (item.get("dsts") or [])),
                ]
            )
        lines.append(_format_table(fan_rows))

    # ---- Crackable hashes (offline) -------------------------------------
    if crackable_hashes:
        lines.append(SUBSECTION_BAR)
        lines.append(header("Crackable Hashes (offline)"))
        lines.append(
            warn(
                "Captured authentication hashes — recover the plaintext offline "
                "(e.g. `hashcat -m <mode> <hash> wordlist`) or relay them."
            )
        )
        hash_rows = [["Account", "Type", "hashcat -m", "Pkt", "Hash"]]
        for h in crackable_hashes[: _limit_value(20)]:
            hash_rows.append(
                [
                    str(h.get("account", "-")),
                    str(h.get("type", "-")),
                    str(h.get("mode", "-")) or "-",
                    str(h.get("pkt", "-")),
                    _truncate_text(str(h.get("hash", "")), 56),
                ]
            )
        lines.append(_format_table(hash_rows))
        lines.append(
            muted(
                "Full hashes are in the hit list (use -v); each line is ready for "
                "hashcat/john."
            )
        )

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Usernames"))
    if not username_groups:
        lines.append(muted("No usernames discovered."))
    else:
        user_rows = [["Family", "Username", "Protocols", "Packets", "Hits"]]
        sorted_users = sorted(
            username_groups.items(),
            key=lambda pair: (
                family_rank.get(
                    _entry_family(
                        pair[1].get("protocols", Counter())
                        if isinstance(pair[1].get("protocols", Counter()), Counter)
                        else Counter()
                    ),
                    99,
                ),
                -int(pair[1].get("hits", 0)),
                pair[0].lower(),
            ),
        )
        for username, item in sorted_users[: _limit_value(80)]:
            protocols = item.get("protocols", Counter())
            packets = item.get("packets", set())
            user_rows.append(
                [
                    _entry_family(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    username,
                    _format_protocols(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    _format_packets(packets if isinstance(packets, set) else set()),
                    str(item.get("hits", 0)),
                ]
            )
        lines.append(_format_table(user_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Secrets/Tokens"))
    if not secret_groups:
        lines.append(muted("No secrets or tokens discovered."))
    else:
        secret_rows = [["Family", "Secret/Token", "Protocols", "Packets", "Hits"]]
        sorted_secrets = sorted(
            secret_groups.items(),
            key=lambda pair: (
                family_rank.get(
                    _entry_family(
                        pair[1].get("protocols", Counter())
                        if isinstance(pair[1].get("protocols", Counter()), Counter)
                        else Counter()
                    ),
                    99,
                ),
                -int(pair[1].get("hits", 0)),
                pair[0].lower(),
            ),
        )
        for secret, item in sorted_secrets[: _limit_value(80)]:
            protocols = item.get("protocols", Counter())
            packets = item.get("packets", set())
            secret_rows.append(
                [
                    _entry_family(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    _display_secret(secret),
                    _format_protocols(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    _format_packets(packets if isinstance(packets, set) else set()),
                    str(item.get("hits", 0)),
                ]
            )
        lines.append(_format_table(secret_rows))

    lines.append(SUBSECTION_BAR)
    lines.append(header("Discovered Username + Secret Pairs"))
    if not pair_groups:
        lines.append(muted("No correlated username+secret pairs discovered."))
    else:
        pair_rows = [
            ["Family", "Username", "Secret/Token", "Protocols", "Packets", "Hits"]
        ]
        sorted_pairs = sorted(
            pair_groups.items(),
            key=lambda pair: (
                family_rank.get(
                    _entry_family(
                        pair[1].get("protocols", Counter())
                        if isinstance(pair[1].get("protocols", Counter()), Counter)
                        else Counter()
                    ),
                    99,
                ),
                -int(pair[1].get("hits", 0)),
                pair[0][0].lower(),
                pair[0][1].lower(),
            ),
        )
        for (username, secret), item in sorted_pairs[: _limit_value(80)]:
            protocols = item.get("protocols", Counter())
            packets = item.get("packets", set())
            pair_rows.append(
                [
                    _entry_family(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    username,
                    _display_secret(secret),
                    _format_protocols(
                        protocols if isinstance(protocols, Counter) else Counter()
                    ),
                    _format_packets(packets if isinstance(packets, set) else set()),
                    str(item.get("hits", 0)),
                ]
            )
        lines.append(_format_table(pair_rows))

    _render_deterministic_checks(
        lines,
        summary,
        "Deterministic Credential Security Checks",
        [
            ("plaintext_credential_exposure", "Cleartext Credential Exposure"),
            ("crackable_hash_capture", "Crackable Authentication Hash Captured"),
            ("external_destination_exposure", "Credentials to Public Internet"),
            ("privileged_account_exposure", "Privileged Account Exposure"),
            ("auth_abuse_pattern", "Brute-force / Password-spray Pattern"),
            ("credential_replay", "Credential Reuse Across Hosts"),
            ("token_misuse_fanout", "Token Reuse / Fan-out"),
            ("likely_benign_test_credentials", "Likely Benign Test Credentials"),
        ],
    )

    if summary.truncated:
        lines.append(
            warn(
                f"[WARN] Detection stage truncated and returned first {len(summary.hits)} matches."
            )
        )

    lines.append(SECTION_BAR)
    return _finalize_output(lines)
