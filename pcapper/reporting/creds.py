"""Rendered output for creds analysis.

Split out of the former 30,000-line ``reporting.py``; the code is
verbatim, only its location changed.
"""

from __future__ import annotations

from collections import Counter

from ..creds import CredentialSummary
from ..utils import output_redaction_enabled
from . import _style as st
from ._common import (
    _redact_in_text,
    _render_deterministic_checks,
)
from ._kv import counter_line

_OT_TOKENS = {"ethernet/ip", "enip", "cip", "modbus", "dnp3", "iec-104", "iec104", "profinet", "s7", "bacnet", "opc ua", "opc-ua",
              "mms", "srtp", "fins", "ethercat", "hart", "iccp", "pcworx", "melsec", "codesys", "niagara", "proconos", "pccc",
              "modicon", "yokogawa", "honeywell", "goose"}
_IT_TOKENS = {"http", "ftp", "smtp", "pop3", "imap", "telnet", "ssh", "ldap", "kerberos", "ntlm", "smb", "rdp", "winrm", "rpc",
              "nfs", "dns", "dhcp", "snmp", "tls", "quic", "mqtt", "coap", "syslog", "netbios", "vnc"}
_FAMILY_RANK = {"OT": 0, "IT": 1, "Mixed": 2, "Other": 3}


def _protocol_family(name: str) -> str:
    text = name.lower()
    if any(t in text for t in _OT_TOKENS):
        return "OT"
    if any(t in text for t in _IT_TOKENS):
        return "IT"
    return "Other"


def _entry_family(protocols: Counter) -> str:
    families = {_protocol_family(str(p)) for p in protocols}
    if "OT" in families and "IT" in families:
        return "Mixed"
    return "OT" if "OT" in families else "IT" if "IT" in families else "Other"


def _secret(value: object) -> str:
    if value is None or value == "":
        return "-"
    return "[REDACTED]" if output_redaction_enabled() else str(value)


def _packets(values: set) -> str:
    ordered = sorted(values)
    if not ordered:
        return "-"
    if st.verbose() or len(ordered) <= 6:
        return ", ".join(str(v) for v in ordered)
    return ", ".join(str(v) for v in ordered[:6]) + st.dim(f", +{len(ordered) - 6}")


def render_creds_summary(summary: CredentialSummary) -> str:
    """Credentials on the wire: compromise first (sent to the internet,
    privileged accounts, brute force and reuse), then every username/secret
    pair with the protocols and packets that carried it, and offline-
    crackable hashes; the raw hit list and counters are -v."""
    rep = st.Report("Credentials", summary.path)
    groups: dict[str, dict] = {"user": {}, "secret": {}, "pair": {}}
    hashes: list[dict[str, object]] = []
    protocols: Counter[str] = Counter()
    for hit in summary.hits:
        proto = str(hit.protocol or "-")
        protocols[proto] += 1
        user, secret = str(hit.username or "").strip(), str(hit.secret or "").strip()
        evidence, kind = str(hit.evidence or ""), str(hit.kind or "")
        if "hashcat -m" in evidence or kind.endswith("Hash"):
            mode = evidence.split("hashcat -m", 1)[1].strip().split()[0] if "hashcat -m" in evidence else ""
            hashes.append({"account": user or "-", "type": kind, "mode": mode, "hash": secret, "pkt": int(hit.packet_number)})
            continue
        for key, value in (("user", user), ("secret", secret), ("pair", (user, secret) if user and secret else None)):
            if not value:
                continue
            entry = groups[key].setdefault(value, {"hits": 0, "protocols": Counter(), "packets": set()})
            entry["hits"] += 1
            entry["protocols"][proto] += 1
            entry["packets"].add(int(hit.packet_number))

    ext = list(summary.external_exposures or [])
    priv = list(summary.privileged_exposures or [])
    abuse = list(summary.auth_abuse_sequences or [])
    replay = list(summary.replay_candidates or [])
    fanout = list(summary.token_fanout or [])
    benign = list((summary.deterministic_checks or {}).get("likely_benign_test_credentials", []) or [])
    reasons = []
    if ext:
        reasons.append(f"{len(ext)} credential(s) sent to a public internet destination")
    if priv:
        reasons.append("privileged accounts exposed: " + ", ".join(sorted({str(p.get("user", "-")) for p in priv})[:6]))
    if abuse:
        patterns = sorted({str(p) for seq in abuse for p in (seq.get("patterns") or [])})
        reasons.append(f"active credential attack ({', '.join(patterns) or 'auth abuse'}) from {len(abuse)} source(s)")
    if replay:
        reasons.append(f"credential reuse across hosts ({len(replay)} value(s))")
    if fanout:
        reasons.append(f"token reused across destinations ({len(fanout)})")
    if hashes:
        reasons.append(f"{len(hashes)} offline-crackable hash(es) for " + ", ".join(sorted({str(h['account']) for h in hashes})[:6]))
    cleartext = summary.matches > len(hashes)
    if ext or priv:
        severity, text = "critical", "credential compromise: rotate the exposed accounts now"
    elif abuse:
        severity, text = "high", "active credential attack"
    elif replay or fanout:
        severity, text = "medium", "credential reuse / token misuse"
    elif cleartext:
        severity, text = "medium", "cleartext credentials exposed"
    elif hashes:
        severity, text = "medium", "authentication hashes captured (offline-crackable)"
    else:
        severity, text = None, "no cleartext credentials"
    rep.headline(severity, text, st.join([st.plural(summary.matches, "credential hit"), f"{st.count(summary.total_packets)} packets scanned"]))
    for reason in reasons:
        rep.scope(reason)
    if benign and summary.matches:
        rep.note("NOTE", f"{len(benign)} hit(s) use placeholder/test secrets (password, admin, test): likely benign")
    if summary.truncated:
        rep.note("CAPPED", f"detection kept the first {len(summary.hits)} matches")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])

    rep.section("Sent to the internet", st.table(
        ["Source", "Public destination", "Account", "Kind", "Packet"],
        [[i.get("src", "-"), st.bad(str(i.get("dst", "-"))), i.get("user", "-"), i.get("kind", "-"), i.get("pkt", "-")] for i in ext],
        max_rows=20, noun="credential",
    ))
    rep.section("Privileged accounts", st.table(
        ["Account", "Source", "Destination", "Kind", "Packet"],
        [[st.bad(str(i.get("user", "-"))), i.get("src", "-"), i.get("dst", "-"), i.get("kind", "-"), i.get("pkt", "-")] for i in priv],
        max_rows=20, noun="account",
    ))
    rep.section("Credential attacks", st.table(
        ["Source", "Pattern", "Attempts", "Accounts", "Passwords", "Targets", "Example"],
        [[s.get("src", "-"), ", ".join(str(p) for p in (s.get("patterns") or [])) or "-", s.get("events", "-"), s.get("users", "-"),
          s.get("secrets", "-"), s.get("dsts", "-"), f"{s.get('sample_user', '-')} -> {s.get('sample_dst', '-')}"] for s in abuse],
        align="llrrrrl", max_rows=20, noun="source",
    ))
    rep.section("Reuse", st.table(
        ["Type", "Value", "Destinations", "Hosts"],
        [[i.get("type", "-"), _secret(i.get("value")) if str(i.get("type", "")).lower() != "username" else i.get("value", "-"),
          i.get("dst_count", "-"), ", ".join(str(d) for d in (i.get("dsts") or []))] for i in replay]
        + [["token", i.get("token", "-"), i.get("dst_count", "-"), ", ".join(str(d) for d in (i.get("dsts") or []))] for i in fanout],
        align="llrl", max_rows=20, noun="value",
    ))

    def _sorted(table: dict) -> list:
        return sorted(table.items(), key=lambda kv: (_FAMILY_RANK.get(_entry_family(kv[1]["protocols"]), 9), -kv[1]["hits"], str(kv[0]).lower()))

    rep.section("Credentials", st.table(
        ["Username", "Secret", "Family", "Protocols", "Packets", "Hits"],
        [[u, _secret(sec), _entry_family(e["protocols"]), st.top(e["protocols"], 4), _packets(e["packets"]), st.count(e["hits"])]
         for (u, sec), e in _sorted(groups["pair"])],
        align="lllllr", widths=(40, 48), max_rows=25, noun="pair",
    ))
    paired_users = {u for u, _ in groups["pair"]}
    paired_secrets = {sec for _, sec in groups["pair"]}
    lone_secrets = [(k, e) for k, e in _sorted(groups["secret"]) if k not in paired_secrets]
    rep.section("Secrets without a username", st.table(
        ["Secret / token", "Family", "Protocols", "Packets", "Hits"],
        [[_secret(k), _entry_family(e["protocols"]), st.top(e["protocols"], 4), _packets(e["packets"]), st.count(e["hits"])] for k, e in lone_secrets],
        align="llllr", widths=(64,), max_rows=10, noun="secret",
    ))
    lone_users = Counter({k: e["hits"] for k, e in groups["user"].items() if k not in paired_users})
    rep.section("Usernames without a secret", st.kv([("Users", st.top(lone_users, 15))]))
    rep.section("Crackable hashes", st.table(
        ["Account", "Type", "hashcat -m", "Packet", "Hash"],
        [[h["account"], h["type"], h["mode"] or "-", h["pkt"], h["hash"]] for h in hashes],
        align="lllrl", widths=(None, None, None, None, 72), max_rows=20, noun="hash",
    ) + ([st.dim("  full hashes with -v; each line is ready for hashcat/john")] if hashes and not st.verbose() else []))
    families: dict[str, Counter] = {}
    for proto, n in protocols.items():
        families.setdefault(_protocol_family(proto), Counter())[proto] += n
    rep.section("Protocols", st.kv([(fam, st.top(families[fam], 8)) for fam in sorted(families, key=lambda f: _FAMILY_RANK.get(f, 9))]))

    rep.section("Hits", st.table(
        ["Packet", "Time", "Flow", "Protocol", "Kind", "Username", "Secret", "Evidence"],
        [[h.packet_number, st.ts(h.ts), f"{h.src_ip}:{h.src_port} -> {h.dst_ip}:{h.dst_port}", h.protocol, h.kind, h.username or "-",
          _secret(h.secret), _redact_in_text(str(h.evidence or "-"))] for h in summary.hits],
        align="rlllllll", max_rows=None, noun="hit",
    ), detail=True)
    conf = summary.confidence_counts or Counter()
    rep.section("Counts", st.kv([
        ("Unique usernames / secrets / pairs", f"{len(groups['user'])} / {len(groups['secret'])} / {len(groups['pair'])}"),
        ("Protocols with hits", str(len(protocols))),
        ("Hit confidence", f"high {int(conf.get('high', 0))} · medium {int(conf.get('medium', 0))} · low {int(conf.get('low', 0))}" if conf else ""),
        counter_line("Kinds", getattr(summary, "kind_counts", None), None),
        counter_line("Users", getattr(summary, "user_counts", None), None),
    ]), detail=True)
    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic Credential Security Checks", [
            ("plaintext_credential_exposure", "Cleartext Credential Exposure"),
            ("crackable_hash_capture", "Crackable Authentication Hash Captured"),
            ("external_destination_exposure", "Credentials to Public Internet"),
            ("privileged_account_exposure", "Privileged Account Exposure"),
            ("auth_abuse_pattern", "Brute-force / Password-spray Pattern"),
            ("credential_replay", "Credential Reuse Across Hosts"),
            ("token_misuse_fanout", "Token Reuse / Fan-out"),
            ("likely_benign_test_credentials", "Likely Benign Test Credentials"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
