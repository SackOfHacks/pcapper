"""Rendered output for SMB: who logged on to which server (account,
workstation, dialect, signing, encryption), the shares mounted (admin shares
flagged), the files and named pipes touched, and lateral-movement scoring;
server/client inventories, conversations and command counts are -v detail."""

from __future__ import annotations

from collections import Counter

from ..smb import SmbSummary
from . import _style as st
from ._common import _redact_in_text, _render_deterministic_checks
from ._kv import counter_line, findings_for
from ._remote import session_table

_SUSPICIOUS_EXT = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".scr", ".sys", ".lnk", ".zip", ".rar", ".7z")


_SPNEGO_HINTS = {"not_defined_in_rfc4178", "$not_defined_in_rfc4178", "please_ignore"}
_NAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.@$ ")


def _plausible(name: object) -> bool:
    """A user, domain or host name read from the payload rather than an
    accident of string carving: 3-64 characters from the name alphabet with
    at least two letters, and not SPNEGO's fixed "not_defined_in_RFC4178@
    please_ignore" hint."""
    text = str(name or "").strip()
    if not 3 <= len(text) <= 64 or text.lower() in _SPNEGO_HINTS:
        return False
    return all(ch in _NAME_CHARS for ch in text) and sum(ch.isalpha() for ch in text) >= 2


def _plausible_counts(counter: object) -> Counter:
    return Counter({k: v for k, v in dict(counter or {}).items() if _plausible(k)})


def _yes_no(value: object) -> str:
    return "-" if value is None else ("yes" if value else "no")


def _signing(sess: object) -> str:
    signed, unsigned = getattr(sess, "signed_packets", 0), getattr(sess, "unsigned_packets", 0)
    used = "mixed" if signed and unsigned else "yes" if signed else "no" if unsigned else "-"
    required = getattr(sess, "signing_required", None)
    text = f"{'required' if required else 'optional' if required is not None else '?'}/{used}"
    return st.caution(text) if used in ("no", "mixed") and not required else text


def _file_flags(filename: str, share: str) -> list[str]:
    flags = []
    low_name, low_share = filename.lower(), share.lower()
    if low_name.endswith(_SUSPICIOUS_EXT):
        flags.append("suspicious-ext")
    if "admin$" in low_share or "ipc$" in low_share or low_share.endswith("\\c$"):
        flags.append("admin-share")
    if "\\pipe\\" in low_name:
        flags.append("named-pipe")
    return flags


def _file_rows(summary: SmbSummary) -> list[list[object]]:
    """File operations aggregated per (file, share, client, server): the
    actions, bytes and window; unnamed operations per (action, share, flow)."""
    known: dict[tuple, dict] = {}
    unknown: dict[tuple, dict] = {}
    for item in summary.files:
        name = item.filename or ""
        is_unknown = not name or name.lower().startswith("(unknown") or name.lower() in {"-", "unknown"}
        share = item.share or "-"
        key = ((item.action or "Op"), share, item.client_ip or "-", item.server_ip or "-") if is_unknown else \
            (name, share, item.client_ip or "-", item.server_ip or "-")
        table = unknown if is_unknown else known
        entry = table.setdefault(key, {"actions": Counter(), "bytes": 0, "first": None, "last": None, "ids": set(), "n": 0})
        entry["actions"][item.action or "Op"] += 1
        entry["n"] += 1
        entry["bytes"] += int(item.size or 0)
        if item.file_id:
            entry["ids"].add(item.file_id)
        ts = item.ts or None
        if ts:
            entry["first"] = ts if entry["first"] is None else min(entry["first"], ts)
            entry["last"] = ts if entry["last"] is None else max(entry["last"], ts)
    rows = []
    verbose = st.verbose()
    for (name, share, client, server), e in sorted(known.items(), key=lambda kv: (kv[1]["bytes"], kv[1]["n"]), reverse=True):
        flags = _file_flags(name, share)
        activity = ", ".join(f"{a} ×{n}" for a, n in e["actions"].most_common())
        rows.append([st.ts(e["first"]), _redact_in_text(name), _redact_in_text(share), activity,
                     st.size(e["bytes"]) if e["bytes"] else "-", st.flow(client, server),
                     st.caution(", ".join(flags)) if flags else ""]
                    + ([st.ts(e["last"]), ", ".join(sorted(e["ids"])) or "-"] if verbose else []))
    for (action, share, client, server), e in sorted(unknown.items(), key=lambda kv: (kv[1]["bytes"], kv[1]["n"]), reverse=True):
        rows.append([st.ts(e["first"]), st.dim("(unnamed)"), _redact_in_text(share), f"{action} ×{e['n']}",
                     st.size(e["bytes"]) if e["bytes"] else "-", st.flow(client, server), ""]
                    + ([st.ts(e["last"]), ", ".join(sorted(e["ids"])) or "-"] if verbose else []))
    return rows


def render_smb_summary(summary: SmbSummary, verbose: bool = False) -> str:
    rep = st.Report("SMB", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.smb_packets and not st.material(findings):
        return rep.absent("SMB traffic", summary.errors)
    severity, text = st.verdict(findings, high="high-severity SMB activity (lateral movement, remote execution): investigate",
                                medium="SMB activity to review")
    signed, unsigned = getattr(summary, "signed_packets", 0), getattr(summary, "unsigned_packets", 0)
    rep.headline(severity, text, st.join([
        f"{st.count(summary.smb_packets)} SMB packets",
        ", ".join((st.bad(f"{k} ({v})") if k == "SMB1" else f"{k} ({v})") for k, v in summary.versions.items()),
        f"{signed} signed / {unsigned} unsigned" if (signed or unsigned) else "",
        f"{summary.encrypted_packets} encrypted" if getattr(summary, "encrypted_packets", 0) else "",
    ]))
    rep.scope(st.join([f"{st.plural(len(summary.clients), 'client')} -> {st.plural(len(summary.servers), 'server')}",
                       st.plural(len(summary.sessions), "session"),
                       "port " + ", ".join(str(p) for p, _ in summary.smb_ports.most_common(3)) if getattr(summary, "smb_ports", None) else ""]))
    if summary.versions.get("SMB1"):
        rep.note("SMBv1", f"{summary.versions['SMB1']} packets of legacy SMBv1 (EternalBlue-class exposure)")
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    # A session without its own account (NTLM AUTHENTICATE) inherits the
    # client's when the client only ever showed one plausible name; domains
    # and workstations carved from strings are not inherited.
    one_user = {c.ip: next(iter(c.usernames)) for c in summary.clients
                if len(c.usernames) == 1 and _plausible(next(iter(c.usernames)))}

    def _account(sess: object) -> str:
        user = sess.username or one_user.get(sess.client_ip) or ""
        domain = sess.domain or ""
        if not user:
            return "-"
        text = f"{domain}\\{user}" if domain else str(user)
        return _redact_in_text(text) + (st.caution(" (guest)") if getattr(sess, "is_guest", False) else "")

    verbose_view = st.verbose()
    session_rows = []
    for sess in sorted(summary.sessions, key=lambda s: s.start_ts or 0.0):
        dur = max(0.0, sess.last_seen - sess.start_ts) if sess.start_ts and sess.last_seen else None
        session_rows.append(
            [st.ts(sess.start_ts or None), st.flow(sess.client_ip, sess.server_ip), _account(sess),
             _redact_in_text(str(sess.workstation or "-")), sess.auth_type or "-",
             sess.smb_version or "-", _signing(sess), "yes" if getattr(sess, "encrypted", False) else "no"]
            + ([sess.session_id if sess.session_id is not None else "-", _yes_no(sess.encryption_required),
                st.count(sess.packets), st.size(sess.bytes) if sess.bytes else "-", st.ts(sess.last_seen or None),
                st.duration(dur) if dur is not None else "-"] if verbose_view else []))
    rep.section("Sessions", st.table(
        ["Start", "Flow", "Account", "Workstation", "Auth", "Dialect", "Signing req/used", "Encrypted"]
        + (["Session ID", "Encrypt req", "Packets", "Bytes", "Last seen", "Duration"] if verbose_view else []),
        session_rows, max_rows=10, noun="session",
    ))
    rep.section("Shares", st.table(
        ["Server", "Share", "Connects", "Type"],
        [[s.server_ip, _redact_in_text(str(s.name)), st.count(s.connect_count), st.caution("admin") if s.is_admin else "normal"]
         for s in sorted(summary.shares, key=lambda s: (not s.is_admin, -s.connect_count))],
        align="llrl", max_rows=12, noun="share",
    ))
    rep.section("Files", st.table(
        ["First seen", "File", "Share", "Activity", "Bytes", "Flow", "Flags"] + (["Last seen", "File IDs"] if verbose_view else []),
        _file_rows(summary), align="llllrll", widths=(None, 60, 30, 40), max_rows=12, noun="file",
    ))
    artifacts = [str(a) for a in (summary.artifacts or [])]
    pipes = [a for a in artifacts if "\\pipe\\" in a.lower()]
    rep.section("Named pipes", st.bullets([_redact_in_text(p) for p in pipes], max_items=10, noun="pipe"))
    lateral = sorted(summary.lateral_movement or [], key=lambda x: x.get("score", 0), reverse=True)
    rep.section("Lateral movement", st.table(
        ["Client", "Servers", "Admin shares", "Failures", "Score"],
        [[i.get("client", "-"), i.get("servers", "-"), i.get("admin_shares", "-"), i.get("failures", "-"), i.get("score", "-")]
         for i in lateral], align="lrrrr", max_rows=5, noun="client",
    ))
    # Names from the NTLM AUTHENTICATE messages, plus carved names that look
    # like names; the raw carved lists are in the -v client inventory.
    hosts: Counter[str] = Counter(str(s.workstation) for s in summary.sessions if getattr(s, "workstation", None))
    rep.section("Accounts", st.kv([
        ("Users", st.top(_plausible_counts(summary.observed_users), 10,
                         fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        ("Domains", st.top(_plausible_counts(summary.observed_domains), 6,
                           fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
        ("Workstations", st.top(hosts, 8, fmt=lambda k, v: f"{_redact_in_text(str(k))} ({st.count(v)})")),
    ]))
    rep.section("Protocol", st.kv([counter_line("Status codes", summary.error_codes, 6),
                                   counter_line("Commands", summary.commands, 8)]))

    # ---- reference (-v) --------------------------------------------------
    cmds = sorted(set(summary.requests) | set(summary.responses),
                  key=lambda c: (-(summary.requests.get(c, 0) + summary.responses.get(c, 0)), str(c)))
    rep.section("Requests and responses", st.table(
        ["Command", "Requests", "Responses"],
        [[c, st.count(summary.requests.get(c, 0)), st.count(summary.responses.get(c, 0))] for c in cmds],
        align="lrr", max_rows=None,
    ), detail=True)
    rep.section("Conversations", session_table(summary.conversations, [
        ("Requests", lambda c: getattr(c, "requests", 0)), ("Responses", lambda c: getattr(c, "responses", 0))], max_rows=None),
        detail=True)
    rep.section("Servers", st.table(
        ["Server", "Dialects", "Signing required", "Shares", "Capabilities"],
        [[s.ip, ", ".join(sorted(s.dialects)) or "-", _yes_no(s.signing_required),
          ", ".join(_redact_in_text(str(x)) for x in sorted(s.shares)) or "-", ", ".join(sorted(s.capabilities)) or "-"]
         for s in summary.servers], max_rows=None,
    ), detail=True)
    rep.section("Clients", st.table(
        ["Client", "Dialects", "Client GUID", "Users", "Domains"],
        [[c.ip, ", ".join(sorted(c.dialects)) or "-", c.client_guid or "-",
          ", ".join(_redact_in_text(str(u)) for u in sorted(c.usernames)) or "-",
          ", ".join(_redact_in_text(str(d)) for d in sorted(c.domains)) or "-"] for c in summary.clients],
        max_rows=None,
    ), detail=True)
    rep.section("Carved names", st.kv([
        counter_line("Users", summary.observed_users, None),
        counter_line("Domains", summary.observed_domains, None),
        ("Workstations", ", ".join(sorted({str(w) for c in summary.clients for w in (getattr(c, "workstations", None) or [])}))),
    ]), detail=True)
    candidates = {c.ip: sorted(getattr(c, "workstation_candidates", None) or []) for c in summary.clients}
    rep.section("Workstation candidates", st.table(
        ["Client", "Candidates"], [[ip, ", ".join(_redact_in_text(x) for x in v)] for ip, v in sorted(candidates.items()) if v],
        max_rows=None,
    ), detail=True)
    rep.section("Other artifacts", st.bullets([_redact_in_text(a) for a in artifacts if a not in pipes], max_items=None),
                detail=True)
    rep.section("Notes", st.bullets(getattr(summary, "analysis_notes", None) or [], max_items=None), detail=True)
    hyp = [f"[{h.get('confidence', '?')}] {h.get('hypothesis', '-')} (evidence={h.get('evidence', '')})"
           for h in (getattr(summary, "threat_hypotheses", None) or [])]
    rep.section("Threat hypotheses", st.bullets(hyp, max_items=None), detail=True)
    rep.section("Benign context", st.bullets(getattr(summary, "benign_context", None) or [], max_items=None), detail=True)
    rep.section("Traffic", st.kv([
        ("Packets", f"{summary.total_packets} total · {summary.smb_packets} SMB"),
        counter_line("Ports", getattr(summary, "smb_ports", None), None),
        counter_line("Top clients", summary.top_clients, None),
        counter_line("Top servers", summary.top_servers, None),
    ]), detail=True)

    if st.analysis_sections():
        legacy: list[str] = []
        _render_deterministic_checks(legacy, summary, "Deterministic SMB Security Checks", [
            ("smb_legacy_protocol", "Legacy SMB Protocol (SMBv1)"),
            ("smb_signing_or_encryption_gap", "Signing/Encryption Gap"),
            ("smb_auth_failure_burst", "Auth Failure Burst"),
            ("smb_admin_share_lateral", "Admin-Share Lateral Movement"),
            ("smb_sensitive_file_staging", "Sensitive File Staging"),
            ("smb_scanning_fanout", "Scanning Fan-out"),
            ("smb_beacon_or_periodicity", "Beacon/Periodicity"),
            ("smb_public_endpoint_exposure", "Public Endpoint Exposure"),
        ])
        rep.section("Deterministic checks", legacy[2:])
    return rep.render()
