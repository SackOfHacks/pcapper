"""Rendered output for SSH. The handshake (banners, KEXINIT, host key) is
cleartext and fingerprints both ends (software, HASSH, host key); user-auth
and channel data are encrypted, so login outcomes are inferred."""

from __future__ import annotations

from ..ssh import SshSummary
from . import _style as st
from ._remote import counts, remote_report


def _strip_msg(counter: object) -> str:
    return st.top(counter, None, fmt=lambda k, v: f"{str(k).replace('SSH_MSG_', '')} ({v})") if counter else ""


def render_ssh_summary(summary: SshSummary, limit: int = 12, verbose: bool = False) -> str:
    if not summary:
        return ""
    inference = sorted(getattr(summary, "auth_inference", None) or [],
                       key=lambda r: (int(r.get("likely_failed", 0)), int(r.get("sessions", 0))), reverse=True)

    def _assess(text: object) -> str:
        value = str(text or "-")
        return st.bad(value) if "brute" in value.lower() else value

    auth = st.table(
        ["Client", "Server", "Sessions", "Likely fail", "Likely OK", "Client software", "Assessment"],
        [[r.get("client", "-"), f"{r.get('server', '-')}:{r.get('port', '-')}", st.count(r.get("sessions", 0)),
          st.count(r.get("likely_failed", 0)), st.count(r.get("likely_success", 0)), r.get("client_software", "-"),
          _assess(r.get("verdict"))] for r in inference],
        align="llrrrll", widths=(None, None, None, None, None, 32),
    )
    if auth:
        auth.append(st.dim("  inferred from post-handshake volume: sessions ending right after key exchange are likely failed logins"))
    fails, oks = summary.auth_failures_by_client, summary.auth_successes_by_client
    outcomes = st.table(
        ["Client", "Failures", "Successes"],
        [[ip, st.count(fails.get(ip, 0)), st.count(oks.get(ip, 0))]
         for ip in sorted(set(fails) | set(oks), key=lambda ip: (-fails.get(ip, 0), ip))],
        align="lrr", noun="client", max_rows=st.TOP_ROWS, tail=st.TOP_ROWS,
    )
    hassh = [["client", h, st.count(n), summary.client_hassh_strings.get(h, "")] for h, n in summary.client_hassh.most_common()]
    hassh += [["server", h, st.count(n), summary.server_hassh_strings.get(h, "")] for h, n in summary.server_hassh.most_common()]
    fingerprints = st.table(["Role", "HASSH", "Count"] + (["KEX string"] if st.verbose() else []),
                            [row if st.verbose() else row[:3] for row in hassh], align="llrl", max_rows=None)
    fingerprints += st.kv([("Host keys", st.top(summary.host_key_fingerprints, 4)),
                           ("Key types", st.top(summary.host_key_types, 4))])
    return remote_report(
        "SSH", summary,
        packets=summary.ssh_packets,
        high="high-severity SSH activity: investigate",
        medium="SSH activity to review",
        ports=[("tcp", summary.server_ports)],
        sections=[
            ("Authentication", auth + ([""] if auth and outcomes else []) + outcomes + st.kv([
                ("Users (decrypted)", st.top(getattr(summary, "auth_usernames", None), 8)),
                ("Methods", st.top(summary.auth_methods, 6)),
            ]), False),
            ("Software", st.kv([
                ("Clients", st.top(summary.client_software, 6)),
                ("Servers", st.top(summary.server_software, 6)),
                ("Devices", st.top(getattr(summary, "device_fingerprints", None), 4)),
            ]), False),
            ("Fingerprints", fingerprints, False),
            ("Disconnect reasons", counts(summary.disconnect_reasons, "Reason"), False),
            ("Suspicious strings", counts(summary.suspicious_plaintext, "String", width=100), False),
            ("Banners", st.kv([("Clients", st.top(summary.client_versions, None)),
                               ("Servers", st.top(summary.server_versions, None))]), True),
            ("Crypto negotiation", st.kv([
                ("KEX", st.top(summary.kex_algorithms, None)), ("Host key", st.top(summary.host_key_algorithms, None)),
                ("Cipher", st.top(summary.cipher_algorithms, None)), ("MAC", st.top(summary.mac_algorithms, None)),
                ("Compression", st.top(summary.compression_algorithms, None)),
            ]), True),
            ("Messages", st.kv([("Requests", _strip_msg(summary.request_counts)),
                                ("Responses", _strip_msg(summary.response_counts))]), True),
        ],
        files_default=False,  # names carved from encrypted payload are mostly noise
        session_cols=([("Auth fail/OK", lambda c: f"{c.auth_failures}/{c.auth_successes}")]
                      if any(c.auth_failures or c.auth_successes for c in summary.conversations) else []),
        plaintext_title="Plaintext (pre-encryption)",
        notes=list(getattr(summary, "analysis_notes", None) or []),
    )
