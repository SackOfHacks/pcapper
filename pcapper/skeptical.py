"""Skeptical-filter layer for pcapper detection scoring.

Applied after specialised analyzers emit detections but before they're
aggregated into the threats/compromised output. Rules downgrade or annotate
severity when the detection's own evidence strings show a well-known
false-positive shape.

Default-on; bypass with `--strict` on the CLI to see raw un-filtered verdicts.

Each rule inspects the `source`, `summary`, and `details` fields of a
detection dict and decides whether to:

  * Downgrade the severity (e.g. `high` → `warning` or `info`)
  * Attach a machine-readable rule tag (`detection['skeptical_rule']`)
  * Attach a human-readable reason (`detection['skeptical_reason']`)
  * Preserve the original severity (`detection['skeptical_original_severity']`)

Nothing is silently dropped — the reviewer always sees the finding, but
with a `[skeptical: <rule>]` marker + explanation appended by the renderer.

Rules ordered by specificity — the first matching rule wins (early return).

Extending: append a new dataclass entry to _RULES; keep rules narrow and
document the concrete FP shape they defend against.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

# A detection dict shape (documenting the fields we read; other keys pass
# through untouched):
#
#     {
#         "source":   "TCP" | "HTTP" | "TLS" | "Malware" | ...
#         "severity": "critical" | "high" | "warning" | "info"
#         "summary":  short human label, e.g. "Potential TCP SYN flood"
#         "details":  free text with evidence — SYN counts, URLs, hostnames
#         # after filter (added by apply_skeptical_filter):
#         "skeptical_downgraded":         bool
#         "skeptical_rule":               short rule id, e.g. "blocked-egress-retries"
#         "skeptical_reason":             human sentence
#         "skeptical_original_severity":  the pre-downgrade value
#     }

Detection = dict[str, Any]

# Ordered severity ladder — index used for downgrade comparisons.
_SEV_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "warning": 2,
    "info": 1,
}


def _sev_rank(s: str) -> int:
    return _SEV_ORDER.get((s or "").lower(), 0)


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SkepticalRule:
    """A single downgrade/annotate rule.

    * ``rule_id`` — short slug, appears in ``detection['skeptical_rule']``.
    * ``sources`` — analyzer sources this rule applies to (matched
      case-insensitively). Empty tuple = any source.
    * ``summary_patterns`` — regexes; at least one must match ``summary``.
    * ``details_predicate`` — callable taking the details string and
      returning True if the rule applies. Where the interesting evidence
      lives (ratios, URL patterns, host names embedded in details).
    * ``downgrade_to`` — the new severity if the rule fires. ``None`` means
      annotate-only (keep original severity, add reason tag).
    * ``reason`` — human-readable explanation appended to output.
    """

    rule_id: str
    sources: tuple[str, ...]
    summary_patterns: tuple[re.Pattern[str], ...]
    details_predicate: Callable[[str], bool]
    downgrade_to: str | None
    reason: str

    def matches(self, detection: Detection) -> bool:
        if self.sources:
            source = str(detection.get("source", "")).lower()
            if source not in {s.lower() for s in self.sources}:
                return False
        summary = str(detection.get("summary", ""))
        if not any(pat.search(summary) for pat in self.summary_patterns):
            return False
        details = str(detection.get("details", ""))
        return self.details_predicate(details)


# ---------------------------------------------------------------------------
# Helpers used by rule predicates
# ---------------------------------------------------------------------------

# Match "SYN-ACK=N (X.Y%)" tokens in TCP-module details. Captures the
# ratio percentage as a float. Multiple occurrences per detection are
# aggregated (min ratio wins for the "blocked egress" heuristic).
_TCP_ACK_RATIO_RE = re.compile(r"SYN-ACK\s*=\s*\d+\s*\((\d+(?:\.\d+)?)\s*%\)")


def _min_ack_ratio(details: str) -> float | None:
    """Return the minimum SYN-ACK response ratio (percentage) seen in
    the TCP-module evidence string, or None if no ratio is present."""
    ratios = [float(m.group(1)) for m in _TCP_ACK_RATIO_RE.finditer(details)]
    return min(ratios) if ratios else None


# Vendor-management-platform URL fragments — polling endpoints that
# generate the "Periodic HTTP check-in behavior" flag with a rock-solid
# vendor-legitimate provenance. Extend as new vendor platforms surface.
_VENDOR_POLLING_URL_RE = re.compile(
    r"(?ix)"
    r"(?:"
    r"     AosService\.svc"                # Rockwell AssetCentre
    r"  |  RockwellSoftware/AssetCentre"   # Rockwell AssetCentre absolute path
    r"  |  VpPlatformService(?:/VpWebService\.asmx)?"  # Activplant
    r"  |  Activplant/"                    # Activplant path root
    r"  |  aspenONE"                       # AspenTech aspenONE
    r"  |  aspenTech"                      # AspenTech generic
    r"  |  PIWebAPI"                       # OSIsoft/AVEVA PI Web API
    r"  |  ProficyHistorian"               # GE Proficy
    r"  |  DeltaV/"                        # Emerson DeltaV
    r"  |  FactoryTalk/?"                  # Rockwell FactoryTalk (broad)
    r"  |  studio5000"                     # Rockwell Studio 5000 mgmt
    r"  |  YokogawaVnet"                   # Yokogawa Vnet/IP mgmt
    r"  |  pfwAuthz\.aspx"                 # Rockwell FactoryTalk auth
    r"  |  ThinManager"                    # Rockwell ThinManager
    r"  |  ControlST"                      # GE Mark VIe / ControlST
    r")"
)


def _has_vendor_polling_url(details: str) -> bool:
    return bool(_VENDOR_POLLING_URL_RE.search(details))


# Well-known CDN / public-cloud IP prefixes — traffic to these blocked
# at the egress firewall commonly shows the same 0% SYN-ACK pattern as
# a SYN flood, but it's blocked-egress + client retries, not a flood.
# List is intentionally short — well-known top-tier CDNs only.
_CDN_PREFIXES: tuple[str, ...] = (
    # Cloudflare — v4 primary
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    "104.22.", "104.23.", "104.24.", "104.25.", "104.26.", "104.27.",
    "104.28.", "104.29.", "104.30.", "104.31.",
    "172.64.", "172.65.", "172.66.", "172.67.",
    "162.159.", "141.101.", "108.162.", "173.245.", "190.93.", "197.234.",
    "198.41.",
    # Akamai
    "23.11.", "23.15.", "23.32.", "23.35.", "23.43.", "23.48.", "23.53.",
    "23.55.", "23.62.", "23.65.", "23.66.", "23.67.", "23.72.", "23.79.",
    "23.192.", "23.201.", "23.203.", "23.208.", "23.209.", "23.210.",
    "23.212.", "23.213.", "23.215.", "23.216.", "23.219.",
    "184.24.", "184.25.", "184.26.", "184.27.", "184.28.", "184.29.",
    "184.50.", "184.51.",
    # Fastly
    "151.101.", "199.232.",
    # AWS CloudFront primary
    "13.32.", "13.33.", "13.35.", "13.224.", "13.225.", "13.226.", "13.227.",
    "13.249.", "52.84.", "52.85.", "52.222.", "54.192.", "54.230.", "54.239.",
    "54.240.",
    # Google — Cloud CDN / static
    "34.64.", "34.72.", "34.96.", "34.104.", "34.128.", "34.144.", "35.190.",
    "35.201.", "35.244.", "216.58.", "142.250.", "216.239.",
    # Azure Front Door / CDN
    "13.107.", "20.36.", "20.37.", "20.38.", "20.39.", "20.40.", "20.41.",
    "20.42.", "20.43.", "20.44.", "20.45.", "20.46.", "20.47.", "20.48.",
    "20.49.", "20.50.",
)

_IP_TOKEN_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _details_contains_only_cdn_destinations(details: str) -> bool:
    """True when every destination IP in the details string starts with a
    known-CDN prefix. Used to distinguish a "SYN flood to Cloudflare"
    (= blocked egress + retries) from a real SYN flood.

    Conservative — if the details string contains no destinations at all,
    or any non-CDN destination, returns False (rule does not fire; original
    severity kept)."""
    ips = _extract_destination_ips(details)
    if not ips:
        return False
    return all(any(ip.startswith(p) for p in _CDN_PREFIXES) for ip in ips)


def _is_rfc1918(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        if ip.count(".") == 3 and all(p.isdigit() for p in ip.split("."))
        else False
    )


_ARROW_DST_RE = re.compile(
    r"->\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?"
)


def _extract_destination_ips(details: str) -> list[str]:
    """Extract destination IPs from an ``A -> B[:port]`` style details string.
    Falls back to all IPs when no arrows are present (matches TCP module
    ``SYN flood`` shape which lists only destinations)."""
    dests = _ARROW_DST_RE.findall(details)
    if dests:
        return dests
    # Fall back to all IPs — details is destination-only (e.g. TCP-flood
    # module which lists ``DST:PORT SYN=N SYN-ACK=M ...``).
    return _IP_TOKEN_RE.findall(details)


def _details_all_destinations_are_public(details: str) -> bool:
    """True when every destination IP in the details string is a public
    (non-RFC1918, non-loopback, non-multicast) address. Used to identify
    "many SYNs to many public IPs, 0 response" as a blocked-egress pattern
    without requiring the destination to be in the CDN prefix allowlist.

    Requires at least 2 destination IPs (single-target high-SYN patterns
    could be a real single-target probing attempt against a specific asset)."""
    ips = _extract_destination_ips(details)
    if len(ips) < 2:
        return False
    for ip in ips:
        if ip.startswith("127.") or ip.startswith("224.") or ip == "255.255.255.255":
            return False
        if _is_rfc1918(ip):
            return False
    return True


_HTTP_HOSTS_1_RE = re.compile(r"\bhosts\s*=\s*1\b")


def _http_fanout_single_host(details: str) -> bool:
    """True when the HTTP burst/fan-out heuristic fires but the details show
    ``hosts=1`` — i.e., many URLs to a single destination host. That's
    polling to one server, not fan-out reconnaissance."""
    return bool(_HTTP_HOSTS_1_RE.search(details))


_TLS_MISSING_SNI_100PCT_RE = re.compile(
    r"missing_sni\s*=\s*(\d+)\s*/\s*(\d+)"
)


def _tls_handshake_all_missing_sni(details: str) -> bool:
    """True when every observed TLS Client Hello in the details string is
    missing an SNI extension AND the destination shape is HTTP-CONNECT-
    tunnel-through-proxy (details mentions CONNECT or a proxy port such
    as ``:80`` for TLS traffic). That's the standard blocked-outbound-
    tunnel shape."""
    all_missing = all(
        int(m.group(1)) == int(m.group(2)) and int(m.group(2)) > 0
        for m in _TLS_MISSING_SNI_100PCT_RE.finditer(details)
    )
    if not all_missing:
        return False
    return bool(re.search(r"\bCONNECT\b|:\s*80\b|proxy", details, re.I))


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

_RULES: tuple[SkepticalRule, ...] = (

    # --- TCP: SYN flood-to-CDN or 0% SYN-ACK ratio = blocked egress ------
    SkepticalRule(
        rule_id="blocked-egress-syn-flood",
        sources=("TCP",),
        summary_patterns=(re.compile(r"(?i)potential\s+tcp\s+syn\s+flood"),),
        details_predicate=lambda d: (
            # Real SYN floods produce SOME SYN-ACK from the target's TCP stack;
            # 0.0-0.4% ratio to a CDN is characteristic of dropped-at-egress.
            # (Careful: _min_ack_ratio may return exactly 0.0 which is falsy;
            #  handle the None case explicitly rather than via ``or``.)
            _details_contains_only_cdn_destinations(d)
            or (
                (_min_ack_ratio(d) is not None)
                and _min_ack_ratio(d) <= 0.4
            )
        ),
        downgrade_to="warning",
        reason=(
            "SYN-ACK response ratio is at-or-near zero across destinations "
            "that look like CDN / public-cloud endpoints. Real SYN floods "
            "elicit at least some SYN-ACK from the target's TCP stack; "
            "0% ratio is more consistent with blocked-egress + client "
            "retries than an actual flood. Verify against the firewall's "
            "egress-block log before treating as adversarial."
        ),
    ),

    # --- TCP: connection probing across multiple public IPs = blocked egress
    SkepticalRule(
        rule_id="blocked-egress-connection-probe",
        sources=("TCP",),
        summary_patterns=(
            re.compile(
                r"(?i)potential\s+tcp\s+connection\s+probing"
            ),
        ),
        # The "connection probing" detection fires when SYN-ACK ratio is
        # already <= 0.1 — so we know unanswered SYNs by construction. What
        # we're distinguishing here: is the destination shape "one specific
        # target being scanned" (real probing) or "many public IPs, all
        # unanswered" (blocked-egress + client retries against benign
        # public services)? Two-or-more public destinations tips the
        # interpretation toward blocked-egress.
        details_predicate=lambda d: (
            _details_contains_only_cdn_destinations(d)
            or _details_all_destinations_are_public(d)
        ),
        downgrade_to="warning",
        reason=(
            "The 'unanswered SYN' pattern is against multiple public IPs "
            "(non-RFC1918). Real connection probing tends to concentrate "
            "on a single target for enumeration; many public destinations "
            "with 0 SYN-ACK is more consistent with blocked-egress at the "
            "firewall + client-side retries against benign public services "
            "(CDN, SaaS, telemetry endpoints). Verify the egress firewall's "
            "block log + reputation of destinations before treating as scan."
        ),
    ),

    # --- Malware/HTTP: periodic check-in against known vendor polling URL -
    SkepticalRule(
        rule_id="likely-vendor-polling",
        sources=("Malware", "HTTP"),
        summary_patterns=(
            re.compile(r"(?i)periodic\s+http\s+check[- ]?in"),
            re.compile(r"(?i)http\s+c2\s*/?\s*beacon\s+check[- ]?in"),
        ),
        details_predicate=_has_vendor_polling_url,
        downgrade_to="info",
        reason=(
            "URL path matches a well-known OT/industrial-management vendor "
            "polling endpoint (Rockwell AssetCentre / FactoryTalk, Activplant "
            "VpPlatformService, AspenTech aspenONE, OSIsoft/AVEVA PI, GE "
            "Proficy, Emerson DeltaV, Yokogawa Vnet mgmt, etc.). Periodic "
            "POST at a fixed cadence is the vendor-legitimate polling "
            "signature, not C2. Confirm the destination host role via asset "
            "inventory before dispositioning as malicious."
        ),
    ),

    # --- HTTP: burst/fan-out reconnaissance against a single host = polling
    SkepticalRule(
        rule_id="single-host-polling-not-fanout",
        sources=("HTTP",),
        summary_patterns=(
            re.compile(r"(?i)burst[/ -]?fan[- ]?out\s+reconnaissance"),
        ),
        details_predicate=_http_fanout_single_host,
        downgrade_to="info",
        reason=(
            "The 'many URLs, many hosts' fan-out heuristic requires "
            "multiple destination hosts to distinguish reconnaissance from "
            "polling. Details show hosts=1 — every request lands on the "
            "same destination, so the pattern is polling-to-one-server, "
            "not fan-out reconnaissance."
        ),
    ),

    # --- TLS: 100% missing-SNI + CONNECT/:80 proxy = blocked outbound tunnel
    SkepticalRule(
        rule_id="blocked-outbound-tunnel",
        sources=("TLS",),
        summary_patterns=(
            re.compile(r"(?i)client[- ]specific\s+sni\s+suppression"),
            re.compile(r"(?i)tls\s+handshake\s+failures?"),
        ),
        details_predicate=_tls_handshake_all_missing_sni,
        downgrade_to="warning",
        reason=(
            "TLS Client Hellos are 100% missing SNI, with destination shape "
            "matching HTTP-CONNECT-tunnel-through-proxy (destination port "
            "80 or CONNECT keyword in details). Consistent with the client "
            "attempting a TLS tunnel that the proxy blocks / does not "
            "forward. Not an SNI-suppression evasion attempt; more likely "
            "an egress-block signal. Confirm what the intended tunnel "
            "target is via the CONNECT request-line before dispositioning."
        ),
    ),
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# Module-level default set by the CLI (`--strict` → True disables the filter).
# Read when ``apply_skeptical_filter`` is called with ``strict=None`` (the
# common case: the caller doesn't know or care whether strict mode is on).
_DEFAULT_STRICT: bool = False


def set_default_strict(strict: bool) -> None:
    """Set the module-level default strict mode. CLI calls this once at
    startup; every subsequent ``apply_skeptical_filter(...)`` call (with no
    explicit ``strict=`` argument) reads this value."""
    global _DEFAULT_STRICT
    _DEFAULT_STRICT = bool(strict)


def get_default_strict() -> bool:
    return _DEFAULT_STRICT


def apply_skeptical_filter(
    detection: Detection,
    *,
    strict: bool | None = None,
) -> Detection:
    """Return a new dict with the skeptical filter applied.

    * When ``strict=True`` the detection is returned unchanged — that's the
      escape hatch when the reviewer wants raw un-filtered verdicts.
    * When ``strict=False`` (default), rules in ``_RULES`` are evaluated in
      order; the first matching rule downgrades ``severity`` and attaches
      the ``skeptical_*`` annotation keys. If no rule matches, the
      detection is returned unchanged.
    * When ``strict=None`` (the common per-detection call site), the
      module-level default set by ``set_default_strict()`` is used —
      lets the CLI set the mode once at startup instead of threading a
      flag through every call site.

    Never mutates the input dict.
    """
    if strict is None:
        strict = _DEFAULT_STRICT
    if strict or not isinstance(detection, dict):
        return detection

    for rule in _RULES:
        if not rule.matches(detection):
            continue

        original_severity = str(detection.get("severity", "")).lower()
        target_severity = (rule.downgrade_to or original_severity).lower()

        # Never upgrade — the filter is downgrade-only.
        if _sev_rank(target_severity) >= _sev_rank(original_severity):
            target_severity = original_severity

        new = dict(detection)
        new["severity"] = target_severity
        new["skeptical_downgraded"] = target_severity != original_severity
        new["skeptical_rule"] = rule.rule_id
        new["skeptical_reason"] = rule.reason
        new["skeptical_original_severity"] = original_severity
        return new

    return detection


def apply_skeptical_filter_many(
    detections: Iterable[Detection],
    *,
    strict: bool = False,
) -> list[Detection]:
    """Vectorised convenience wrapper — apply to every detection."""
    return [apply_skeptical_filter(d, strict=strict) for d in detections]


def skeptical_rules_summary() -> Sequence[dict[str, str]]:
    """Return a list of ``{rule_id, sources, reason}`` for docs / --help /
    the ``--verdict-summary`` output. Pure introspection — no side effects."""
    return [
        {
            "rule_id": r.rule_id,
            "sources": ",".join(r.sources) or "*",
            "downgrade_to": r.downgrade_to or "(annotate only)",
            "reason": r.reason,
        }
        for r in _RULES
    ]


__all__ = [
    "SkepticalRule",
    "apply_skeptical_filter",
    "apply_skeptical_filter_many",
    "skeptical_rules_summary",
    "set_default_strict",
    "get_default_strict",
]
