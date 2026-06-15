"""Shared TLS fingerprint helpers (JA3 / JA4 / JA4S) and hello parsing.

Single source of truth for the fingerprint construction used by tls.py and
ips.py. Implements:

- JA3 (Salesforce): MD5 over
  "SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
  using decimal values dash-joined within fields, in ClientHello order, with
  GREASE values removed. JA3 deliberately uses the hello's legacy version
  field, NOT the supported_versions extension.
- JA4 / JA4S (FoxIO, spec v1): see _ja4_from_client_hello /
  _ja4s_from_server_hello docstrings for the exact layout.

GREASE (RFC 8701) values are 0x0a0a, 0x1a1a, ... 0xfafa — both bytes equal,
low nibble 0xA.
"""

from __future__ import annotations

import hashlib
from typing import Optional

SUPPORTED_VERSIONS_EXT_TYPE = 43
SIGNATURE_ALGORITHMS_EXT_TYPE = 13
SNI_EXT_TYPE = 0x0000
ALPN_EXT_TYPE = 0x0010

# JA4 two-character TLS version codes (from the resolved, real version).
_JA4_VERSION_CODES = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0200: "s2",
    0x0002: "s2",
    0xFEFF: "d1",
    0xFEFD: "d2",
    0xFEFC: "d3",
}


def _is_grease(value: int) -> bool:
    # RFC 8701: 0x0a0a, 0x1a1a, ..., 0xfafa — both bytes identical and the
    # low nibble 0xA. (A looser mask like (value & 0x0f0f) == 0x0a0a also
    # strips non-GREASE values such as 0x1a2a and corrupts fingerprints.)
    return (value & 0xFF) == ((value >> 8) & 0xFF) and (value & 0x0F) == 0x0A


def _coerce_int_list(values: object) -> list[int]:
    if values is None:
        return []
    if isinstance(values, (list, tuple, set)):
        out = []
        for item in values:
            try:
                out.append(int(item))
            except Exception:
                continue
        return out
    try:
        return [int(values)]
    except Exception:
        return []


def _iter_tls_extensions(hello: object) -> list[object]:
    exts = getattr(hello, "ext", None)
    if exts is None:
        exts = getattr(hello, "extensions", None)
    if exts is None:
        return []
    try:
        return list(exts)
    except Exception:
        return []


def _tls_extension_type(ext: object) -> Optional[int]:
    for attr in ("type", "ext_type", "etype", "extension_type"):
        value = getattr(ext, attr, None)
        if value is not None:
            try:
                return int(value)
            except Exception:
                continue
    return None


def _extract_sni(ext: object) -> Optional[str]:
    name = ext.__class__.__name__
    if "ServerName" not in name and "SNI" not in name:
        return None
    for attr in ("servernames", "server_names", "server_name", "names"):
        names = getattr(ext, attr, None)
        if names:
            try:
                if isinstance(names, (list, tuple)):
                    first = names[0]
                else:
                    first = names
                candidate = (
                    getattr(first, "servername", None)
                    or getattr(first, "name", None)
                    or first
                )
                if isinstance(candidate, bytes):
                    return candidate.decode("utf-8", errors="ignore").strip(".")
                return str(candidate).strip(".")
            except Exception:
                return None
    return None


def _extract_alpn(ext: object) -> list[str]:
    name = ext.__class__.__name__
    if "ALPN" not in name and "ApplicationLayerProtocol" not in name:
        return []
    for attr in ("protocols", "alpn_protocols"):
        protocols = getattr(ext, attr, None)
        if protocols:
            out: list[str] = []
            for proto in protocols:
                # scapy wraps each name in a ProtocolName whose value is the
                # `protocol` byte field; str(proto) would yield the class
                # name ("ProtocolName"), so read the field explicitly first.
                value = getattr(proto, "protocol", proto)
                if isinstance(value, bytes):
                    out.append(value.decode("utf-8", errors="ignore"))
                elif isinstance(value, str):
                    out.append(value)
                else:
                    out.append(str(value))
            return out
    return []


def _resolve_negotiated_version(hello: object, fallback: object) -> Optional[int]:
    """Return the real TLS version for a hello message.

    TLS 1.3 (RFC 8446) hardcodes the hello's version field (legacy_version)
    to 0x0303 for middlebox compatibility; the real offered/selected version
    lives in the supported_versions extension (type 43). For a ClientHello
    the extension lists every offered version (highest wins); for a
    ServerHello it holds the single selected version.
    """
    candidates: list[int] = []
    for ext in _iter_tls_extensions(hello):
        if _tls_extension_type(ext) != SUPPORTED_VERSIONS_EXT_TYPE:
            continue
        values: list[int] = []
        for attr in ("versions", "version"):
            values = _coerce_int_list(getattr(ext, attr, None))
            if values:
                break
        candidates.extend(v for v in values if not _is_grease(v))
    if candidates:
        tls_versions = [v for v in candidates if v < 0xFE00]
        if tls_versions:
            return max(tls_versions)
        # DTLS version numbers decrease as the protocol gets newer.
        return min(candidates)
    try:
        return int(fallback)  # type: ignore[arg-type]
    except Exception:
        return None


def _client_hello_ciphers(client_hello: object) -> list[int]:
    ciphers: list[int] = []
    for attr in ("ciphers", "cipher_suites", "ciphersuites"):
        ciphers = _coerce_int_list(getattr(client_hello, attr, None))
        if ciphers:
            break
    return [c for c in ciphers if not _is_grease(c)]


def _hello_extension_types(hello: object) -> list[int]:
    ext_types: list[int] = []
    for ext in _iter_tls_extensions(hello):
        ext_type = _tls_extension_type(ext)
        if ext_type is not None and not _is_grease(ext_type):
            ext_types.append(ext_type)
    return ext_types


def _signature_algorithms(hello: object) -> list[int]:
    for ext in _iter_tls_extensions(hello):
        if _tls_extension_type(ext) != SIGNATURE_ALGORITHMS_EXT_TYPE:
            continue
        for attr in ("sig_algs", "sig_algorithms", "algorithms"):
            values = _coerce_int_list(getattr(ext, attr, None))
            if values:
                return [v for v in values if not _is_grease(v)]
    return []


def _ja3_from_client_hello(client_hello: object) -> Optional[str]:
    version = getattr(client_hello, "version", None)
    if version is None:
        return None
    try:
        version_val = int(version)
    except Exception:
        return None

    ciphers = _client_hello_ciphers(client_hello)

    exts = _iter_tls_extensions(client_hello)
    ext_types = []
    curves = []
    ec_points = []
    for ext in exts:
        ext_type = _tls_extension_type(ext)
        if ext_type is not None and not _is_grease(ext_type):
            ext_types.append(ext_type)

        for attr in ("groups", "supported_groups", "elliptic_curves"):
            groups = _coerce_int_list(getattr(ext, attr, None))
            if groups:
                curves.extend(groups)
                break

        for attr in ("ecpl", "ec_point_formats", "formats", "ec_points"):
            points = _coerce_int_list(getattr(ext, attr, None))
            if points:
                ec_points.extend(points)
                break

    curves = [c for c in curves if not _is_grease(c)]
    ec_points = [p for p in ec_points if not _is_grease(p)]

    def _join(values: list[int]) -> str:
        return "-".join(str(v) for v in values)

    return (
        f"{version_val},{_join(ciphers)},{_join(ext_types)},"
        f"{_join(curves)},{_join(ec_points)}"
    )


def _ja4_version_code(version_val: Optional[int]) -> str:
    if version_val is None:
        return "00"
    return _JA4_VERSION_CODES.get(version_val, "00")


def _ja4_alpn_token(alpn: list[str]) -> str:
    if not alpn:
        return "00"
    value = str(alpn[0] or "")
    if not value:
        return "00"
    first, last = value[0], value[-1]
    if first.isalnum() and last.isalnum():
        return f"{first}{last}"
    # Non-printable ALPN values use the first and last characters of the
    # hex encoding per the JA4 spec.
    hex_value = value.encode("utf-8", errors="ignore").hex() or "00"
    return f"{hex_value[0]}{hex_value[-1]}"


def _sha256_12(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _ja4_from_client_hello(
    client_hello: object, sni: Optional[str], alpn: list[str]
) -> Optional[str]:
    """JA4 client fingerprint (FoxIO spec).

    JA4_a: t + version(2) + d/i (SNI present/absent) + cipher count(2) +
           extension count(2) + ALPN first/last char.
    JA4_b: sha256[:12] of the SORTED cipher list, comma-joined 4-hex values.
    JA4_c: sha256[:12] of the SORTED extension list (excluding SNI 0x0000 and
           ALPN 0x0010), comma-joined 4-hex values, then "_" + the
           signature_algorithms values in ORIGINAL order if present.
    Empty cipher/extension lists hash to twelve zeros.
    """
    version = getattr(client_hello, "version", None)
    if version is None:
        return None
    resolved = _resolve_negotiated_version(client_hello, version)

    ciphers = _client_hello_ciphers(client_hello)
    ext_types = _hello_extension_types(client_hello)
    sig_algs = _signature_algorithms(client_hello)

    cipher_count = min(len(ciphers), 99)
    ext_count = min(len(ext_types), 99)
    sni_flag = "d" if sni else "i"
    ja4_a = (
        f"t{_ja4_version_code(resolved)}{sni_flag}"
        f"{cipher_count:02d}{ext_count:02d}{_ja4_alpn_token(alpn)}"
    )

    if ciphers:
        ja4_b = _sha256_12(",".join(f"{c:04x}" for c in sorted(ciphers)))
    else:
        ja4_b = "0" * 12

    hash_exts = sorted(
        t for t in ext_types if t not in (SNI_EXT_TYPE, ALPN_EXT_TYPE)
    )
    if hash_exts:
        ext_str = ",".join(f"{t:04x}" for t in hash_exts)
        if sig_algs:
            ext_str += "_" + ",".join(f"{s:04x}" for s in sig_algs)
        ja4_c = _sha256_12(ext_str)
    else:
        ja4_c = "0" * 12

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def _ja4s_from_server_hello(
    server_hello: object, alpn: list[str] | None = None
) -> Optional[str]:
    """JA4S server fingerprint (FoxIO spec).

    JA4S_a: t + version(2) + extension count(2) + ALPN first/last char.
    JA4S_b: the chosen cipher suite as a 4-hex value.
    JA4S_c: sha256[:12] of the extension list in ORIGINAL order,
            comma-joined 4-hex values (twelve zeros when empty).
    """
    version = getattr(server_hello, "version", None)
    if version is None:
        return None
    resolved = _resolve_negotiated_version(server_hello, version)

    cipher = getattr(server_hello, "cipher", None)
    try:
        cipher_val = int(cipher) if cipher is not None else 0
    except Exception:
        cipher_val = 0

    ext_types = _hello_extension_types(server_hello)
    ext_count = min(len(ext_types), 99)
    alpn_token = _ja4_alpn_token(alpn or [])

    ja4s_a = f"t{_ja4_version_code(resolved)}{ext_count:02d}{alpn_token}"
    ja4s_b = f"{cipher_val:04x}"
    if ext_types:
        ja4s_c = _sha256_12(",".join(f"{t:04x}" for t in ext_types))
    else:
        ja4s_c = "0" * 12
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"


# Curated known-malicious / offensive-tool JA3 fingerprints for hunting.
#
# Sources:
#  - abuse.ch SSLBL JA3 fingerprint blocklist (https://sslbl.abuse.ch/ja3-fingerprints/)
#    — malware-family-specific, the higher-confidence entries below.
#  - Salesforce JA3 research / public C2 research for offensive-tooling sockets.
#
# CAVEAT (intentional confidence tiering): a JA3 is a hash of the ClientHello
# shape, so it collides across any client sharing that TLS stack. The Windows
# WinHTTP/schannel sockets used by Cobalt Strike / Meterpreter beacons are the
# SAME ones legitimate Windows apps use, so those are marked "low" confidence
# (corroborate, do not alert on alone). Malware-family fingerprints from SSLBL
# are "medium". Nothing here is "definitive" — JA3 is a corroborating signal.
_JA3_INTEL: dict[str, tuple[str, str]] = {
    # --- abuse.ch SSLBL malware-family fingerprints (medium confidence) ---
    "b386946a5a44d1ddcc843bc75336dfce": ("Dridex / Dyre", "medium"),
    "cb98a24ee4b9134448ffb5714fd870ac": ("Dridex", "medium"),
    "d6f04b5a910115f4b50ecec09d40a1df": ("Dridex", "medium"),
    "1aa7bf8b97e540ca5edd75f7b8384bfa": ("TrickBot", "medium"),
    "8f52d1ce303fb4a6515836aec3cc16b1": ("TrickBot", "medium"),
    "c50f6a8b9173676b47ba6085bd0c6cee": ("TrickBot", "medium"),
    "35c0a31c481927f022a3b530255ac080": ("Tofsee", "medium"),
    "70722097d1fe1d78d8c2164640ab6df4": ("Tofsee", "medium"),
    "4d7a28d6f2263ed61de88ca66eb011e3": ("Tofsee", "medium"),
    "590a232d04d56409fab72e752a8a2634": ("Tofsee", "medium"),
    "96eba628dcb2b47607192ba74a3b55ba": ("Tofsee", "medium"),
    "df5c30e670dba99f9270ed36060cf054": ("Tofsee", "medium"),
    "d7150af4514b868defb854db0f62a441": ("Tofsee", "medium"),
    "03e186a7f83285e93341de478334006e": ("Tofsee", "medium"),
    "3cda52da4ade09f1f781ad2e82dcfa20": ("Qakbot", "medium"),
    "51a7ad14509fd614c7bb3a50c4982b8c": ("JBifrost RAT", "medium"),
    # --- offensive-tooling sockets (low confidence: collide with benign apps) ---
    "5d65ea3fb1d4aa7d826733d2f2cbbb1d": ("Metasploit Meterpreter (Linux)", "low"),
    "72a589da586844d7f0818ce684948eea": (
        "Cobalt Strike / Meterpreter beacon (Win socket; also benign Windows apps)",
        "low",
    ),
    "a0e9f5d64349fb13191bc781f81f42e1": (
        "Cobalt Strike / Meterpreter beacon (Win socket; also benign Windows apps)",
        "low",
    ),
}


def lookup_ja3_intel(ja3_hash: str) -> Optional[tuple[str, str]]:
    """Return (label, confidence) if a JA3 hash matches curated threat intel."""
    if not ja3_hash:
        return None
    return _JA3_INTEL.get(ja3_hash.strip().lower())
