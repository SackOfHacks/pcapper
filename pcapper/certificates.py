from __future__ import annotations

from collections import Counter
import logging
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import ipaddress

from .pcap_cache import get_reader
from .utils import detect_file_type, safe_float

try:
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
    from scapy.config import conf  # type: ignore
    from scapy import error as scapy_error  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore
    conf = None  # type: ignore
    scapy_error = None  # type: ignore

try:
    from scapy.layers.tls.handshake import TLSCertificate  # type: ignore
    from scapy.layers.tls.record import TLS  # type: ignore
except Exception:  # pragma: no cover
    TLSCertificate = None  # type: ignore
    TLS = None  # type: ignore

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
except Exception:  # pragma: no cover
    x509 = None  # type: ignore
    default_backend = None  # type: ignore
    hashes = None  # type: ignore


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    not_before: str
    not_after: str
    sig_algo: str
    pubkey_type: str
    pubkey_size: int
    san: str
    sha1: str
    sha256: str
    src_ip: str
    dst_ip: str
    sni: Optional[str]


@dataclass(frozen=True)
class CertificateSummary:
    path: Path
    total_packets: int
    tls_packets: int
    cert_count: int
    subjects: Counter[str]
    issuers: Counter[str]
    sas: Counter[str]
    weak_keys: list[dict[str, object]]
    expired: list[dict[str, object]]
    self_signed: list[dict[str, object]]
    artifacts: list[CertificateInfo]
    weak_signatures: list[dict[str, object]] = field(default_factory=list)
    eku_mismatches: list[dict[str, object]] = field(default_factory=list)
    key_usage_issues: list[dict[str, object]] = field(default_factory=list)
    name_mismatches: list[dict[str, object]] = field(default_factory=list)
    validity_outliers: list[dict[str, object]] = field(default_factory=list)
    serial_reuse: list[dict[str, object]] = field(default_factory=list)
    fingerprint_reuse: list[dict[str, object]] = field(default_factory=list)
    issuer_impersonation: list[dict[str, object]] = field(default_factory=list)
    revocation_gaps: list[dict[str, object]] = field(default_factory=list)
    chain_gaps: list[dict[str, object]] = field(default_factory=list)
    endpoint_profiles: list[dict[str, object]] = field(default_factory=list)
    timeline: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def analyze_certificates(path: Path, show_status: bool = True) -> CertificateSummary:
    errors: list[str] = []
    warnings.filterwarnings("ignore", message=r".*Unknown cipher suite.*")
    warnings.filterwarnings("ignore", message=r".*serial number which wasn't positive.*")
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.layers.tls").setLevel(logging.ERROR)
    prev_verb = None
    prev_warning = None
    if conf is not None:
        try:
            prev_verb = conf.verb
            conf.verb = 0
        except Exception:
            prev_verb = None
    if scapy_error is not None:
        try:
            prev_warning = scapy_error.warning
            def _silent_warning(msg, *args, **kwargs):
                if "Unknown cipher suite" in str(msg):
                    return
                if prev_warning is not None:
                    return prev_warning(msg, *args, **kwargs)
            scapy_error.warning = _silent_warning  # type: ignore[assignment]
        except Exception:
            prev_warning = None
    if x509 is None or default_backend is None:
        errors.append("TLS certificate parsing unavailable (install scapy[tls] and cryptography).")
        return CertificateSummary(
            path=path,
            total_packets=0,
            tls_packets=0,
            cert_count=0,
            subjects=Counter(),
            issuers=Counter(),
            sas=Counter(),
            weak_keys=[],
            expired=[],
            self_signed=[],
            artifacts=[],
            weak_signatures=[],
            eku_mismatches=[],
            key_usage_issues=[],
            name_mismatches=[],
            validity_outliers=[],
            serial_reuse=[],
            fingerprint_reuse=[],
            issuer_impersonation=[],
            revocation_gaps=[],
            chain_gaps=[],
            endpoint_profiles=[],
            timeline=[],
            errors=errors,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )

    total_packets = 0
    tls_packets = 0
    subjects = Counter()
    issuers = Counter()
    sas = Counter()
    artifacts: list[CertificateInfo] = []
    weak_keys: list[dict[str, object]] = []
    expired: list[dict[str, object]] = []
    self_signed: list[dict[str, object]] = []
    seen_fingerprints: set[str] = set()
    fingerprint_contexts: dict[str, set[str]] = {}
    serial_contexts: dict[str, set[str]] = {}
    tls_buffers: dict[tuple[str, str, int, int], bytearray] = {}
    weak_signatures: list[dict[str, object]] = []
    eku_mismatches: list[dict[str, object]] = []
    key_usage_issues: list[dict[str, object]] = []
    name_mismatches: list[dict[str, object]] = []
    validity_outliers: list[dict[str, object]] = []
    issuer_impersonation: list[dict[str, object]] = []
    revocation_gaps: list[dict[str, object]] = []
    chain_gaps: list[dict[str, object]] = []
    timeline: list[dict[str, object]] = []

    now_utc = datetime.now(timezone.utc)
    suspicious_tlds = (".ru", ".cn", ".top", ".xyz", ".gq", ".tk", ".ml", ".ga")
    brand_markers = ("microsoft", "google", "apple", "amazon", "paypal", "okta", "github", "adobe")

    def _collect_cert_items(payload: object) -> list[object]:
        if payload is None:
            return []
        for attr in ("certs", "certificates", "certs_data", "cert", "certificate"):
            value = getattr(payload, attr, None)
            if value:
                if isinstance(value, (list, tuple)):
                    return list(value)
                return [value]
        if isinstance(payload, (bytes, bytearray)):
            return [payload]
        return []

    def _extract_der_cert(raw: bytes) -> Optional[bytes]:
        if not raw or len(raw) < 4 or raw[0] != 0x30:
            return None
        length_byte = raw[1]
        if length_byte < 0x80:
            total_len = 2 + length_byte
            if total_len <= len(raw):
                return raw[:total_len]
            return None
        num_len_bytes = length_byte & 0x7F
        if num_len_bytes == 0 or len(raw) < 2 + num_len_bytes:
            return None
        length_val = int.from_bytes(raw[2:2 + num_len_bytes], "big")
        total_len = 2 + num_len_bytes + length_val
        if total_len <= len(raw):
            return raw[:total_len]
        return None

    def _parse_tls_from_buffer(buffer: bytearray) -> tuple[list[bytes], int]:
        certs: list[bytes] = []
        idx = 0
        while idx + 5 <= len(buffer):
            content_type = buffer[idx]
            if content_type not in (20, 21, 22, 23):
                idx += 1
                continue
            version = buffer[idx + 1:idx + 3]
            if not version or version[0] != 0x03:
                idx += 1
                continue
            length = int.from_bytes(buffer[idx + 3:idx + 5], "big")
            if length <= 0:
                idx += 1
                continue
            if idx + 5 + length > len(buffer):
                break
            record = buffer[idx + 5:idx + 5 + length]
            if content_type == 22:
                hidx = 0
                while hidx + 4 <= len(record):
                    htype = record[hidx]
                    hlen = int.from_bytes(record[hidx + 1:hidx + 4], "big")
                    if hidx + 4 + hlen > len(record):
                        break
                    body = record[hidx + 4:hidx + 4 + hlen]
                    if htype == 11 and len(body) >= 3:
                        list_len = int.from_bytes(body[0:3], "big")
                        pos = 3
                        while pos + 3 <= len(body) and (pos - 3) < list_len:
                            clen = int.from_bytes(body[pos:pos + 3], "big")
                            pos += 3
                            if pos + clen > len(body):
                                break
                            certs.append(bytes(body[pos:pos + clen]))
                            pos += clen
                    hidx += 4 + hlen
            idx += 5 + length
        return certs, idx

    def _handle_cert_bytes(raw_cert: bytes, src_ip: str, dst_ip: str) -> None:
        der_cert = _extract_der_cert(raw_cert)
        if der_cert is None:
            return
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception as exc:
            exc_text = str(exc)
            lower = exc_text.lower()
            if "asn1" in lower and (
                "shortdata" in lower
                or "unexpectedtag" in lower
                or "invalidvalue" in lower
                or "invalidlength" in lower
                or "utctime" in lower
                or "extradata" in lower
            ):
                return
            errors.append(exc_text)
            return

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        serial = hex(cert.serial_number)
        if hasattr(cert, "not_valid_before_utc"):
            not_before = cert.not_valid_before_utc.isoformat()  # type: ignore[attr-defined]
        else:
            not_before = cert.not_valid_before.isoformat()
        if hasattr(cert, "not_valid_after_utc"):
            not_after = cert.not_valid_after_utc.isoformat()  # type: ignore[attr-defined]
        else:
            not_after = cert.not_valid_after.isoformat()
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        pubkey = cert.public_key()
        pubkey_type = pubkey.__class__.__name__
        pubkey_size = getattr(pubkey, "key_size", 0) or 0
        san_list = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_list = san.value.get_values_for_type(x509.DNSName)
        except Exception:
            san_list = []
        san_text = ", ".join(san_list) if san_list else "-"

        sha1 = cert.fingerprint(hashes.SHA1()).hex() if hashes else "-"
        sha256 = cert.fingerprint(hashes.SHA256()).hex() if hashes else "-"
        context_key = f"{src_ip}->{dst_ip}"
        serial_contexts.setdefault(serial, set()).add(context_key)
        fingerprint_contexts.setdefault(sha256, set()).add(context_key)
        if sha256 in seen_fingerprints:
            timeline.append({
                "event": "cert_reuse",
                "subject": subject,
                "issuer": issuer,
                "sha256": sha256,
                "src": src_ip,
                "dst": dst_ip,
                "not_after": not_after,
            })
            return
        seen_fingerprints.add(sha256)

        subjects[subject] += 1
        issuers[issuer] += 1
        for name in san_list:
            sas[name] += 1

        if pubkey_size and pubkey_size < 2048:
            weak_keys.append({"subject": subject, "size": pubkey_size, "src": src_ip, "dst": dst_ip})

        lower_sig = sig_algo.lower()
        if "md5" in lower_sig or "sha1" in lower_sig:
            weak_signatures.append({
                "subject": subject,
                "issuer": issuer,
                "sig_algo": sig_algo,
                "src": src_ip,
                "dst": dst_ip,
            })

        if hasattr(cert, "not_valid_after_utc") and hasattr(cert, "not_valid_before_utc"):
            not_before_dt = cert.not_valid_before_utc  # type: ignore[attr-defined]
            not_after_dt = cert.not_valid_after_utc  # type: ignore[attr-defined]
        else:
            not_before_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
            not_after_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

        if not_after_dt < not_before_dt:
            expired.append({"subject": subject, "reason": "invalid validity", "src": src_ip, "dst": dst_ip})
        if now_utc > not_after_dt:
            expired.append({"subject": subject, "reason": "expired", "src": src_ip, "dst": dst_ip})
        if now_utc < not_before_dt:
            validity_outliers.append({
                "subject": subject,
                "reason": "not_yet_valid",
                "src": src_ip,
                "dst": dst_ip,
            })

        validity_days = (not_after_dt - not_before_dt).total_seconds() / 86400.0
        if validity_days <= 14:
            validity_outliers.append({"subject": subject, "reason": "short_validity", "days": round(validity_days, 1), "src": src_ip, "dst": dst_ip})
        elif validity_days >= 825:
            validity_outliers.append({"subject": subject, "reason": "long_validity", "days": round(validity_days, 1), "src": src_ip, "dst": dst_ip})

        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            oid_names = [getattr(oid, "_name", str(oid)) for oid in eku]
            joined = ",".join(str(v).lower() for v in oid_names)
            if "serverauth" not in joined and "tls web server authentication" not in joined:
                eku_mismatches.append({"subject": subject, "reason": "missing_server_auth", "eku": ", ".join(oid_names), "src": src_ip, "dst": dst_ip})
        except Exception:
            eku_mismatches.append({"subject": subject, "reason": "missing_eku", "src": src_ip, "dst": dst_ip})

        try:
            ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if not bool(getattr(ku, "digital_signature", False) or getattr(ku, "key_encipherment", False) or getattr(ku, "key_agreement", False)):
                key_usage_issues.append({"subject": subject, "reason": "leaf_without_tls_key_usage", "src": src_ip, "dst": dst_ip})
        except Exception:
            key_usage_issues.append({"subject": subject, "reason": "missing_key_usage", "src": src_ip, "dst": dst_ip})

        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if bool(getattr(bc, "ca", False)):
                chain_gaps.append({"subject": subject, "reason": "leaf_marked_as_ca", "src": src_ip, "dst": dst_ip})
        except Exception:
            chain_gaps.append({"subject": subject, "reason": "missing_basic_constraints", "src": src_ip, "dst": dst_ip})

        if san_list:
            if dst_ip not in san_list:
                try:
                    ipaddress.ip_address(dst_ip)
                    name_mismatches.append({"subject": subject, "reason": "dst_ip_not_in_san", "dst": dst_ip, "src": src_ip})
                except Exception:
                    pass
        else:
            name_mismatches.append({"subject": subject, "reason": "missing_san", "src": src_ip, "dst": dst_ip})

        lower_blob = f"{subject} {san_text}".lower()
        if any(marker in lower_blob for marker in brand_markers):
            suspicious = False
            if subject == issuer:
                suspicious = True
            if any(name.lower().endswith(suspicious_tlds) for name in san_list):
                suspicious = True
            if pubkey_size and pubkey_size < 2048:
                suspicious = True
            if suspicious:
                issuer_impersonation.append({"subject": subject, "issuer": issuer, "san": san_text, "src": src_ip, "dst": dst_ip})

        has_aia = False
        has_crl = False
        try:
            aia = cert.extensions.get_extension_for_oid(x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            aia_items = [str(item.access_method) for item in aia]
            has_aia = bool(aia_items)
        except Exception:
            has_aia = False
        try:
            cdp = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS).value
            has_crl = bool(cdp)
        except Exception:
            has_crl = False
        if not has_aia and not has_crl:
            revocation_gaps.append({"subject": subject, "reason": "missing_ocsp_and_crl", "src": src_ip, "dst": dst_ip})

        if subject == issuer:
            self_signed.append({"subject": subject, "src": src_ip, "dst": dst_ip})

        timeline.append({
            "event": "cert_seen",
            "subject": subject,
            "issuer": issuer,
            "sha256": sha256,
            "serial": serial,
            "src": src_ip,
            "dst": dst_ip,
            "not_after": not_after,
        })

        artifacts.append(CertificateInfo(
            subject=subject,
            issuer=issuer,
            serial=serial,
            not_before=not_before,
            not_after=not_after,
            sig_algo=sig_algo,
            pubkey_type=pubkey_type,
            pubkey_size=pubkey_size,
            san=san_text,
            sha1=sha1,
            sha256=sha256,
            src_ip=src_ip,
            dst_ip=dst_ip,
            sni=None,
        ))

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            total_packets += 1
            if TLS is not None and pkt.haslayer(TLS):
                tls_packets += 1

            cert_payloads: list[object] = []
            if TLSCertificate is not None and pkt.haslayer(TLSCertificate):
                cert_payloads.append(pkt[TLSCertificate])  # type: ignore[index]
            if TLS is not None and pkt.haslayer(TLS):
                tls_layer = pkt[TLS]  # type: ignore[index]
                for attr in ("msg", "msglist", "msgs", "messages", "records", "handshakes", "handshake", "hsmsg"):
                    value = getattr(tls_layer, attr, None)
                    if value is None:
                        continue
                    if isinstance(value, (list, tuple)):
                        cert_payloads.extend(value)
                    else:
                        cert_payloads.append(value)
            if not cert_payloads:
                continue

            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
            if IP is not None and pkt.haslayer(IP):  # type: ignore[truthy-bool]
                ip_layer = pkt[IP]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", "0.0.0.0"))
                dst_ip = str(getattr(ip_layer, "dst", "0.0.0.0"))
            elif IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
                ip_layer = pkt[IPv6]  # type: ignore[index]
                src_ip = str(getattr(ip_layer, "src", "::"))
                dst_ip = str(getattr(ip_layer, "dst", "::"))

            for payload in cert_payloads:
                for cert_bytes in _collect_cert_items(payload):
                    try:
                        if isinstance(cert_bytes, (bytes, bytearray)):
                            raw_cert = bytes(cert_bytes)
                        elif isinstance(cert_bytes, str):
                            raw_cert = cert_bytes.encode("latin-1", errors="ignore")
                        else:
                            raw_cert = None
                            for attr in ("der", "data", "raw", "cert", "bytes", "bin"):
                                val = getattr(cert_bytes, attr, None)
                                if val is None:
                                    continue
                                if isinstance(val, str):
                                    raw_cert = val.encode("latin-1", errors="ignore")
                                else:
                                    try:
                                        raw_cert = bytes(val)
                                    except Exception:
                                        raw_cert = None
                                if raw_cert:
                                    break
                            if raw_cert is None:
                                try:
                                    raw_cert = bytes(cert_bytes)
                                except Exception:
                                    raw_cert = bytes(bytearray(
                                        (int(b) & 0xFF)
                                        for b in cert_bytes
                                        if isinstance(b, (int,))
                                    ))
                        if not isinstance(raw_cert, (bytes, bytearray)) or not raw_cert:
                            continue
                        _handle_cert_bytes(bytes(raw_cert), src_ip, dst_ip)
                    except Exception as exc:
                        exc_text = str(exc)
                        lower = exc_text.lower()
                        if "asn1" in lower and "shortdata" in lower:
                            continue
                        errors.append(exc_text)
                        continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp_layer = pkt[TCP]  # type: ignore[index]
                payload = None
                if Raw is not None and pkt.haslayer(Raw):  # type: ignore[truthy-bool]
                    payload = bytes(pkt[Raw])  # type: ignore[index]
                else:
                    try:
                        payload = bytes(tcp_layer.payload)
                    except Exception:
                        payload = None
                if payload and len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 0x03:
                    flow_key = (src_ip, dst_ip, int(getattr(tcp_layer, "sport", 0)), int(getattr(tcp_layer, "dport", 0)))
                    buf = tls_buffers.setdefault(flow_key, bytearray())
                    buf.extend(payload)
                    certs, consumed = _parse_tls_from_buffer(buf)
                    if consumed > 0:
                        del buf[:consumed]
                    if len(buf) > 1_000_000:
                        del buf[:-1_000_000]
                    for cert_bytes in certs:
                        _handle_cert_bytes(cert_bytes, src_ip, dst_ip)
    finally:
        status.finish()
        reader.close()
        if conf is not None and prev_verb is not None:
            try:
                conf.verb = prev_verb
            except Exception:
                pass
        if scapy_error is not None and prev_warning is not None:
            try:
                scapy_error.warning = prev_warning  # type: ignore[assignment]
            except Exception:
                pass

    serial_reuse: list[dict[str, object]] = []
    for serial_value, contexts in serial_contexts.items():
        if len(contexts) >= 3:
            serial_reuse.append({
                "serial": serial_value,
                "contexts": sorted(contexts)[:10],
                "count": len(contexts),
            })

    fingerprint_reuse: list[dict[str, object]] = []
    for fp, contexts in fingerprint_contexts.items():
        if len(contexts) >= 3:
            fingerprint_reuse.append({
                "sha256": fp,
                "contexts": sorted(contexts)[:10],
                "count": len(contexts),
            })

    endpoint_profiles_map: dict[str, dict[str, object]] = {}
    for cert in artifacts:
        endpoint = str(cert.dst_ip)
        profile = endpoint_profiles_map.setdefault(
            endpoint,
            {
                "endpoint": endpoint,
                "subjects": set(),
                "issuers": set(),
                "fingerprints": set(),
                "not_after": [],
                "flows": set(),
            },
        )
        cast_subjects = profile.get("subjects")
        if isinstance(cast_subjects, set):
            cast_subjects.add(cert.subject)
        cast_issuers = profile.get("issuers")
        if isinstance(cast_issuers, set):
            cast_issuers.add(cert.issuer)
        cast_fps = profile.get("fingerprints")
        if isinstance(cast_fps, set):
            cast_fps.add(cert.sha256)
        cast_dates = profile.get("not_after")
        if isinstance(cast_dates, list):
            cast_dates.append(cert.not_after)
        cast_flows = profile.get("flows")
        if isinstance(cast_flows, set):
            cast_flows.add(f"{cert.src_ip}->{cert.dst_ip}")

    endpoint_profiles: list[dict[str, object]] = []
    for profile in endpoint_profiles_map.values():
        endpoint_profiles.append({
            "endpoint": profile.get("endpoint", "-"),
            "subjects": len(profile.get("subjects", set())),
            "issuers": len(profile.get("issuers", set())),
            "fingerprints": len(profile.get("fingerprints", set())),
            "flows": len(profile.get("flows", set())),
            "latest_not_after": max(profile.get("not_after", ["-"])) if profile.get("not_after") else "-",
        })
    endpoint_profiles.sort(key=lambda item: int(item.get("fingerprints", 0)), reverse=True)

    timeline_sorted = sorted(timeline, key=lambda item: str(item.get("not_after", "")))

    return CertificateSummary(
        path=path,
        total_packets=total_packets,
        tls_packets=tls_packets,
        cert_count=len(artifacts),
        subjects=subjects,
        issuers=issuers,
        sas=sas,
        weak_keys=weak_keys,
        expired=expired,
        self_signed=self_signed,
        artifacts=artifacts,
        weak_signatures=weak_signatures,
        eku_mismatches=eku_mismatches,
        key_usage_issues=key_usage_issues,
        name_mismatches=name_mismatches,
        validity_outliers=validity_outliers,
        serial_reuse=serial_reuse,
        fingerprint_reuse=fingerprint_reuse,
        issuer_impersonation=issuer_impersonation,
        revocation_gaps=revocation_gaps,
        chain_gaps=chain_gaps,
        endpoint_profiles=endpoint_profiles,
        timeline=timeline_sorted[:200],
        errors=errors,
    )
