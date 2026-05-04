from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .pcap_cache import get_reader
from .utils import safe_float, extract_packet_endpoints

try:
    from scapy.layers.inet import IP, TCP, UDP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
except Exception:  # pragma: no cover
    IP = None  # type: ignore
    TCP = None  # type: ignore
    UDP = None  # type: ignore
    IPv6 = None  # type: ignore

try:
    from scapy.layers.tls.handshake import (  # type: ignore
        TLSCertificate,
        TLSClientHello,
        TLSServerHello,
    )
except Exception:  # pragma: no cover
    TLSCertificate = None  # type: ignore
    TLSClientHello = None  # type: ignore
    TLSServerHello = None  # type: ignore

try:
    from cryptography import x509  # type: ignore
    from cryptography.hazmat.backends import default_backend  # type: ignore
    from cryptography.hazmat.primitives import hashes  # type: ignore
except Exception:  # pragma: no cover
    x509 = None  # type: ignore
    default_backend = None  # type: ignore
    hashes = None  # type: ignore


VPN_PORTS = {
    500: "IKE",
    4500: "IPsec NAT-T",
    1194: "OpenVPN",
    4433: "OpenVPN",
    51820: "WireGuard",
    1701: "L2TP",
    1723: "PPTP",
    443: "SSTP/HTTPS VPN",
    5555: "SoftEther VPN",
}

VPN_IP_PROTOCOLS = {
    47: "GRE",
    50: "IPsec ESP",
    51: "IPsec AH",
}

IKEV1_EXCHANGE_TYPES = {
    2: "IKEv1 Main Mode",
    4: "IKEv1 Aggressive Mode",
    5: "IKEv1 Informational",
    32: "IKEv1 Quick Mode",
}

IKEV2_EXCHANGE_TYPES = {
    34: "IKEv2 IKE_SA_INIT",
    35: "IKEv2 IKE_AUTH",
    36: "IKEv2 CREATE_CHILD_SA",
    37: "IKEv2 INFORMATIONAL",
    38: "IKEv2 IKE_SESSION_RESUME",
}

WIREGUARD_MESSAGE_TYPES = {
    1: "WireGuard Handshake Initiation",
    2: "WireGuard Handshake Response",
    3: "WireGuard Cookie Reply",
    4: "WireGuard Transport",
}

OPENVPN_OPCODES = {
    1: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V1",
    2: "OpenVPN P_CONTROL_HARD_RESET_SERVER_V1",
    3: "OpenVPN P_CONTROL_SOFT_RESET_V1",
    4: "OpenVPN P_CONTROL_V1",
    5: "OpenVPN P_ACK_V1",
    6: "OpenVPN P_DATA_V1",
    7: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2",
    8: "OpenVPN P_CONTROL_HARD_RESET_SERVER_V2",
    9: "OpenVPN P_DATA_V2",
    10: "OpenVPN P_CONTROL_HARD_RESET_CLIENT_V3",
}

WEAK_CERT_SIGS = {"md5", "sha1"}


@dataclass(frozen=True)
class VpnSummary:
    path: Path
    total_packets: int
    vpn_packets: int
    service_counts: Counter[str]
    protocol_counts: Counter[str]
    client_counts: Counter[str]
    server_counts: Counter[str]
    artifact_correlations: Counter[str]
    server_port_counts: Counter[int]
    handshake_counts: Counter[str]
    certificate_subjects: Counter[str]
    certificate_issuers: Counter[str]
    certificate_sans: Counter[str]
    certificate_count: int
    self_signed_cert_count: int
    weak_cert_count: int
    threat_counts: Counter[str]
    anomaly_counts: Counter[str]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _packet_ip_proto(pkt: object) -> Optional[int]:
    try:
        value = getattr(pkt, "proto", None)
        if value is not None:
            return int(value)
    except Exception:
        pass
    try:
        if IPv6 is not None and pkt.haslayer(IPv6):  # type: ignore[truthy-bool]
            value = getattr(pkt[IPv6], "nh", None)  # type: ignore[index]
            if value is not None:
                return int(value)
    except Exception:
        pass
    return None


def _infer_client_server(
    src_ip: str,
    dst_ip: str,
    sport: Optional[int],
    dport: Optional[int],
) -> tuple[str, str, Optional[int]]:
    src_is_known = bool(sport is not None and sport in VPN_PORTS)
    dst_is_known = bool(dport is not None and dport in VPN_PORTS)

    if src_is_known and not dst_is_known:
        return dst_ip, src_ip, sport
    if dst_is_known and not src_is_known:
        return src_ip, dst_ip, dport

    if dport is not None and dport in VPN_PORTS:
        return src_ip, dst_ip, dport
    if sport is not None and sport in VPN_PORTS:
        return dst_ip, src_ip, sport

    if dport is not None:
        return src_ip, dst_ip, dport
    if sport is not None:
        return dst_ip, src_ip, sport
    return src_ip, dst_ip, None


def _record_artifact_correlation(
    correlations: Counter[str], artifact: str, client_ip: str, server_ip: str
) -> None:
    artifact_name = str(artifact).strip()
    if not artifact_name or not client_ip or not server_ip:
        return
    correlations[f"{artifact_name} | {client_ip} -> {server_ip}"] += 1


def _extract_layer_payload(layer: object) -> bytes:
    try:
        return bytes(getattr(layer, "payload", b""))
    except Exception:
        return b""


def _parse_ike_exchange(payload: bytes, server_port: int) -> Optional[str]:
    if not payload:
        return None
    offset = 0
    if server_port == 4500:
        # UDP/4500 IKE messages have a 4-byte non-ESP marker of zeros.
        if len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
            offset = 4
        else:
            return None
    if len(payload) < offset + 28:
        return None

    version = payload[offset + 17]
    exchange_type = payload[offset + 18]
    major = (version >> 4) & 0x0F

    if major >= 2:
        return IKEV2_EXCHANGE_TYPES.get(exchange_type, "IKEv2 Other")
    if major == 1:
        return IKEV1_EXCHANGE_TYPES.get(exchange_type, "IKEv1 Other")
    return "IKE Unknown"


def _parse_wireguard_message(payload: bytes) -> Optional[str]:
    if len(payload) < 4:
        return None
    message_type = payload[0]
    if payload[1:4] != b"\x00\x00\x00":
        return None
    return WIREGUARD_MESSAGE_TYPES.get(message_type)


def _parse_openvpn_opcode(payload: bytes) -> Optional[str]:
    if not payload:
        return None
    opcode = payload[0] >> 3
    return OPENVPN_OPCODES.get(opcode)


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
    length_val = int.from_bytes(raw[2 : 2 + num_len_bytes], "big")
    total_len = 2 + num_len_bytes + length_val
    if total_len <= len(raw):
        return raw[:total_len]
    return None


def _coerce_cert_bytes(item: object) -> Optional[bytes]:
    if isinstance(item, (bytes, bytearray)):
        return bytes(item)
    for attr in ("cert", "cert_data", "data", "raw", "der"):
        value = getattr(item, attr, None)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
    try:
        raw = bytes(item)
        return raw if raw else None
    except Exception:
        return None


def _extract_tls_certificates(pkt: object) -> list[dict[str, object]]:
    if TLSCertificate is None or x509 is None or default_backend is None:
        return []
    try:
        if not pkt.haslayer(TLSCertificate):  # type: ignore[truthy-bool]
            return []
        cert_layer = pkt[TLSCertificate]  # type: ignore[index]
    except Exception:
        return []

    extracted: list[dict[str, object]] = []
    for item in _collect_cert_items(cert_layer):
        raw = _coerce_cert_bytes(item)
        if not raw:
            continue
        der_cert = _extract_der_cert(raw) or raw
        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
        except Exception:
            continue

        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        san_values: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san_values = [str(name).strip() for name in san.value.get_values_for_type(x509.DNSName)]
        except Exception:
            san_values = []

        sig_name = ""
        try:
            sig_algo = cert.signature_hash_algorithm
            if sig_algo is not None:
                sig_name = str(getattr(sig_algo, "name", "")).lower()
        except Exception:
            sig_name = ""

        key_size = 0
        try:
            key_size = int(getattr(cert.public_key(), "key_size", 0) or 0)
        except Exception:
            key_size = 0

        fingerprint = str(cert.serial_number)
        if hashes is not None:
            try:
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            except Exception:
                pass

        extracted.append(
            {
                "subject": subject,
                "issuer": issuer,
                "sans": san_values,
                "self_signed": bool(subject and subject == issuer),
                "weak": bool((sig_name in WEAK_CERT_SIGS) or (0 < key_size < 2048)),
                "fingerprint": fingerprint,
            }
        )
    return extracted


def analyze_vpn(path: Path, show_status: bool = True) -> VpnSummary:
    reader, status, stream, size_bytes, _file_type = get_reader(
        path, show_status=show_status
    )
    total_packets = 0
    vpn_packets = 0
    service_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    artifact_correlations: Counter[str] = Counter()
    server_port_counts: Counter[int] = Counter()
    handshake_counts: Counter[str] = Counter()
    certificate_subjects: Counter[str] = Counter()
    certificate_issuers: Counter[str] = Counter()
    certificate_sans: Counter[str] = Counter()
    certificate_count = 0
    self_signed_cert_count = 0
    weak_cert_count = 0
    threat_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    seen_cert_fingerprints: set[str] = set()

    try:
        for pkt in reader:
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            total_packets += 1
            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            src_ip, dst_ip = extract_packet_endpoints(pkt)
            if not src_ip or not dst_ip:
                continue

            ip_proto = _packet_ip_proto(pkt)
            if ip_proto in VPN_IP_PROTOCOLS:
                service = VPN_IP_PROTOCOLS[ip_proto]
                vpn_packets += 1
                service_counts[service] += 1
                protocol_counts[service] += 1
                client_ip, server_ip, _server_port = _infer_client_server(
                    src_ip, dst_ip, None, None
                )
                client_counts[client_ip] += 1
                server_counts[server_ip] += 1
                _record_artifact_correlation(
                    artifact_correlations, service, client_ip, server_ip
                )
                continue

            if TCP is not None and pkt.haslayer(TCP):  # type: ignore[truthy-bool]
                tcp = pkt[TCP]  # type: ignore[index]
                sport = int(getattr(tcp, "sport", 0) or 0)
                dport = int(getattr(tcp, "dport", 0) or 0)
                if sport in VPN_PORTS or dport in VPN_PORTS:
                    vpn_packets += 1
                    service = VPN_PORTS.get(dport) or VPN_PORTS.get(sport) or "VPN"
                    service_counts[service] += 1
                    protocol_counts["TCP"] += 1
                    client_ip, server_ip, server_port = _infer_client_server(
                        src_ip, dst_ip, sport, dport
                    )
                    client_counts[client_ip] += 1
                    server_counts[server_ip] += 1
                    _record_artifact_correlation(
                        artifact_correlations, service, client_ip, server_ip
                    )
                    if server_port:
                        server_port_counts[server_port] += 1

                    payload = _extract_layer_payload(tcp)
                    if server_port in {1194, 4433}:
                        opcode = _parse_openvpn_opcode(payload)
                        if opcode:
                            handshake_counts[opcode] += 1
                            _record_artifact_correlation(
                                artifact_correlations, opcode, client_ip, server_ip
                            )
                    if server_port == 1723:
                        try:
                            flags = int(getattr(tcp, "flags", 0) or 0)
                        except Exception:
                            flags = 0
                        if (flags & 0x02) and not (flags & 0x10):
                            handshake_counts["PPTP TCP SYN"] += 1
                            _record_artifact_correlation(
                                artifact_correlations,
                                "PPTP TCP SYN",
                                client_ip,
                                server_ip,
                            )
                    if server_port == 443:
                        if (
                            TLSClientHello is not None
                            and pkt.haslayer(TLSClientHello)  # type: ignore[truthy-bool]
                        ):
                            handshake_counts["TLS ClientHello"] += 1
                            _record_artifact_correlation(
                                artifact_correlations,
                                "TLS ClientHello",
                                client_ip,
                                server_ip,
                            )
                        if (
                            TLSServerHello is not None
                            and pkt.haslayer(TLSServerHello)  # type: ignore[truthy-bool]
                        ):
                            handshake_counts["TLS ServerHello"] += 1
                            _record_artifact_correlation(
                                artifact_correlations,
                                "TLS ServerHello",
                                client_ip,
                                server_ip,
                            )
                        for cert_info in _extract_tls_certificates(pkt):
                            fingerprint = str(cert_info.get("fingerprint", ""))
                            if fingerprint and fingerprint in seen_cert_fingerprints:
                                continue
                            if fingerprint:
                                seen_cert_fingerprints.add(fingerprint)
                            certificate_count += 1
                            _record_artifact_correlation(
                                artifact_correlations,
                                "TLS Certificate",
                                client_ip,
                                server_ip,
                            )

                            subject = str(cert_info.get("subject", "")).strip()
                            issuer = str(cert_info.get("issuer", "")).strip()
                            if subject:
                                certificate_subjects[subject] += 1
                            if issuer:
                                certificate_issuers[issuer] += 1

                            for san in cert_info.get("sans", []) or []:
                                san_text = str(san).strip()
                                if san_text:
                                    certificate_sans[san_text] += 1

                            if bool(cert_info.get("self_signed", False)):
                                self_signed_cert_count += 1
                                _record_artifact_correlation(
                                    artifact_correlations,
                                    "Self-Signed VPN Certificate",
                                    client_ip,
                                    server_ip,
                                )
                            if bool(cert_info.get("weak", False)):
                                weak_cert_count += 1
                                _record_artifact_correlation(
                                    artifact_correlations,
                                    "Weak VPN Certificate",
                                    client_ip,
                                    server_ip,
                                )

            if UDP is not None and pkt.haslayer(UDP):  # type: ignore[truthy-bool]
                udp = pkt[UDP]  # type: ignore[index]
                sport = int(getattr(udp, "sport", 0) or 0)
                dport = int(getattr(udp, "dport", 0) or 0)
                if sport in VPN_PORTS or dport in VPN_PORTS:
                    vpn_packets += 1
                    service = VPN_PORTS.get(dport) or VPN_PORTS.get(sport) or "VPN"
                    service_counts[service] += 1
                    protocol_counts["UDP"] += 1
                    client_ip, server_ip, server_port = _infer_client_server(
                        src_ip, dst_ip, sport, dport
                    )
                    client_counts[client_ip] += 1
                    server_counts[server_ip] += 1
                    _record_artifact_correlation(
                        artifact_correlations, service, client_ip, server_ip
                    )
                    if server_port:
                        server_port_counts[server_port] += 1

                    payload = _extract_layer_payload(udp)
                    if server_port in {500, 4500}:
                        exchange = _parse_ike_exchange(payload, server_port)
                        if exchange:
                            handshake_counts[exchange] += 1
                            _record_artifact_correlation(
                                artifact_correlations, exchange, client_ip, server_ip
                            )
                        elif server_port == 4500 and payload:
                            # UDP/4500 packets without non-ESP marker are often ESP-in-UDP.
                            protocol_counts["UDP-ESP"] += 1
                            _record_artifact_correlation(
                                artifact_correlations, "UDP-ESP", client_ip, server_ip
                            )
                    if server_port == 51820:
                        wg_message = _parse_wireguard_message(payload)
                        if wg_message:
                            handshake_counts[wg_message] += 1
                            _record_artifact_correlation(
                                artifact_correlations,
                                wg_message,
                                client_ip,
                                server_ip,
                            )
                    if server_port in {1194, 4433}:
                        opcode = _parse_openvpn_opcode(payload)
                        if opcode:
                            handshake_counts[opcode] += 1
                            _record_artifact_correlation(
                                artifact_correlations, opcode, client_ip, server_ip
                            )
                    if server_port == 1701 and payload and (payload[0] & 0x80):
                        handshake_counts["L2TP Control"] += 1
                        _record_artifact_correlation(
                            artifact_correlations,
                            "L2TP Control",
                            client_ip,
                            server_ip,
                        )

    finally:
        status.finish()
        reader.close()

    if int(service_counts.get("PPTP", 0)) > 0:
        threat_counts["Legacy PPTP tunnel observed"] += int(service_counts["PPTP"])

    if int(service_counts.get("L2TP", 0)) > 0:
        has_ipsec_companion = any(
            service_counts.get(key, 0) > 0
            for key in ("IKE", "IPsec NAT-T", "IPsec ESP", "IPsec AH")
        )
        if not has_ipsec_companion:
            anomaly_counts["L2TP observed without IPsec companion"] += int(
                service_counts["L2TP"]
            )

    ike_init = int(handshake_counts.get("IKEv2 IKE_SA_INIT", 0))
    ike_auth = int(handshake_counts.get("IKEv2 IKE_AUTH", 0))
    if ike_init >= 10 and (ike_auth * 3) < ike_init:
        threat_counts["High IKE init/auth mismatch"] += ike_init - ike_auth

    wg_init = int(handshake_counts.get("WireGuard Handshake Initiation", 0))
    wg_resp = int(handshake_counts.get("WireGuard Handshake Response", 0))
    if wg_init >= 10 and (wg_resp * 3) < wg_init:
        anomaly_counts["WireGuard initiation/response imbalance"] += wg_init - wg_resp

    https_vpn = int(service_counts.get("SSTP/HTTPS VPN", 0))
    tls_hello_count = int(handshake_counts.get("TLS ClientHello", 0)) + int(
        handshake_counts.get("TLS ServerHello", 0)
    )
    if https_vpn >= 10 and tls_hello_count == 0:
        anomaly_counts["Port 443 VPN labeling without TLS hello"] += https_vpn

    if weak_cert_count > 0:
        threat_counts["Weak VPN certificate cryptography"] += weak_cert_count
    if self_signed_cert_count > 0:
        anomaly_counts["Self-signed VPN certificates"] += self_signed_cert_count

    if len(client_counts) >= 25 and len(server_counts) <= 2:
        anomaly_counts["Many clients targeting few VPN gateways"] += len(client_counts)

    if vpn_packets:
        detections.append(
            {
                "severity": "info",
                "summary": "VPN/Tunnel indicators observed",
                "details": (
                    f"{vpn_packets} packets mapped to VPN/Tunnel protocols/ports "
                    f"across {len(service_counts)} service types."
                ),
            }
        )

    for label, count in threat_counts.most_common(5):
        detections.append(
            {
                "severity": "warning",
                "summary": label,
                "details": f"{count} related indicator(s) observed.",
            }
        )

    for label, count in anomaly_counts.most_common(5):
        detections.append(
            {
                "severity": "low",
                "summary": label,
                "details": f"{count} anomalous event(s) observed.",
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return VpnSummary(
        path=path,
        total_packets=total_packets,
        vpn_packets=vpn_packets,
        service_counts=service_counts,
        protocol_counts=protocol_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        artifact_correlations=artifact_correlations,
        server_port_counts=server_port_counts,
        handshake_counts=handshake_counts,
        certificate_subjects=certificate_subjects,
        certificate_issuers=certificate_issuers,
        certificate_sans=certificate_sans,
        certificate_count=certificate_count,
        self_signed_cert_count=self_signed_cert_count,
        weak_cert_count=weak_cert_count,
        threat_counts=threat_counts,
        anomaly_counts=anomaly_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )


def merge_vpn_summaries(summaries: list[VpnSummary]) -> VpnSummary:
    if not summaries:
        return VpnSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            vpn_packets=0,
            service_counts=Counter(),
            protocol_counts=Counter(),
            client_counts=Counter(),
            server_counts=Counter(),
            artifact_correlations=Counter(),
            server_port_counts=Counter(),
            handshake_counts=Counter(),
            certificate_subjects=Counter(),
            certificate_issuers=Counter(),
            certificate_sans=Counter(),
            certificate_count=0,
            self_signed_cert_count=0,
            weak_cert_count=0,
            threat_counts=Counter(),
            anomaly_counts=Counter(),
            detections=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = sum(item.total_packets for item in summaries)
    vpn_packets = sum(item.vpn_packets for item in summaries)
    service_counts: Counter[str] = Counter()
    protocol_counts: Counter[str] = Counter()
    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    artifact_correlations: Counter[str] = Counter()
    server_port_counts: Counter[int] = Counter()
    handshake_counts: Counter[str] = Counter()
    certificate_subjects: Counter[str] = Counter()
    certificate_issuers: Counter[str] = Counter()
    certificate_sans: Counter[str] = Counter()
    certificate_count = 0
    self_signed_cert_count = 0
    weak_cert_count = 0
    threat_counts: Counter[str] = Counter()
    anomaly_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    for item in summaries:
        service_counts.update(item.service_counts)
        protocol_counts.update(item.protocol_counts)
        client_counts.update(item.client_counts)
        server_counts.update(item.server_counts)
        artifact_correlations.update(item.artifact_correlations)
        server_port_counts.update(item.server_port_counts)
        handshake_counts.update(item.handshake_counts)
        certificate_subjects.update(item.certificate_subjects)
        certificate_issuers.update(item.certificate_issuers)
        certificate_sans.update(item.certificate_sans)
        certificate_count += int(item.certificate_count)
        self_signed_cert_count += int(item.self_signed_cert_count)
        weak_cert_count += int(item.weak_cert_count)
        threat_counts.update(item.threat_counts)
        anomaly_counts.update(item.anomaly_counts)
        detections.extend(item.detections)
        errors.extend(item.errors)
        if item.first_seen is not None:
            first_seen = (
                item.first_seen
                if first_seen is None
                else min(first_seen, item.first_seen)
            )
        if item.last_seen is not None:
            last_seen = item.last_seen if last_seen is None else max(last_seen, item.last_seen)

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )

    return VpnSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        vpn_packets=vpn_packets,
        service_counts=service_counts,
        protocol_counts=protocol_counts,
        client_counts=client_counts,
        server_counts=server_counts,
        artifact_correlations=artifact_correlations,
        server_port_counts=server_port_counts,
        handshake_counts=handshake_counts,
        certificate_subjects=certificate_subjects,
        certificate_issuers=certificate_issuers,
        certificate_sans=certificate_sans,
        certificate_count=certificate_count,
        self_signed_cert_count=self_signed_cert_count,
        weak_cert_count=weak_cert_count,
        threat_counts=threat_counts,
        anomaly_counts=anomaly_counts,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
