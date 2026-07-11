from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from .pcap_cache import get_reader
from .utils import safe_float

try:
    from scapy.layers.dot11 import (  # type: ignore
        Dot11,
        Dot11AssoReq,
        Dot11AssoResp,
        Dot11Auth,
        Dot11Beacon,
        Dot11Deauth,
        Dot11Disas,
        Dot11Elt,
        Dot11ProbeReq,
        Dot11ProbeResp,
        Dot11WEP,
        RadioTap,
    )
except Exception:  # pragma: no cover
    Dot11 = Dot11AssoReq = Dot11AssoResp = Dot11Auth = Dot11Beacon = None  # type: ignore
    Dot11Deauth = Dot11Disas = Dot11Elt = Dot11ProbeReq = Dot11ProbeResp = RadioTap = (
        Dot11WEP
    ) = None  # type: ignore

try:
    from scapy.layers.eap import EAPOL  # type: ignore
except Exception:  # pragma: no cover
    EAPOL = None  # type: ignore


OUI_WPA = b"\x00\x50\xf2\x01"
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "key=",
    "private key",
)
SECRET_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b"
    r"\s*[:=]\s*([^\s&;\"']{2,200})"
)
AUTH_RE = re.compile(r"(?i)\bauthorization\s*:\s*([^\r\n]{1,220})")
B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DOT11_MGMT_SUBTYPE_NAMES: dict[int, str] = {
    0: "AssocReq",
    1: "AssocResp",
    2: "ReassocReq",
    3: "ReassocResp",
    4: "ProbeReq",
    5: "ProbeResp",
    8: "Beacon",
    9: "ATIM",
    10: "Disassoc",
    11: "Auth",
    12: "Deauth",
    13: "Action",
    14: "ActionNoAck",
}

PHY_RANK: dict[str, int] = {
    "802.11ax": 5,
    "802.11ac": 4,
    "802.11n": 3,
    "802.11g/a": 2,
    "802.11b": 1,
    "Legacy/Unknown": 0,
}

SECURITY_RANK: dict[str, int] = {
    "OPEN": 0,
    "WEP": 1,
    "WEP/Unknown-Privacy": 1,
    "WPA1": 2,
    "WPA2-PSK": 3,
    "WPA2-Enterprise": 4,
    "WPA2/WPA3-Transition": 5,
    "WPA3-SAE": 6,
    "UNKNOWN": 0,
}


@dataclass(frozen=True)
class WlanNetwork:
    bssid: str
    ssid: str
    channel: Optional[int]
    security: str
    beacons: int
    probe_responses: int
    associated_clients: int
    eapol_frames: int
    phy_protocol: str
    avg_signal_dbm: Optional[int]
    peak_signal_dbm: Optional[int]
    first_seen: Optional[float]
    last_seen: Optional[float]


@dataclass(frozen=True)
class WlanClient:
    mac: str
    probe_requests: int
    auth_requests: int
    assoc_requests: int
    deauth_frames: int
    unique_bssids: int
    ips: tuple[str, ...]
    protection: str
    avg_signal_dbm: Optional[int]
    peak_signal_dbm: Optional[int]


@dataclass(frozen=True)
class WlanSummary:
    path: Path
    total_packets: int
    wlan_packets: int
    mgmt_packets: int
    data_packets: int
    protected_data_packets: int
    control_packets: int
    eapol_packets: int
    wep_packets: int
    open_data_packets: int
    open_data_bytes: int
    null_data_packets: int
    qos_null_packets: int
    unique_networks: int
    unique_clients: int
    security_counts: Counter[str]
    phy_counts: Counter[str]
    ssid_counts: Counter[str]
    channel_counts: Counter[int]
    mgmt_subtype_counts: Counter[str]
    networks: list[WlanNetwork]
    clients: list[WlanClient]
    ap_client_links: list[dict[str, object]]
    ssid_details: list[dict[str, object]]
    bssid_details: list[dict[str, object]]
    detections: list[dict[str, object]]
    deterministic_checks: dict[str, list[str]]
    wpa_handshakes: list[dict[str, object]]
    wep_signals: list[dict[str, object]]
    open_artifacts: list[dict[str, object]]
    discovered_secrets: list[dict[str, object]]
    transfer_channels: list[dict[str, object]]
    recovered_ip_artifacts: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def _cap_privacy_set(cap: int | None) -> bool:
    if cap is None:
        return False
    return bool(int(cap) & 0x0010)


def _extract_akm_types_from_rsn(info: bytes) -> set[int]:
    out: set[int] = set()
    try:
        if len(info) < 8:
            return out
        idx = 0
        idx += 2  # version
        idx += 4  # group cipher
        if idx + 2 > len(info):
            return out
        pairwise_count = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2 + (pairwise_count * 4)
        if idx + 2 > len(info):
            return out
        akm_count = int.from_bytes(info[idx : idx + 2], "little")
        idx += 2
        for _ in range(akm_count):
            if idx + 4 > len(info):
                break
            suite = info[idx : idx + 4]
            idx += 4
            out.add(int(suite[3]))
    except Exception:
        return out
    return out


def _detect_security(pkt, privacy_flag: bool) -> tuple[str, bool, bool]:
    has_rsn = False
    has_wpa_vendor = False
    akm_types: set[int] = set()
    elt = pkt.getlayer(Dot11Elt) if Dot11Elt is not None else None
    while elt is not None:
        try:
            eid = int(getattr(elt, "ID", -1))
            info = bytes(getattr(elt, "info", b"") or b"")
        except Exception:
            eid = -1
            info = b""
        if eid == 48:
            has_rsn = True
            akm_types.update(_extract_akm_types_from_rsn(info))
        elif eid == 221 and info.startswith(OUI_WPA):
            has_wpa_vendor = True
            akm_types.update(_extract_akm_types_from_rsn(info[4:]))
        elt = (
            elt.payload.getlayer(Dot11Elt)
            if getattr(elt, "payload", None) is not None
            else None
        )

    if has_rsn:
        if 8 in akm_types:
            if 2 in akm_types:
                return "WPA2/WPA3-Transition", has_rsn, has_wpa_vendor
            return "WPA3-SAE", has_rsn, has_wpa_vendor
        if 1 in akm_types:
            return "WPA2-Enterprise", has_rsn, has_wpa_vendor
        return "WPA2-PSK", has_rsn, has_wpa_vendor
    if has_wpa_vendor:
        return "WPA1", has_rsn, has_wpa_vendor
    if privacy_flag:
        return "WEP/Unknown-Privacy", has_rsn, has_wpa_vendor
    return "OPEN", has_rsn, has_wpa_vendor


def _normalize_ssid(value: str) -> str:
    text = (value or "").strip()
    if not text or text == "\x00" * len(text):
        return "<hidden>"
    return text


def _extract_text_payload(pkt: object) -> str:
    try:
        payload = bytes(getattr(pkt, "payload", b"") or b"")
    except Exception:
        payload = b""
    if not payload:
        return ""
    sample = payload[:8192]
    return sample.decode("utf-8", errors="ignore")


def _extract_signal_dbm(pkt: object) -> Optional[int]:
    if RadioTap is not None and hasattr(pkt, "haslayer") and pkt.haslayer(RadioTap):  # type: ignore[truthy-bool]
        try:
            val = getattr(pkt[RadioTap], "dBm_AntSignal", None)  # type: ignore[index]
            if val is not None:
                return int(val)
        except Exception:
            pass
    for attr in ("dBm_AntSignal", "dbm_antsignal", "signal"):
        try:
            val = getattr(pkt, attr, None)
            if val is not None:
                return int(val)
        except Exception:
            continue
    return None


def _infer_phy_protocol(pkt: object) -> str:
    has_ht = False
    has_vht = False
    has_he = False
    elt = (
        pkt.getlayer(Dot11Elt)
        if Dot11Elt is not None and hasattr(pkt, "getlayer")
        else None
    )
    while elt is not None:
        try:
            eid = int(getattr(elt, "ID", -1))
            info = bytes(getattr(elt, "info", b"") or b"")
        except Exception:
            eid = -1
            info = b""
        if eid in {45, 61}:
            has_ht = True
        elif eid == 191:
            has_vht = True
        elif eid == 255 and info:
            ext_id = int(info[0])
            if ext_id in {35, 36}:
                has_he = True
        elt = (
            elt.payload.getlayer(Dot11Elt)
            if getattr(elt, "payload", None) is not None
            else None
        )
    if has_he:
        return "802.11ax"
    if has_vht:
        return "802.11ac"
    if has_ht:
        return "802.11n"
    return "Legacy/Unknown"


def _prefer_phy(left: str, right: str) -> str:
    if PHY_RANK.get(right, 0) > PHY_RANK.get(left, 0):
        return right
    return left


def _prefer_security(left: str, right: str) -> str:
    if SECURITY_RANK.get(right, 0) > SECURITY_RANK.get(left, 0):
        return right
    return left


def _is_unicast_mac(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text or text == "ff:ff:ff:ff:ff:ff":
        return False
    if text.startswith("33:33:") or text.startswith("01:00:5e:"):
        return False
    return True


def _infer_bssid(dot11: object, ftype: int, addr1: str, addr2: str, addr3: str) -> str:
    if ftype == 0:
        return addr3 or addr2 or addr1
    try:
        fc_val = int(getattr(dot11, "FCfield", 0) or 0)
    except Exception:
        fc_val = 0
    to_ds = bool(fc_val & 0x1)
    from_ds = bool(fc_val & 0x2)
    if ftype == 2:
        if not to_ds and not from_ds:
            return addr3
        if to_ds and not from_ds:
            return addr1
        if not to_ds and from_ds:
            return addr2
    return addr3 or addr1 or addr2


def analyze_wlan(
    path: Path,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: object | None = None,
) -> WlanSummary:
    if Dot11 is None:
        return WlanSummary(
            path=path,
            total_packets=0,
            wlan_packets=0,
            mgmt_packets=0,
            data_packets=0,
            protected_data_packets=0,
            control_packets=0,
            eapol_packets=0,
            wep_packets=0,
            open_data_packets=0,
            open_data_bytes=0,
            null_data_packets=0,
            qos_null_packets=0,
            unique_networks=0,
            unique_clients=0,
            security_counts=Counter(),
            phy_counts=Counter(),
            ssid_counts=Counter(),
            channel_counts=Counter(),
            mgmt_subtype_counts=Counter(),
            networks=[],
            clients=[],
            ap_client_links=[],
            ssid_details=[],
            bssid_details=[],
            detections=[],
            deterministic_checks={},
            wpa_handshakes=[],
            wep_signals=[],
            open_artifacts=[],
            discovered_secrets=[],
            transfer_channels=[],
            recovered_ip_artifacts=[],
            errors=[
                "Scapy 802.11 layers unavailable; install full scapy wireless support."
            ],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    reader, status, stream, size_bytes, _file_type = get_reader(
        path, packets=packets, meta=meta, show_status=show_status
    )

    total_packets = 0
    wlan_packets = 0
    mgmt_packets = 0
    data_packets = 0
    protected_data_packets = 0
    control_packets = 0
    eapol_packets = 0
    wep_packets = 0
    open_data_packets = 0
    open_data_bytes = 0
    null_data_packets = 0
    qos_null_packets = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    errors: list[str] = []

    security_counts: Counter[str] = Counter()
    phy_counts: Counter[str] = Counter()
    ssid_counts: Counter[str] = Counter()
    channel_counts: Counter[int] = Counter()
    mgmt_subtype_counts: Counter[str] = Counter()

    network_state: dict[str, dict[str, object]] = {}
    client_state: dict[str, dict[str, object]] = defaultdict(
        lambda: {
            "probe_requests": 0,
            "auth_requests": 0,
            "assoc_requests": 0,
            "deauth_frames": 0,
            "bssids": set(),
            "protection": Counter(),
            "signals": [],
        }
    )
    deauth_by_src: Counter[str] = Counter()
    disassoc_by_src: Counter[str] = Counter()
    eapol_pair_counts: Counter[tuple[str, str]] = Counter()
    wep_iv_counts: dict[str, Counter[str]] = defaultdict(Counter)
    wep_keyid_counts: Counter[str] = Counter()
    ssid_bssids: dict[str, set[str]] = defaultdict(set)
    ssid_security: dict[str, set[str]] = defaultdict(set)
    bssid_security_observed: dict[str, Counter[str]] = defaultdict(Counter)
    wep_packets_by_bssid: Counter[str] = Counter()
    open_artifacts: list[dict[str, object]] = []
    discovered_secrets: list[dict[str, object]] = []
    recovered_ip_artifacts: list[dict[str, object]] = []
    artifact_seen: set[tuple[object, ...]] = set()
    secret_seen: set[tuple[object, ...]] = set()
    ip_artifact_seen: set[tuple[object, ...]] = set()
    transfer_state: dict[tuple[str, str, str], dict[str, object]] = defaultdict(
        lambda: {
            "packets": 0,
            "bytes": 0,
            "subtypes": Counter(),
            "first_packet": 0,
            "last_packet": 0,
        }
    )
    mac_to_ips: dict[str, set[str]] = defaultdict(set)
    bssid_channels: dict[str, set[int]] = defaultdict(set)
    broadcast_deauth_by_src: Counter[str] = Counter()

    checks: dict[str, list[str]] = {
        "legacy_wep_or_wpa1_detected": [],
        "open_network_exposure": [],
        "deauth_or_disassoc_flood": [],
        "possible_handshake_capture": [],
        "evil_twin_suspicion": [],
        "auth_bruteforce_or_churn": [],
        "wpa_handshake_observed": [],
        "wep_key_recovery_risk": [],
        "open_traffic_secret_exposure": [],
        "obfuscated_secret_in_open_traffic": [],
        "open_traffic_payload_visibility": [],
        "hidden_ssid_activity": [],
        "client_probe_scan_burst": [],
        "channel_hopping_or_rogue_ap": [],
        "broadcast_deauth_abuse": [],
    }
    detections: list[dict[str, object]] = []

    try:
        for pkt in reader:
            total_packets += 1
            if stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    status.update(int(min(100, (pos / size_bytes) * 100)))
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if not pkt.haslayer(Dot11):  # type: ignore[truthy-bool]
                continue

            wlan_packets += 1
            dot11 = pkt[Dot11]  # type: ignore[index]
            try:
                ftype_raw = getattr(dot11, "type", -1)
                ftype = int(-1 if ftype_raw is None else ftype_raw)
            except Exception:
                ftype = -1
            addr1 = str(getattr(dot11, "addr1", "") or "")
            addr2 = str(getattr(dot11, "addr2", "") or "")
            addr3 = str(getattr(dot11, "addr3", "") or "")
            bssid = _infer_bssid(dot11, ftype, addr1, addr2, addr3)
            signal_dbm = _extract_signal_dbm(pkt)
            try:
                subtype = int(getattr(dot11, "subtype", -1) or -1)
            except Exception:
                subtype = -1

            if ftype == 0:
                mgmt_packets += 1
                mgmt_subtype_counts[
                    DOT11_MGMT_SUBTYPE_NAMES.get(subtype, f"Mgmt-{subtype}")
                ] += 1
            elif ftype == 1:
                control_packets += 1
            elif ftype == 2:
                data_packets += 1
                src_mac = addr2 or "-"
                dst_mac = addr1 or "-"
                security_tag = "OPEN"
                try:
                    fc_val = int(getattr(dot11, "FCfield", 0) or 0)
                    if fc_val & 0x40:
                        security_tag = "PROTECTED"
                        protected_data_packets += 1
                except Exception:
                    security_tag = "OPEN"
                channel_key = (src_mac, dst_mac, security_tag)
                channel = transfer_state[channel_key]
                channel["packets"] = int(channel.get("packets", 0) or 0) + 1
                channel["subtypes"][subtype] += 1  # type: ignore[index]
                if int(channel.get("first_packet", 0) or 0) == 0:
                    channel["first_packet"] = total_packets
                channel["last_packet"] = total_packets
                if Dot11WEP is not None and pkt.haslayer(Dot11WEP):  # type: ignore[truthy-bool]
                    try:
                        wep_layer_for_size = pkt[Dot11WEP]  # type: ignore[index]
                        chan_bytes = len(
                            bytes(getattr(wep_layer_for_size, "wepdata", b"") or b"")
                        )
                    except Exception:
                        chan_bytes = 0
                else:
                    try:
                        chan_bytes = len(bytes(getattr(dot11, "payload", b"") or b""))
                    except Exception:
                        chan_bytes = 0
                channel["bytes"] = int(channel.get("bytes", 0) or 0) + int(chan_bytes)
                if src_mac and src_mac != "-":
                    src_entry = client_state[src_mac]
                    prot = src_entry.setdefault("protection", Counter())
                    if isinstance(prot, Counter):
                        prot[security_tag] += 1
                    sigs = src_entry.setdefault("signals", [])
                    if isinstance(sigs, list) and signal_dbm is not None:
                        sigs.append(signal_dbm)
                    if bssid and _is_unicast_mac(bssid):
                        bset = src_entry.get("bssids", set())
                        if isinstance(bset, set):
                            bset.add(bssid)
                if dst_mac and dst_mac != "-" and dst_mac != "ff:ff:ff:ff:ff:ff":
                    dst_entry = client_state[dst_mac]
                    sigs = dst_entry.setdefault("signals", [])
                    if isinstance(sigs, list) and signal_dbm is not None:
                        sigs.append(signal_dbm)

            if Dot11WEP is not None and pkt.haslayer(Dot11WEP):  # type: ignore[truthy-bool]
                wep_packets += 1
                try:
                    wep_layer = pkt[Dot11WEP]  # type: ignore[index]
                    iv_bytes = bytes(getattr(wep_layer, "iv", b"") or b"")
                    iv_hex = iv_bytes.hex() if iv_bytes else "-"
                    keyid = str(int(getattr(wep_layer, "keyid", 0) or 0))
                except Exception:
                    iv_hex = "-"
                    keyid = "-"
                bssid_for_wep = addr3 or addr1 or addr2 or "<unknown>"
                if bssid and _is_unicast_mac(bssid):
                    bssid_for_wep = bssid
                if iv_hex != "-":
                    wep_iv_counts[bssid_for_wep][iv_hex] += 1
                wep_keyid_counts[keyid] += 1
                if bssid_for_wep and bssid_for_wep != "<unknown>":
                    wep_packets_by_bssid[bssid_for_wep] += 1

            if EAPOL is not None and pkt.haslayer(EAPOL):  # type: ignore[truthy-bool]
                eapol_packets += 1
                bssid = addr3 or addr1 or addr2
                station = addr2 if addr2 and addr2 != bssid else addr1
                if bssid and station:
                    pair = tuple(sorted([bssid, station]))
                    eapol_pair_counts[pair] += 1
                    state = network_state.setdefault(
                        bssid,
                        {
                            "ssid": "<unknown>",
                            "channel": None,
                            "security": "UNKNOWN",
                            "phy": "Legacy/Unknown",
                            "signals": [],
                            "beacons": 0,
                            "probe_responses": 0,
                            "clients": set(),
                            "eapol": 0,
                            "first": ts,
                            "last": ts,
                        },
                    )
                    state["eapol"] = int(state.get("eapol", 0) or 0) + 1
                    if station:
                        cast = state.get("clients", set())
                        if isinstance(cast, set):
                            cast.add(station)
                    if signal_dbm is not None:
                        sigs = state.get("signals", [])
                        if isinstance(sigs, list):
                            sigs.append(signal_dbm)

            if ftype == 2:
                try:
                    fcfield = int(getattr(dot11, "FCfield", 0) or 0)
                    subtype = int(getattr(dot11, "subtype", -1) or -1)
                except Exception:
                    fcfield = 0
                    subtype = -1
                protected = bool(fcfield & 0x40)
                if not protected:
                    if subtype == 4:
                        null_data_packets += 1
                        continue
                    if subtype == 12:
                        qos_null_packets += 1
                        continue
                    open_data_packets += 1
                    try:
                        raw_payload = bytes(getattr(dot11, "payload", b"") or b"")
                    except Exception:
                        raw_payload = b""
                    open_data_bytes += len(raw_payload)
                    text_payload = _extract_text_payload(dot11)
                    if text_payload:
                        pkt_no = total_packets
                        src = addr2 or "-"
                        dst = addr1 or "-"

                        for method in HTTP_METHODS:
                            prefix = f"{method} "
                            if prefix in text_payload:
                                for line in text_payload.splitlines():
                                    if line.startswith(prefix):
                                        val = line[:220]
                                        key = ("http_request", pkt_no, src, dst, val)
                                        if key not in artifact_seen:
                                            artifact_seen.add(key)
                                            open_artifacts.append(
                                                {
                                                    "packet": pkt_no,
                                                    "src": src,
                                                    "dst": dst,
                                                    "type": "HTTP Request Line",
                                                    "value": val,
                                                }
                                            )
                                        break

                        host_match = re.search(
                            r"(?im)^host:\s*([^\r\n]{1,180})", text_payload
                        )
                        if host_match:
                            host_val = host_match.group(1).strip()
                            key = ("host", pkt_no, src, dst, host_val)
                            if key not in artifact_seen:
                                artifact_seen.add(key)
                                open_artifacts.append(
                                    {
                                        "packet": pkt_no,
                                        "src": src,
                                        "dst": dst,
                                        "type": "HTTP Host",
                                        "value": host_val,
                                    }
                                )
                                ip_match = re.findall(
                                    r"(?:\d{1,3}\.){3}\d{1,3}", host_val
                                )
                                for ip_value in ip_match:
                                    if src != "-" and ip_value:
                                        mac_to_ips[src].add(ip_value)
                                    k2 = ("host_ip", ip_value, src, dst, pkt_no)
                                    if k2 not in ip_artifact_seen:
                                        ip_artifact_seen.add(k2)
                                        recovered_ip_artifacts.append(
                                            {
                                                "packet": pkt_no,
                                                "src": src,
                                                "dst": dst,
                                                "ip": ip_value,
                                                "context": "HTTP Host",
                                            }
                                        )

                        auth_match = AUTH_RE.search(text_payload)
                        if auth_match:
                            auth_val = auth_match.group(1).strip()
                            key = ("auth", pkt_no, src, dst, auth_val)
                            if key not in secret_seen:
                                secret_seen.add(key)
                                discovered_secrets.append(
                                    {
                                        "packet": pkt_no,
                                        "src": src,
                                        "dst": dst,
                                        "indicator": "Authorization Header",
                                        "value": auth_val[:220],
                                    }
                                )

                        for match in SECRET_RE.finditer(text_payload):
                            secret_val = match.group(1).strip()
                            if not secret_val:
                                continue
                            key = ("secret", pkt_no, src, dst, secret_val)
                            if key in secret_seen:
                                continue
                            secret_seen.add(key)
                            discovered_secrets.append(
                                {
                                    "packet": pkt_no,
                                    "src": src,
                                    "dst": dst,
                                    "indicator": "Credential/Secret Pattern",
                                    "value": secret_val[:220],
                                }
                            )
                            for ip_value in re.findall(
                                r"(?:\d{1,3}\.){3}\d{1,3}", secret_val
                            ):
                                if src != "-" and ip_value:
                                    mac_to_ips[src].add(ip_value)
                                k3 = ("secret_ip", ip_value, src, dst, pkt_no)
                                if k3 not in ip_artifact_seen:
                                    ip_artifact_seen.add(k3)
                                    recovered_ip_artifacts.append(
                                        {
                                            "packet": pkt_no,
                                            "src": src,
                                            "dst": dst,
                                            "ip": ip_value,
                                            "context": "Secret Pattern",
                                        }
                                    )

                        for b64 in B64_RE.findall(text_payload):
                            key = ("b64", pkt_no, src, dst, b64)
                            if key in secret_seen:
                                continue
                            secret_seen.add(key)
                            discovered_secrets.append(
                                {
                                    "packet": pkt_no,
                                    "src": src,
                                    "dst": dst,
                                    "indicator": "Obfuscated (Base64-like)",
                                    "value": b64[:220],
                                }
                            )
                            checks["obfuscated_secret_in_open_traffic"].append(
                                f"packet={pkt_no} {src}->{dst} base64-like token"
                            )

                        for hex_blob in HEX_RE.findall(text_payload):
                            key = ("hex", pkt_no, src, dst, hex_blob)
                            if key in secret_seen:
                                continue
                            secret_seen.add(key)
                            discovered_secrets.append(
                                {
                                    "packet": pkt_no,
                                    "src": src,
                                    "dst": dst,
                                    "indicator": "Obfuscated (Hex-like)",
                                    "value": hex_blob[:220],
                                }
                            )
                            checks["obfuscated_secret_in_open_traffic"].append(
                                f"packet={pkt_no} {src}->{dst} hex-like blob"
                            )

                        if any(k in text_payload.lower() for k in KEYWORDS):
                            checks["open_traffic_secret_exposure"].append(
                                f"packet={pkt_no} {src}->{dst} contains credential keyword(s)"
                            )
                        for ip_value in IPV4_RE.findall(text_payload):
                            if src != "-":
                                mac_to_ips[src].add(ip_value)
                            if dst != "-":
                                mac_to_ips[dst].add(ip_value)

            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):  # type: ignore[truthy-bool]
                bssid = addr3 or addr2
                if not bssid:
                    continue
                ssid = "<hidden>"
                channel: Optional[int] = None
                elt = pkt.getlayer(Dot11Elt) if Dot11Elt is not None else None
                while elt is not None:
                    try:
                        eid = int(getattr(elt, "ID", -1))
                        info = bytes(getattr(elt, "info", b"") or b"")
                    except Exception:
                        eid = -1
                        info = b""
                    if eid == 0:
                        try:
                            ssid = _normalize_ssid(
                                info.decode("utf-8", errors="ignore")
                            )
                        except Exception:
                            ssid = "<hidden>"
                    elif eid == 3 and info:
                        channel = int(info[0])
                    elt = (
                        elt.payload.getlayer(Dot11Elt)
                        if getattr(elt, "payload", None) is not None
                        else None
                    )

                capability = None
                try:
                    if pkt.haslayer(Dot11Beacon):  # type: ignore[truthy-bool]
                        capability = int(getattr(pkt[Dot11Beacon], "cap", 0) or 0)  # type: ignore[index]
                    elif pkt.haslayer(Dot11ProbeResp):  # type: ignore[truthy-bool]
                        capability = int(getattr(pkt[Dot11ProbeResp], "cap", 0) or 0)  # type: ignore[index]
                except Exception:
                    capability = None
                privacy = _cap_privacy_set(capability)
                security, _has_rsn, _has_wpa_vendor = _detect_security(pkt, privacy)
                phy_protocol = _infer_phy_protocol(pkt)

                ssid_bssids[ssid].add(bssid)
                ssid_security[ssid].add(security)
                bssid_security_observed[bssid][security] += 1
                ssid_counts[ssid] += 1
                security_counts[security] += 1
                phy_counts[phy_protocol] += 1
                if channel is not None:
                    channel_counts[channel] += 1
                    bssid_channels[bssid].add(channel)

                state = network_state.setdefault(
                    bssid,
                    {
                        "ssid": ssid,
                        "channel": channel,
                        "security": security,
                        "phy": phy_protocol,
                        "signals": [],
                        "beacons": 0,
                        "probe_responses": 0,
                        "clients": set(),
                        "eapol": 0,
                        "first": ts,
                        "last": ts,
                    },
                )
                if pkt.haslayer(Dot11Beacon):  # type: ignore[truthy-bool]
                    state["beacons"] = int(state.get("beacons", 0) or 0) + 1
                else:
                    state["probe_responses"] = (
                        int(state.get("probe_responses", 0) or 0) + 1
                    )
                state["ssid"] = ssid
                if channel is not None:
                    state["channel"] = channel
                state["security"] = _prefer_security(
                    str(state.get("security", "UNKNOWN") or "UNKNOWN"), security
                )
                state["phy"] = _prefer_phy(
                    str(state.get("phy", "Legacy/Unknown") or "Legacy/Unknown"),
                    phy_protocol,
                )
                if signal_dbm is not None:
                    sigs = state.get("signals", [])
                    if isinstance(sigs, list):
                        sigs.append(signal_dbm)
                if ts is not None:
                    first = safe_float(state.get("first"))
                    last = safe_float(state.get("last"))
                    state["first"] = ts if first is None else min(first, ts)
                    state["last"] = ts if last is None else max(last, ts)

                if security in {"WEP/Unknown-Privacy", "WPA1"}:
                    checks["legacy_wep_or_wpa1_detected"].append(
                        f"{ssid} ({bssid}) security={security}"
                    )
                if security == "OPEN":
                    checks["open_network_exposure"].append(f"{ssid} ({bssid}) is open")
                if ssid == "<hidden>":
                    checks["hidden_ssid_activity"].append(
                        f"hidden SSID beacon/probe from {bssid}"
                    )

            if pkt.haslayer(Dot11ProbeReq):  # type: ignore[truthy-bool]
                if addr2:
                    entry = client_state[addr2]
                    entry["probe_requests"] = (
                        int(entry.get("probe_requests", 0) or 0) + 1
                    )

            if pkt.haslayer(Dot11Auth):  # type: ignore[truthy-bool]
                if addr2:
                    entry = client_state[addr2]
                    entry["auth_requests"] = int(entry.get("auth_requests", 0) or 0) + 1
                    if addr3:
                        bset = entry.get("bssids", set())
                        if isinstance(bset, set):
                            bset.add(addr3)

            if pkt.haslayer(Dot11AssoReq):  # type: ignore[truthy-bool]
                if addr2:
                    entry = client_state[addr2]
                    entry["assoc_requests"] = (
                        int(entry.get("assoc_requests", 0) or 0) + 1
                    )
                    if addr1:
                        bset = entry.get("bssids", set())
                        if isinstance(bset, set):
                            bset.add(addr1)
                    if addr1 in network_state:
                        cast = network_state[addr1].get("clients", set())
                        if isinstance(cast, set):
                            cast.add(addr2)

            if pkt.haslayer(Dot11Deauth):  # type: ignore[truthy-bool]
                if addr2:
                    deauth_by_src[addr2] += 1
                    entry = client_state[addr2]
                    entry["deauth_frames"] = int(entry.get("deauth_frames", 0) or 0) + 1
                    if addr1.lower() == "ff:ff:ff:ff:ff:ff":
                        broadcast_deauth_by_src[addr2] += 1
            if pkt.haslayer(Dot11Disas):  # type: ignore[truthy-bool]
                if addr2:
                    disassoc_by_src[addr2] += 1

    except Exception as exc:
        errors.append(str(exc))
    finally:
        status.finish()
        reader.close()

    for src, count in deauth_by_src.items():
        if count >= 20:
            checks["deauth_or_disassoc_flood"].append(
                f"{src} sent {count} deauth frames"
            )
    for src, count in disassoc_by_src.items():
        if count >= 20:
            checks["deauth_or_disassoc_flood"].append(
                f"{src} sent {count} disassoc frames"
            )
    for src, count in broadcast_deauth_by_src.items():
        if count >= 8:
            checks["broadcast_deauth_abuse"].append(
                f"{src} sent {count} broadcast deauth frames"
            )

    for pair, count in eapol_pair_counts.items():
        if count >= 2:
            checks["possible_handshake_capture"].append(
                f"{pair[0]}<->{pair[1]} eapol_frames={count}"
            )
            checks["wpa_handshake_observed"].append(
                f"bssid={pair[0]} station={pair[1]} eapol_frames={count}"
            )

    for ssid, bssids in ssid_bssids.items():
        if ssid == "<hidden>":
            continue
        sec_set = ssid_security.get(ssid, set())
        if len(bssids) >= 2 and len(sec_set) >= 2:
            checks["evil_twin_suspicion"].append(
                f"SSID '{ssid}' seen on {len(bssids)} BSSIDs with mixed security ({', '.join(sorted(sec_set))})"
            )

    for client, data in client_state.items():
        auth_count = int(data.get("auth_requests", 0) or 0)
        probe_count = int(data.get("probe_requests", 0) or 0)
        assoc_count = int(data.get("assoc_requests", 0) or 0)
        bssids = data.get("bssids", set())
        bssid_count = len(bssids) if isinstance(bssids, set) else 0
        if auth_count >= 10 and assoc_count == 0:
            checks["auth_bruteforce_or_churn"].append(
                f"{client} auth requests without association ({auth_count})"
            )
        elif auth_count >= 20 or bssid_count >= 10:
            checks["auth_bruteforce_or_churn"].append(
                f"{client} high WLAN auth/churn (auth={auth_count}, bssids={bssid_count})"
            )
        if probe_count >= 30 and bssid_count >= 8:
            checks["client_probe_scan_burst"].append(
                f"{client} probe burst (probes={probe_count}, bssids={bssid_count})"
            )

    for bssid, channels in bssid_channels.items():
        if len(channels) >= 4:
            checks["channel_hopping_or_rogue_ap"].append(
                f"{bssid} observed on {len(channels)} channels ({','.join(str(v) for v in sorted(channels)[:8])})"
            )

    for key, values in list(checks.items()):
        checks[key] = list(dict.fromkeys(values))

    # Finalize per-BSSID security with data-plane corroboration.
    # If a BSSID has substantial WEP-encrypted data and no EAPOL handshakes, prefer WEP label.
    for bssid, state in network_state.items():
        observed = bssid_security_observed.get(bssid, Counter())
        best_security = str(state.get("security", "UNKNOWN") or "UNKNOWN")
        if observed:
            best_security = observed.most_common(1)[0][0]
        wep_count = int(wep_packets_by_bssid.get(bssid, 0) or 0)
        eapol_count = int(state.get("eapol", 0) or 0)
        if wep_count >= 100 and eapol_count == 0:
            best_security = "WEP"
        state["security"] = best_security

    transfer_channels: list[dict[str, object]] = []
    for (src, dst, security_tag), info in transfer_state.items():
        subtype_counter = info.get("subtypes", Counter())
        subtype_text = ",".join(
            f"{stype}:{count}"
            for stype, count in sorted(
                subtype_counter.items(), key=lambda item: item[1], reverse=True
            )[:5]
        )
        transfer_channels.append(
            {
                "src": src,
                "dst": dst,
                "security": security_tag,
                "packets": int(info.get("packets", 0) or 0),
                "bytes": int(info.get("bytes", 0) or 0),
                "subtypes": subtype_text or "-",
                "first_packet": int(info.get("first_packet", 0) or 0),
                "last_packet": int(info.get("last_packet", 0) or 0),
            }
        )
    transfer_channels.sort(
        key=lambda item: int(item.get("packets", 0) or 0), reverse=True
    )

    if open_data_packets == 0 and (null_data_packets or qos_null_packets):
        checks["open_traffic_payload_visibility"].append(
            f"open frames are primarily null/qos-null keepalives (null={null_data_packets}, qos_null={qos_null_packets})"
        )

    wpa_handshakes: list[dict[str, object]] = []
    for pair, count in sorted(
        eapol_pair_counts.items(), key=lambda item: item[1], reverse=True
    ):
        if count < 2:
            continue
        wpa_handshakes.append(
            {
                "bssid": pair[0],
                "station": pair[1],
                "eapol_frames": int(count),
            }
        )

    wep_signals: list[dict[str, object]] = []
    for bssid, iv_counter in wep_iv_counts.items():
        if not iv_counter:
            continue
        unique_ivs = len(iv_counter)
        repeated = sum(1 for _iv, c in iv_counter.items() if c > 1)
        top_iv, top_iv_count = iv_counter.most_common(1)[0]
        if repeated > 0:
            checks["wep_key_recovery_risk"].append(
                f"bssid={bssid} repeated_iv_count={repeated} top_iv={top_iv}x{top_iv_count}"
            )
        wep_signals.append(
            {
                "bssid": bssid,
                "unique_ivs": unique_ivs,
                "repeated_ivs": repeated,
                "top_iv": top_iv,
                "top_iv_count": int(top_iv_count),
            }
        )
    for keyid, count in sorted(
        wep_keyid_counts.items(), key=lambda item: item[1], reverse=True
    ):
        if keyid != "-" and count > 0:
            wep_signals.append(
                {
                    "bssid": "-",
                    "unique_ivs": 0,
                    "repeated_ivs": 0,
                    "top_iv": f"keyid={keyid}",
                    "top_iv_count": int(count),
                }
            )

    networks: list[WlanNetwork] = []
    for bssid, data in network_state.items():
        clients = data.get("clients", set())
        signals = (
            [int(v) for v in data.get("signals", [])]
            if isinstance(data.get("signals"), list)
            else []
        )
        avg_signal = int(round(sum(signals) / len(signals))) if signals else None
        peak_signal = max(signals) if signals else None
        networks.append(
            WlanNetwork(
                bssid=bssid,
                ssid=str(data.get("ssid", "<unknown>") or "<unknown>"),
                channel=data.get("channel")
                if isinstance(data.get("channel"), int)
                else None,
                security=str(data.get("security", "UNKNOWN") or "UNKNOWN"),
                beacons=int(data.get("beacons", 0) or 0),
                probe_responses=int(data.get("probe_responses", 0) or 0),
                associated_clients=len(clients) if isinstance(clients, set) else 0,
                eapol_frames=int(data.get("eapol", 0) or 0),
                phy_protocol=str(data.get("phy", "Legacy/Unknown") or "Legacy/Unknown"),
                avg_signal_dbm=avg_signal,
                peak_signal_dbm=peak_signal,
                first_seen=safe_float(data.get("first")),
                last_seen=safe_float(data.get("last")),
            )
        )
    networks.sort(key=lambda item: (item.ssid.lower(), item.bssid))
    security_counts = Counter(
        item.security for item in networks if str(item.security).strip()
    )

    # Rebuild security posture checks from finalized network security labels.
    checks["open_network_exposure"] = []
    checks["legacy_wep_or_wpa1_detected"] = []
    for item in networks:
        if item.security in {"WEP", "WEP/Unknown-Privacy", "WPA1"}:
            checks["legacy_wep_or_wpa1_detected"].append(
                f"{item.ssid} ({item.bssid}) security={item.security}"
            )
        if item.security == "OPEN":
            checks["open_network_exposure"].append(
                f"{item.ssid} ({item.bssid}) is open"
            )

    clients: list[WlanClient] = []
    for mac, data in client_state.items():
        bssids = data.get("bssids", set())
        ips = tuple(sorted(mac_to_ips.get(mac, set()))[:6])
        protection_counter = data.get("protection", Counter())
        if isinstance(protection_counter, Counter) and protection_counter:
            protection = protection_counter.most_common(1)[0][0]
        else:
            protection = "-"
        signals = (
            [int(v) for v in data.get("signals", [])]
            if isinstance(data.get("signals"), list)
            else []
        )
        avg_signal = int(round(sum(signals) / len(signals))) if signals else None
        peak_signal = max(signals) if signals else None
        clients.append(
            WlanClient(
                mac=mac,
                probe_requests=int(data.get("probe_requests", 0) or 0),
                auth_requests=int(data.get("auth_requests", 0) or 0),
                assoc_requests=int(data.get("assoc_requests", 0) or 0),
                deauth_frames=int(data.get("deauth_frames", 0) or 0),
                unique_bssids=len(bssids) if isinstance(bssids, set) else 0,
                ips=ips,
                protection=protection,
                avg_signal_dbm=avg_signal,
                peak_signal_dbm=peak_signal,
            )
        )
    clients.sort(
        key=lambda item: (
            -(item.auth_requests + item.probe_requests + item.assoc_requests),
            item.mac,
        )
    )

    network_lookup = {item.bssid: item for item in networks}
    ap_client_links: list[dict[str, object]] = []
    for client in clients:
        data = client_state.get(client.mac, {})
        bssids = data.get("bssids", set()) if isinstance(data, dict) else set()
        if not isinstance(bssids, set):
            bssids = set()
        for bssid in sorted(str(v) for v in bssids if str(v).strip())[:12]:
            net = network_lookup.get(bssid)
            ap_client_links.append(
                {
                    "ap_bssid": bssid,
                    "ssid": net.ssid if net else "<unknown>",
                    "client_mac": client.mac,
                    "client_ips": ",".join(client.ips) if client.ips else "-",
                    "wireless_protocol": (
                        net.phy_protocol if net else "Legacy/Unknown"
                    ),
                    "protection": (net.security if net else client.protection),
                    "avg_signal_dbm": net.avg_signal_dbm
                    if net and net.avg_signal_dbm is not None
                    else client.avg_signal_dbm,
                    "peak_signal_dbm": net.peak_signal_dbm
                    if net and net.peak_signal_dbm is not None
                    else client.peak_signal_dbm,
                    "auth_req": client.auth_requests,
                    "assoc_req": client.assoc_requests,
                    "eapol_frames": net.eapol_frames if net else 0,
                }
            )
    ap_client_links.sort(
        key=lambda item: (
            int(item.get("assoc_req", 0) or 0),
            int(item.get("auth_req", 0) or 0),
            int(item.get("eapol_frames", 0) or 0),
        ),
        reverse=True,
    )

    ssid_details: list[dict[str, object]] = []
    for ssid, bssids in sorted(
        ssid_bssids.items(), key=lambda kv: (-(len(kv[1])), kv[0].lower())
    ):
        chans = sorted(
            {
                int(net.channel)
                for net in networks
                if net.ssid == ssid and isinstance(net.channel, int)
            }
        )
        phys = sorted(
            {
                net.phy_protocol
                for net in networks
                if net.ssid == ssid and str(net.phy_protocol).strip()
            }
        )
        sec = sorted(
            {
                net.security
                for net in networks
                if net.ssid == ssid and str(net.security).strip()
            }
        )
        ssid_details.append(
            {
                "ssid": ssid,
                "bssid_count": len(bssids),
                "security_modes": ", ".join(sec[:4]) if sec else "-",
                "channels": ",".join(str(v) for v in chans[:8]) if chans else "-",
                "phy_protocols": ", ".join(phys[:4]) if phys else "-",
                "beacons": sum(net.beacons for net in networks if net.ssid == ssid),
                "clients": sum(
                    net.associated_clients for net in networks if net.ssid == ssid
                ),
            }
        )

    bssid_details: list[dict[str, object]] = []
    for net in networks:
        bssid_details.append(
            {
                "bssid": net.bssid,
                "ssid": net.ssid,
                "channel": net.channel if net.channel is not None else "-",
                "security": net.security,
                "wireless_protocol": net.phy_protocol,
                "clients": net.associated_clients,
                "beacons": net.beacons,
                "eapol": net.eapol_frames,
                "avg_signal_dbm": net.avg_signal_dbm
                if net.avg_signal_dbm is not None
                else "-",
                "peak_signal_dbm": net.peak_signal_dbm
                if net.peak_signal_dbm is not None
                else "-",
                "first_seen": net.first_seen,
                "last_seen": net.last_seen,
            }
        )

    if checks["legacy_wep_or_wpa1_detected"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Legacy/weak WLAN security detected",
                "details": "; ".join(checks["legacy_wep_or_wpa1_detected"][:6]),
            }
        )
    if checks["open_network_exposure"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Open WLAN network exposure detected",
                "details": "; ".join(checks["open_network_exposure"][:6]),
            }
        )
    if checks["deauth_or_disassoc_flood"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Deauthentication/disassociation abuse detected",
                "details": "; ".join(checks["deauth_or_disassoc_flood"][:6]),
            }
        )
    if checks["evil_twin_suspicion"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Possible evil twin behavior detected",
                "details": "; ".join(checks["evil_twin_suspicion"][:6]),
            }
        )
    if checks["auth_bruteforce_or_churn"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "WLAN authentication churn/anomaly observed",
                "details": "; ".join(checks["auth_bruteforce_or_churn"][:6]),
            }
        )
    if checks["possible_handshake_capture"]:
        detections.append(
            {
                "severity": "info",
                "summary": "WPA/WPA2/WPA3 EAPOL handshake activity observed",
                "details": "; ".join(checks["possible_handshake_capture"][:6]),
            }
        )
    if checks["wep_key_recovery_risk"]:
        detections.append(
            {
                "severity": "high",
                "summary": "WEP IV reuse/key-recovery risk observed",
                "details": "; ".join(checks["wep_key_recovery_risk"][:6]),
            }
        )
    if checks["open_traffic_secret_exposure"] or discovered_secrets:
        details = checks["open_traffic_secret_exposure"][:4]
        if discovered_secrets:
            details.append(f"discovered_secret_items={len(discovered_secrets)}")
        detections.append(
            {
                "severity": "high",
                "summary": "Sensitive content exposed in open WLAN traffic",
                "details": "; ".join(details)[:900],
            }
        )
    if checks["obfuscated_secret_in_open_traffic"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Obfuscated secret-like material observed in open WLAN traffic",
                "details": "; ".join(checks["obfuscated_secret_in_open_traffic"][:6]),
            }
        )
    if checks["hidden_ssid_activity"]:
        detections.append(
            {
                "severity": "info",
                "summary": "Hidden SSID activity observed",
                "details": "; ".join(checks["hidden_ssid_activity"][:6]),
            }
        )
    if checks["client_probe_scan_burst"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "Potential active probing/wardriving burst observed",
                "details": "; ".join(checks["client_probe_scan_burst"][:6]),
            }
        )
    if checks["channel_hopping_or_rogue_ap"]:
        detections.append(
            {
                "severity": "warning",
                "summary": "BSSID channel-hopping/rogue AP behavior observed",
                "details": "; ".join(checks["channel_hopping_or_rogue_ap"][:6]),
            }
        )
    if checks["broadcast_deauth_abuse"]:
        detections.append(
            {
                "severity": "high",
                "summary": "Broadcast deauthentication abuse observed",
                "details": "; ".join(checks["broadcast_deauth_abuse"][:6]),
            }
        )
    protected_transfer_packets = sum(
        int(item.get("packets", 0) or 0)
        for item in transfer_channels
        if str(item.get("security", "")).upper() == "PROTECTED"
    )
    if protected_transfer_packets > 0 and open_data_packets == 0:
        detections.append(
            {
                "severity": "info",
                "summary": "Transferred content is predominantly protected 802.11 payload",
                "details": (
                    f"protected_transfer_packets={protected_transfer_packets}; "
                    f"open_data_packets={open_data_packets}; "
                    "no cleartext payload to decode in open data frames"
                ),
            }
        )

    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return WlanSummary(
        path=path,
        total_packets=total_packets,
        wlan_packets=wlan_packets,
        mgmt_packets=mgmt_packets,
        data_packets=data_packets,
        protected_data_packets=protected_data_packets,
        control_packets=control_packets,
        eapol_packets=eapol_packets,
        wep_packets=wep_packets,
        open_data_packets=open_data_packets,
        open_data_bytes=open_data_bytes,
        null_data_packets=null_data_packets,
        qos_null_packets=qos_null_packets,
        unique_networks=len(networks),
        unique_clients=len(clients),
        security_counts=security_counts,
        phy_counts=phy_counts,
        ssid_counts=ssid_counts,
        channel_counts=channel_counts,
        mgmt_subtype_counts=mgmt_subtype_counts,
        networks=networks,
        clients=clients,
        ap_client_links=ap_client_links,
        ssid_details=ssid_details,
        bssid_details=bssid_details,
        detections=detections,
        deterministic_checks=checks,
        wpa_handshakes=wpa_handshakes,
        wep_signals=wep_signals,
        open_artifacts=open_artifacts,
        discovered_secrets=discovered_secrets,
        transfer_channels=transfer_channels,
        recovered_ip_artifacts=recovered_ip_artifacts,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )


def merge_wlan_summaries(summaries: Iterable[WlanSummary]) -> WlanSummary:
    items = list(summaries)
    if not items:
        return WlanSummary(
            path=Path("ALL_PCAPS"),
            total_packets=0,
            wlan_packets=0,
            mgmt_packets=0,
            data_packets=0,
            protected_data_packets=0,
            control_packets=0,
            eapol_packets=0,
            wep_packets=0,
            open_data_packets=0,
            open_data_bytes=0,
            null_data_packets=0,
            qos_null_packets=0,
            unique_networks=0,
            unique_clients=0,
            security_counts=Counter(),
            phy_counts=Counter(),
            ssid_counts=Counter(),
            channel_counts=Counter(),
            mgmt_subtype_counts=Counter(),
            networks=[],
            clients=[],
            ap_client_links=[],
            ssid_details=[],
            bssid_details=[],
            detections=[],
            deterministic_checks={},
            wpa_handshakes=[],
            wep_signals=[],
            open_artifacts=[],
            discovered_secrets=[],
            transfer_channels=[],
            recovered_ip_artifacts=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    security_counts: Counter[str] = Counter()
    phy_counts: Counter[str] = Counter()
    ssid_counts: Counter[str] = Counter()
    channel_counts: Counter[int] = Counter()
    mgmt_subtype_counts: Counter[str] = Counter()
    detections: list[dict[str, object]] = []
    errors: list[str] = []
    checks: dict[str, list[str]] = defaultdict(list)
    all_networks: list[WlanNetwork] = []
    all_clients: list[WlanClient] = []
    all_wpa_handshakes: list[dict[str, object]] = []
    all_wep_signals: list[dict[str, object]] = []
    all_open_artifacts: list[dict[str, object]] = []
    all_discovered_secrets: list[dict[str, object]] = []
    all_transfer_channels: list[dict[str, object]] = []
    all_recovered_ip_artifacts: list[dict[str, object]] = []
    all_ap_client_links: list[dict[str, object]] = []
    all_ssid_details: list[dict[str, object]] = []
    all_bssid_details: list[dict[str, object]] = []
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    total_packets = 0
    wlan_packets = 0
    mgmt_packets = 0
    data_packets = 0
    protected_data_packets = 0
    control_packets = 0
    eapol_packets = 0
    wep_packets = 0
    open_data_packets = 0
    open_data_bytes = 0
    null_data_packets = 0
    qos_null_packets = 0

    for item in items:
        total_packets += int(item.total_packets)
        wlan_packets += int(item.wlan_packets)
        mgmt_packets += int(item.mgmt_packets)
        data_packets += int(item.data_packets)
        protected_data_packets += int(getattr(item, "protected_data_packets", 0) or 0)
        control_packets += int(item.control_packets)
        eapol_packets += int(item.eapol_packets)
        wep_packets += int(item.wep_packets)
        open_data_packets += int(getattr(item, "open_data_packets", 0) or 0)
        open_data_bytes += int(getattr(item, "open_data_bytes", 0) or 0)
        null_data_packets += int(getattr(item, "null_data_packets", 0) or 0)
        qos_null_packets += int(getattr(item, "qos_null_packets", 0) or 0)
        security_counts.update(item.security_counts)
        phy_counts.update(getattr(item, "phy_counts", Counter()) or Counter())
        ssid_counts.update(item.ssid_counts)
        channel_counts.update(item.channel_counts)
        mgmt_subtype_counts.update(
            getattr(item, "mgmt_subtype_counts", Counter()) or Counter()
        )
        all_networks.extend(item.networks)
        all_clients.extend(item.clients)
        all_wpa_handshakes.extend(getattr(item, "wpa_handshakes", []) or [])
        all_wep_signals.extend(getattr(item, "wep_signals", []) or [])
        all_open_artifacts.extend(getattr(item, "open_artifacts", []) or [])
        all_discovered_secrets.extend(getattr(item, "discovered_secrets", []) or [])
        all_transfer_channels.extend(getattr(item, "transfer_channels", []) or [])
        all_recovered_ip_artifacts.extend(
            getattr(item, "recovered_ip_artifacts", []) or []
        )
        all_ap_client_links.extend(getattr(item, "ap_client_links", []) or [])
        all_ssid_details.extend(getattr(item, "ssid_details", []) or [])
        all_bssid_details.extend(getattr(item, "bssid_details", []) or [])
        detections.extend(item.detections)
        errors.extend(item.errors)
        for key, values in (item.deterministic_checks or {}).items():
            for value in values or []:
                checks[str(key)].append(str(value))
        if item.first_seen is not None:
            first_seen = (
                item.first_seen
                if first_seen is None
                else min(first_seen, item.first_seen)
            )
        if item.last_seen is not None:
            last_seen = (
                item.last_seen if last_seen is None else max(last_seen, item.last_seen)
            )

    unique_network_keys = {(n.bssid, n.ssid) for n in all_networks}
    unique_clients = {c.mac for c in all_clients}
    duration = (
        (last_seen - first_seen)
        if first_seen is not None and last_seen is not None
        else None
    )
    return WlanSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        wlan_packets=wlan_packets,
        mgmt_packets=mgmt_packets,
        data_packets=data_packets,
        protected_data_packets=protected_data_packets,
        control_packets=control_packets,
        eapol_packets=eapol_packets,
        wep_packets=wep_packets,
        open_data_packets=open_data_packets,
        open_data_bytes=open_data_bytes,
        null_data_packets=null_data_packets,
        qos_null_packets=qos_null_packets,
        unique_networks=len(unique_network_keys),
        unique_clients=len(unique_clients),
        security_counts=security_counts,
        phy_counts=phy_counts,
        ssid_counts=ssid_counts,
        channel_counts=channel_counts,
        mgmt_subtype_counts=mgmt_subtype_counts,
        networks=all_networks,
        clients=all_clients,
        ap_client_links=all_ap_client_links,
        ssid_details=all_ssid_details,
        bssid_details=all_bssid_details,
        detections=detections,
        deterministic_checks={k: list(dict.fromkeys(v)) for k, v in checks.items()},
        wpa_handshakes=all_wpa_handshakes,
        wep_signals=all_wep_signals,
        open_artifacts=all_open_artifacts,
        discovered_secrets=all_discovered_secrets,
        transfer_channels=all_transfer_channels,
        recovered_ip_artifacts=all_recovered_ip_artifacts,
        errors=sorted(set(errors)),
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
    )
