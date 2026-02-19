from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import ipaddress
import re

from .pcap_cache import PcapMeta, get_reader
from .utils import safe_float, decode_payload, counter_inc, setdict_add, set_add_cap
import os

try:
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.layers.inet import IP, TCP  # type: ignore
    from scapy.layers.inet6 import IPv6  # type: ignore
    from scapy.packet import Raw  # type: ignore
except Exception:  # pragma: no cover
    Ether = None  # type: ignore
    IP = None  # type: ignore
    TCP = None  # type: ignore
    IPv6 = None  # type: ignore
    Raw = None  # type: ignore


FTP_CONTROL_PORTS = {21, 2100, 2121, 8021}
FTP_DATA_PORTS = {20}

FTP_COMMANDS = {
    "USER",
    "PASS",
    "ACCT",
    "CWD",
    "CDUP",
    "PWD",
    "XPWD",
    "LIST",
    "NLST",
    "MLSD",
    "MLST",
    "RETR",
    "STOR",
    "APPE",
    "DELE",
    "RMD",
    "MKD",
    "RNFR",
    "RNTO",
    "TYPE",
    "SYST",
    "FEAT",
    "STAT",
    "NOOP",
    "QUIT",
    "PASV",
    "EPSV",
    "PORT",
    "EPRT",
    "AUTH",
    "PBSZ",
    "PROT",
    "SITE",
    "OPTS",
    "HOST",
}

FTP_DATA_COMMANDS = {"LIST", "NLST", "MLSD", "MLST", "RETR", "STOR", "APPE"}

SUSPICIOUS_SITE_SUBCMDS = {"EXEC", "SYSTEM", "CHMOD", "CPFR", "CPTO"}

FTP_RESPONSE_RE = re.compile(r"^(?P<code>\d{3})(?P<sep>[ -])(?P<msg>.*)$")
HOSTNAME_RE = re.compile(r"([A-Za-z0-9.-]+\.[A-Za-z]{2,})")

MAX_FTP_UNIQUE = int(os.getenv("PCAPPER_MAX_FTP_UNIQUE", "50000"))


@dataclass(frozen=True)
class FtpCredential:
    client_ip: str
    server_ip: str
    username: Optional[str]
    password: Optional[str]
    packet_number: int
    ts: Optional[float]


@dataclass(frozen=True)
class FtpTransfer:
    client_ip: str
    server_ip: str
    direction: str
    filename: Optional[str]
    bytes: int
    data_host: Optional[str]
    data_port: Optional[int]
    first_seen: Optional[float]
    last_seen: Optional[float]
    command: Optional[str]


@dataclass(frozen=True)
class FtpSummary:
    path: Path
    total_packets: int
    ftp_packets: int
    total_bytes: int
    ftp_bytes: int
    unique_clients: int
    unique_servers: int
    client_counts: Counter[str]
    server_counts: Counter[str]
    server_ports: Counter[int]
    command_counts: Counter[str]
    response_counts: Counter[str]
    user_counts: Counter[str]
    password_counts: Counter[str]
    host_counts: Counter[str]
    banner_counts: Counter[str]
    server_software: Counter[str]
    system_types: Counter[str]
    feature_counts: Counter[str]
    suspicious_commands: Counter[str]
    mac_addresses: dict[str, set[str]]
    credential_hits: list[FtpCredential]
    transfers: list[FtpTransfer]
    detections: list[dict[str, object]]
    errors: list[str]
    first_seen: Optional[float]
    last_seen: Optional[float]
    duration_seconds: Optional[float]


def merge_ftp_summaries(
    summaries: list[FtpSummary] | tuple[FtpSummary, ...] | set[FtpSummary],
) -> FtpSummary:
    summary_list = list(summaries)
    if not summary_list:
        return FtpSummary(
            path=Path("ALL_PCAPS_0"),
            total_packets=0,
            ftp_packets=0,
            total_bytes=0,
            ftp_bytes=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            command_counts=Counter(),
            response_counts=Counter(),
            user_counts=Counter(),
            password_counts=Counter(),
            host_counts=Counter(),
            banner_counts=Counter(),
            server_software=Counter(),
            system_types=Counter(),
            feature_counts=Counter(),
            suspicious_commands=Counter(),
            mac_addresses={},
            credential_hits=[],
            transfers=[],
            detections=[],
            errors=[],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    ftp_packets = 0
    total_bytes = 0
    ftp_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    banner_counts: Counter[str] = Counter()
    server_software: Counter[str] = Counter()
    system_types: Counter[str] = Counter()
    feature_counts: Counter[str] = Counter()
    suspicious_commands: Counter[str] = Counter()
    mac_addresses: dict[str, set[str]] = defaultdict(set)

    credential_hits: list[FtpCredential] = []
    transfers: list[FtpTransfer] = []
    detections: list[dict[str, object]] = []
    errors: list[str] = []

    for summary in summary_list:
        total_packets += summary.total_packets
        ftp_packets += summary.ftp_packets
        total_bytes += summary.total_bytes
        ftp_bytes += summary.ftp_bytes

        if summary.first_seen is not None:
            first_seen = summary.first_seen if first_seen is None else min(first_seen, summary.first_seen)
        if summary.last_seen is not None:
            last_seen = summary.last_seen if last_seen is None else max(last_seen, summary.last_seen)

        client_counts.update(summary.client_counts)
        server_counts.update(summary.server_counts)
        server_ports.update(summary.server_ports)
        command_counts.update(summary.command_counts)
        response_counts.update(summary.response_counts)
        user_counts.update(summary.user_counts)
        password_counts.update(summary.password_counts)
        host_counts.update(summary.host_counts)
        banner_counts.update(summary.banner_counts)
        server_software.update(summary.server_software)
        system_types.update(summary.system_types)
        feature_counts.update(summary.feature_counts)
        suspicious_commands.update(summary.suspicious_commands)
        for ip_value, macs in summary.mac_addresses.items():
            mac_addresses[ip_value].update(macs)

        credential_hits.extend(summary.credential_hits)
        transfers.extend(summary.transfers)
        detections.extend(summary.detections)
        errors.extend(summary.errors)

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return FtpSummary(
        path=Path("ALL_PCAPS"),
        total_packets=total_packets,
        ftp_packets=ftp_packets,
        total_bytes=total_bytes,
        ftp_bytes=ftp_bytes,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        command_counts=command_counts,
        response_counts=response_counts,
        user_counts=user_counts,
        password_counts=password_counts,
        host_counts=host_counts,
        banner_counts=banner_counts,
        server_software=server_software,
        system_types=system_types,
        feature_counts=feature_counts,
        suspicious_commands=suspicious_commands,
        mac_addresses={key: set(value) for key, value in mac_addresses.items()},
        credential_hits=credential_hits,
        transfers=transfers,
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )


@dataclass
class _FlowState:
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    last_user: Optional[str] = None
    last_pass: Optional[str] = None
    pending_pasv: bool = False
    pending_data_cmd: Optional[str] = None
    pending_filename: Optional[str] = None
    last_data_host: Optional[str] = None
    last_data_port: Optional[int] = None
    banner_lines: list[str] = None
    banner_active: bool = False
    feat_active: bool = False
    feat_lines: list[str] = None
    noop_times: list[float] = None

    def __post_init__(self) -> None:
        if self.banner_lines is None:
            self.banner_lines = []
        if self.feat_lines is None:
            self.feat_lines = []
        if self.noop_times is None:
            self.noop_times = []


def _safe_decode(payload: bytes) -> str:
    return decode_payload(payload, encoding="latin-1")


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except Exception:
        return False


def _parse_ftp_response(line: str) -> Optional[tuple[str, str, str]]:
    match = FTP_RESPONSE_RE.match(line)
    if not match:
        return None
    return match.group("code"), match.group("sep"), match.group("msg")


def _parse_port_command(arg: str) -> Optional[tuple[str, int]]:
    parts = [p.strip() for p in arg.split(",") if p.strip()]
    if len(parts) != 6:
        return None
    try:
        host = ".".join(parts[:4])
        port = (int(parts[4]) * 256) + int(parts[5])
        return host, port
    except Exception:
        return None


def _parse_eprt_command(arg: str) -> Optional[tuple[str, int]]:
    match = re.match(r"^\|(?P<af>\d)\|(?P<addr>[^|]+)\|(?P<port>\d+)\|", arg)
    if not match:
        return None
    try:
        return match.group("addr"), int(match.group("port"))
    except Exception:
        return None


def _parse_pasv_response(msg: str) -> Optional[tuple[str, int]]:
    match = re.search(r"\((\d+,\d+,\d+,\d+,\d+,\d+)\)", msg)
    if not match:
        return None
    return _parse_port_command(match.group(1))


def _parse_epsv_response(msg: str) -> Optional[int]:
    match = re.search(r"\(\|\|\|(\d+)\|\)", msg)
    if not match:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _infer_flow_key(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    is_response: bool,
) -> tuple[str, str, int, int]:
    if dport in FTP_CONTROL_PORTS:
        return src, dst, sport, dport
    if sport in FTP_CONTROL_PORTS:
        return dst, src, dport, sport
    if is_response:
        return dst, src, dport, sport
    return src, dst, sport, dport


def _extract_filename(arg: str) -> Optional[str]:
    if not arg:
        return None
    token = arg.strip().strip('"').strip("'")
    if not token:
        return None
    return token


def analyze_ftp(
    path: Path,
    *,
    show_status: bool = True,
    packets: list[object] | None = None,
    meta: PcapMeta | None = None,
) -> FtpSummary:
    if TCP is None or Raw is None:
        return FtpSummary(
            path=path,
            total_packets=0,
            ftp_packets=0,
            total_bytes=0,
            ftp_bytes=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            command_counts=Counter(),
            response_counts=Counter(),
            user_counts=Counter(),
            password_counts=Counter(),
            host_counts=Counter(),
            banner_counts=Counter(),
            server_software=Counter(),
            system_types=Counter(),
            feature_counts=Counter(),
            suspicious_commands=Counter(),
            mac_addresses={},
            credential_hits=[],
            transfers=[],
            detections=[],
            errors=["Scapy not available"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    try:
        reader, status, stream, size_bytes, _file_type = get_reader(
            path, packets=packets, meta=meta, show_status=show_status
        )
    except Exception as exc:
        return FtpSummary(
            path=path,
            total_packets=0,
            ftp_packets=0,
            total_bytes=0,
            ftp_bytes=0,
            unique_clients=0,
            unique_servers=0,
            client_counts=Counter(),
            server_counts=Counter(),
            server_ports=Counter(),
            command_counts=Counter(),
            response_counts=Counter(),
            user_counts=Counter(),
            password_counts=Counter(),
            host_counts=Counter(),
            banner_counts=Counter(),
            server_software=Counter(),
            system_types=Counter(),
            feature_counts=Counter(),
            suspicious_commands=Counter(),
            mac_addresses={},
            credential_hits=[],
            transfers=[],
            detections=[],
            errors=[f"Error opening pcap: {exc}"],
            first_seen=None,
            last_seen=None,
            duration_seconds=None,
        )

    total_packets = 0
    ftp_packets = 0
    total_bytes = 0
    ftp_bytes = 0
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None

    client_counts: Counter[str] = Counter()
    server_counts: Counter[str] = Counter()
    server_ports: Counter[int] = Counter()
    command_counts: Counter[str] = Counter()
    response_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    password_counts: Counter[str] = Counter()
    host_counts: Counter[str] = Counter()
    banner_counts: Counter[str] = Counter()
    server_software: Counter[str] = Counter()
    system_types: Counter[str] = Counter()
    feature_counts: Counter[str] = Counter()
    suspicious_commands: Counter[str] = Counter()
    mac_addresses: dict[str, set[str]] = defaultdict(set)

    credential_hits: list[FtpCredential] = []
    transfers: list[FtpTransfer] = []
    detections: list[dict[str, object]] = []
    errors: list[str] = []

    flow_states: dict[tuple[str, str, int, int], _FlowState] = {}
    login_attempts: dict[tuple[str, str], dict[str, object]] = defaultdict(lambda: {"attempts": 0, "fails": 0, "users": set(), "success": 0})
    client_server_commands: dict[tuple[str, str], int] = Counter()
    client_server_failures: dict[tuple[str, str], int] = Counter()
    client_servers_seen: dict[str, set[str]] = defaultdict(set)
    username_servers: dict[str, set[str]] = defaultdict(set)
    data_expectations: list[dict[str, object]] = []
    tcp_flow_bytes: dict[tuple[str, str, int, int], int] = Counter()
    tcp_flow_first: dict[tuple[str, str, int, int], float] = {}
    tcp_flow_last: dict[tuple[str, str, int, int], float] = {}

    def _register_flow_state(key: tuple[str, str, int, int]) -> _FlowState:
        if key in flow_states:
            return flow_states[key]
        client_ip, server_ip, client_port, server_port = key
        state = _FlowState(client_ip=client_ip, server_ip=server_ip, client_port=client_port, server_port=server_port)
        flow_states[key] = state
        return state

    def _record_banner(state: _FlowState, text: str) -> None:
        banner = text.strip()
        if banner:
            counter_inc(banner_counts, banner)
            for match in HOSTNAME_RE.findall(banner):
                counter_inc(host_counts, match.lower())
            tokens = re.split(r"[;()]", banner)
            for token in tokens:
                token = token.strip()
                if not token:
                    continue
                if re.search(r"ftp|ftpd|proftpd|vsftpd|filezilla|serv-u|pure-ftpd", token, re.IGNORECASE):
                    counter_inc(server_software, token)

    def _record_mac(pkt) -> None:
        if Ether is None:
            return
        try:
            if Ether in pkt:
                src_mac = getattr(pkt[Ether], "src", None)
                dst_mac = getattr(pkt[Ether], "dst", None)
                if src_mac and IP is not None and IP in pkt:
                    setdict_add(mac_addresses, str(pkt[IP].src), str(src_mac), max_values=MAX_FTP_UNIQUE)
                if dst_mac and IP is not None and IP in pkt:
                    setdict_add(mac_addresses, str(pkt[IP].dst), str(dst_mac), max_values=MAX_FTP_UNIQUE)
        except Exception:
            return

    try:
        for pkt in reader:
            total_packets += 1
            pkt_len = int(len(pkt)) if hasattr(pkt, "__len__") else 0
            total_bytes += pkt_len

            if status.enabled and stream is not None and size_bytes:
                try:
                    pos = stream.tell()
                    percent = int(min(100, (pos / size_bytes) * 100))
                    status.update(percent)
                except Exception:
                    pass

            ts = safe_float(getattr(pkt, "time", None))
            if ts is not None:
                if first_seen is None or ts < first_seen:
                    first_seen = ts
                if last_seen is None or ts > last_seen:
                    last_seen = ts

            if IP is not None and IP in pkt:
                src_ip = str(pkt[IP].src)
                dst_ip = str(pkt[IP].dst)
            elif IPv6 is not None and IPv6 in pkt:
                src_ip = str(pkt[IPv6].src)
                dst_ip = str(pkt[IPv6].dst)
            else:
                continue

            _record_mac(pkt)

            if TCP is None or TCP not in pkt:
                continue
            tcp = pkt[TCP]
            try:
                sport = int(tcp.sport)
                dport = int(tcp.dport)
            except Exception:
                continue

            flow_key = (src_ip, dst_ip, sport, dport)
            tcp_flow_bytes[flow_key] += pkt_len
            if ts is not None:
                if flow_key not in tcp_flow_first:
                    tcp_flow_first[flow_key] = ts
                tcp_flow_last[flow_key] = ts

            if Raw not in pkt:
                continue
            try:
                payload = bytes(pkt[Raw])
            except Exception:
                continue
            if not payload:
                continue

            text = _safe_decode(payload)
            if not text:
                continue

            lines = [line.strip() for line in text.splitlines() if line.strip()]
            if not lines:
                continue

            ftp_seen = False
            for line in lines:
                response = _parse_ftp_response(line)
                is_response = response is not None
                if not is_response:
                    command = line.split(" ", 1)[0].upper()
                    if command not in FTP_COMMANDS:
                        # Allow multiline banner/feature lines without codes
                        flow_key = _infer_flow_key(src_ip, dst_ip, sport, dport, True)
                        state = _register_flow_state(flow_key)
                        if state.banner_active:
                            state.banner_lines.append(line)
                        if state.feat_active:
                            state.feat_lines.append(line)
                        continue
                if not ftp_seen:
                    ftp_packets += 1
                    ftp_bytes += len(payload)
                    ftp_seen = True

                key = _infer_flow_key(src_ip, dst_ip, sport, dport, is_response)
                state = _register_flow_state(key)

                if is_response:
                    code, sep, msg = response
                    counter_inc(response_counts, code)
                    counter_inc(server_counts, state.server_ip)
                    counter_inc(server_ports, state.server_port)
                    setdict_add(client_servers_seen, state.client_ip, state.server_ip, max_values=MAX_FTP_UNIQUE)
                    counter_inc(client_server_commands, (state.client_ip, state.server_ip), 0)

                    if code == "220":
                        if sep == "-":
                            state.banner_active = True
                            state.banner_lines.append(msg)
                        else:
                            if state.banner_active:
                                state.banner_lines.append(msg)
                                banner_text = " ".join(state.banner_lines)
                                _record_banner(state, banner_text)
                                state.banner_lines = []
                                state.banner_active = False
                            else:
                                _record_banner(state, msg)

                    if code == "215" and msg:
                        counter_inc(system_types, msg.strip())

                    if code == "211":
                        if sep == "-":
                            state.feat_active = True
                            if msg:
                                state.feat_lines.append(msg)
                        else:
                            if state.feat_active:
                                if msg:
                                    state.feat_lines.append(msg)
                                for feat in state.feat_lines:
                                    feat = feat.strip()
                                    if feat:
                                        counter_inc(feature_counts, feat)
                                state.feat_lines = []
                                state.feat_active = False
                            elif msg:
                                counter_inc(feature_counts, msg.strip())

                    if code in {"530", "430", "421"}:
                        counter_inc(client_server_failures, (state.client_ip, state.server_ip))
                        login_attempts[(state.client_ip, state.server_ip)]["fails"] = int(
                            login_attempts[(state.client_ip, state.server_ip)]["fails"]
                        ) + 1

                    if code in {"230"}:
                        login_attempts[(state.client_ip, state.server_ip)]["success"] = int(
                            login_attempts[(state.client_ip, state.server_ip)]["success"]
                        ) + 1

                    if state.pending_pasv and code == "227":
                        parsed = _parse_pasv_response(msg)
                        if parsed:
                            host, port = parsed
                            state.last_data_host = host
                            state.last_data_port = port
                            state.pending_pasv = False
                            if host and host != state.server_ip:
                                detections.append(
                                    {
                                        "severity": "medium",
                                        "summary": "FTP PASV host mismatch",
                                        "details": f"Server {state.server_ip} offered PASV host {host}:{port}",
                                        "source": "FTP",
                                    }
                                )

                    if state.pending_pasv and code == "229":
                        port = _parse_epsv_response(msg)
                        if port:
                            state.last_data_host = state.server_ip
                            state.last_data_port = port
                            state.pending_pasv = False

                    if code in {"150", "125"} and state.pending_data_cmd:
                        data_expectations.append(
                            {
                                "client_ip": state.client_ip,
                                "server_ip": state.server_ip,
                                "data_host": state.last_data_host,
                                "data_port": state.last_data_port,
                                "direction": "upload" if state.pending_data_cmd in {"STOR", "APPE"} else "download",
                                "filename": state.pending_filename,
                                "command": state.pending_data_cmd,
                                "ts": ts,
                            }
                        )
                        state.pending_data_cmd = None
                        state.pending_filename = None

                    continue

                command = line.split(" ", 1)[0].upper()
                arg = line[len(command):].strip() if len(line) > len(command) else ""
                counter_inc(command_counts, command)
                counter_inc(client_counts, state.client_ip)
                setdict_add(client_servers_seen, state.client_ip, state.server_ip, max_values=MAX_FTP_UNIQUE)
                counter_inc(client_server_commands, (state.client_ip, state.server_ip))

                if command == "NOOP" and ts is not None:
                    state.noop_times.append(ts)
                    if len(state.noop_times) > 30:
                        state.noop_times = state.noop_times[-30:]

                if command == "USER":
                    user = arg.strip()
                    if user:
                        state.last_user = user
                        counter_inc(user_counts, user)
                        login_attempts[(state.client_ip, state.server_ip)]["attempts"] = int(
                            login_attempts[(state.client_ip, state.server_ip)]["attempts"]
                        ) + 1
                        login_attempts[(state.client_ip, state.server_ip)]["users"].add(user)
                        setdict_add(username_servers, user, state.server_ip, max_values=MAX_FTP_UNIQUE)
                        if user.lower() in {"anonymous", "ftp"}:
                            detections.append(
                                {
                                    "severity": "medium",
                                    "summary": "Anonymous FTP login observed",
                                    "details": f"{state.client_ip} -> {state.server_ip} USER {user}",
                                    "source": "FTP",
                                }
                            )

                if command == "PASS":
                    password = arg.strip()
                    if password:
                        state.last_pass = password
                        counter_inc(password_counts, password)
                        credential_hits.append(
                            FtpCredential(
                                client_ip=state.client_ip,
                                server_ip=state.server_ip,
                                username=state.last_user,
                                password=password,
                                packet_number=total_packets,
                                ts=ts,
                            )
                        )
                        detections.append(
                            {
                                "severity": "high",
                                "summary": "FTP cleartext credential observed",
                                "details": f"{state.client_ip} -> {state.server_ip} USER {state.last_user or '-'} PASS {password}",
                                "source": "FTP",
                            }
                        )

                if command == "HOST" and arg:
                    counter_inc(host_counts, arg.lower())

                if command == "AUTH" and arg.upper().startswith("TLS"):
                    detections.append(
                        {
                            "severity": "info",
                            "summary": "FTP TLS upgrade requested",
                            "details": f"{state.client_ip} -> {state.server_ip} AUTH {arg}",
                            "source": "FTP",
                        }
                    )

                if command == "PASV":
                    state.pending_pasv = True

                if command == "EPSV":
                    state.pending_pasv = True

                if command == "PORT" and arg:
                    parsed = _parse_port_command(arg)
                    if parsed:
                        host, port = parsed
                        state.last_data_host = host
                        state.last_data_port = port
                        if host and host != state.client_ip:
                            detections.append(
                                {
                                    "severity": "high",
                                    "summary": "FTP PORT bounce/FXP attempt",
                                    "details": f"{state.client_ip} requested PORT {host}:{port} (server {state.server_ip})",
                                    "source": "FTP",
                                }
                            )

                if command == "EPRT" and arg:
                    parsed = _parse_eprt_command(arg)
                    if parsed:
                        host, port = parsed
                        state.last_data_host = host
                        state.last_data_port = port
                        if host and host != state.client_ip:
                            detections.append(
                                {
                                    "severity": "high",
                                    "summary": "FTP EPRT bounce/FXP attempt",
                                    "details": f"{state.client_ip} requested EPRT {host}:{port} (server {state.server_ip})",
                                    "source": "FTP",
                                }
                            )

                if command in FTP_DATA_COMMANDS:
                    state.pending_data_cmd = command
                    state.pending_filename = _extract_filename(arg)
                    if state.pending_filename and ("../" in state.pending_filename or "..\\" in state.pending_filename):
                        detections.append(
                            {
                                "severity": "high",
                                "summary": "FTP directory traversal attempt",
                                "details": f"{state.client_ip} -> {state.server_ip} {command} {state.pending_filename}",
                                "source": "FTP",
                            }
                        )

                if command == "SITE":
                    subcmd = arg.split(" ", 1)[0].upper() if arg else ""
                    if subcmd in SUSPICIOUS_SITE_SUBCMDS:
                        counter_inc(suspicious_commands, subcmd)
                        detections.append(
                            {
                                "severity": "high",
                                "summary": "Suspicious FTP SITE command",
                                "details": f"{state.client_ip} -> {state.server_ip} SITE {arg}",
                                "source": "FTP",
                            }
                        )

    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    finally:
        status.finish()
        try:
            reader.close()
        except Exception:
            pass

    used_data_flows: set[tuple[str, str, int, int]] = set()
    for expected in data_expectations:
        client_ip = expected.get("client_ip")
        server_ip = expected.get("server_ip")
        data_host = expected.get("data_host") or server_ip
        data_port = expected.get("data_port")
        if not data_port:
            continue
        matched_bytes = 0
        matched_first = None
        matched_last = None
        for flow_key, bytes_count in tcp_flow_bytes.items():
            src, dst, sport, dport = flow_key
            if flow_key in used_data_flows:
                continue
            if data_port not in (sport, dport):
                continue
            if data_host and data_host not in (src, dst):
                continue
            if client_ip and client_ip not in (src, dst):
                continue
            if server_ip and server_ip not in (src, dst):
                continue
            matched_bytes += bytes_count
            matched_first = tcp_flow_first.get(flow_key, matched_first)
            matched_last = tcp_flow_last.get(flow_key, matched_last)
            used_data_flows.add(flow_key)

        if matched_bytes > 0:
            transfers.append(
                FtpTransfer(
                    client_ip=client_ip or "-",
                    server_ip=server_ip or "-",
                    direction=expected.get("direction", "unknown"),
                    filename=expected.get("filename"),
                    bytes=matched_bytes,
                    data_host=data_host,
                    data_port=data_port,
                    first_seen=matched_first,
                    last_seen=matched_last,
                    command=expected.get("command"),
                )
            )

    for flow_key, bytes_count in tcp_flow_bytes.items():
        src, dst, sport, dport = flow_key
        if flow_key in used_data_flows:
            continue
        if sport in FTP_DATA_PORTS or dport in FTP_DATA_PORTS:
            transfers.append(
                FtpTransfer(
                    client_ip=src,
                    server_ip=dst,
                    direction="data",
                    filename=None,
                    bytes=bytes_count,
                    data_host=dst if dport in FTP_DATA_PORTS else src,
                    data_port=dport if dport in FTP_DATA_PORTS else sport,
                    first_seen=tcp_flow_first.get(flow_key),
                    last_seen=tcp_flow_last.get(flow_key),
                    command=None,
                )
            )

    for (client_ip, server_ip), stats in login_attempts.items():
        attempts = int(stats["attempts"])
        fails = int(stats["fails"])
        success = int(stats["success"])
        user_count = len(stats["users"])
        if fails >= 10 and success == 0:
            detections.append(
                {
                    "severity": "high",
                    "summary": "FTP brute-force suspected",
                    "details": f"{client_ip} -> {server_ip} failed logins: {fails} (users: {user_count})",
                    "source": "FTP",
                }
            )
        elif fails >= 10 and user_count >= 5:
            detections.append(
                {
                    "severity": "high",
                    "summary": "FTP password spraying suspected",
                    "details": f"{client_ip} -> {server_ip} failed logins: {fails} (distinct users: {user_count})",
                    "source": "FTP",
                }
            )

    for client_ip, servers in client_servers_seen.items():
        if len(servers) >= 20:
            detections.append(
                {
                    "severity": "medium",
                    "summary": "FTP scanning/probing suspected",
                    "details": f"{client_ip} touched {len(servers)} FTP servers",
                    "source": "FTP",
                }
            )

    for user, servers in username_servers.items():
        if len(servers) >= 10:
            detections.append(
                {
                    "severity": "medium",
                    "summary": "FTP credential reuse across servers",
                    "details": f"Username {user} observed on {len(servers)} servers",
                    "source": "FTP",
                }
            )

    for state in flow_states.values():
        times = state.noop_times
        if len(times) >= 6:
            intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
            if intervals:
                mean = sum(intervals) / len(intervals)
                if mean > 0:
                    variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
                    std = variance ** 0.5
                    if mean > 5 and (std / mean) < 0.2:
                        detections.append(
                            {
                                "severity": "medium",
                                "summary": "FTP beaconing-like keepalive pattern",
                                "details": f"{state.client_ip} -> {state.server_ip} NOOP interval ~{mean:.1f}s",
                                "source": "FTP",
                            }
                        )

    for transfer in transfers:
        if transfer.direction == "upload" and transfer.bytes >= 10_000_000 and _is_public_ip(transfer.server_ip):
            detections.append(
                {
                    "severity": "high",
                    "summary": "FTP possible data exfiltration",
                    "details": f"{transfer.client_ip} uploaded {transfer.bytes} bytes to {transfer.server_ip}",
                    "source": "FTP",
                }
            )

    duration_seconds = None
    if first_seen is not None and last_seen is not None:
        duration_seconds = max(0.0, last_seen - first_seen)

    return FtpSummary(
        path=path,
        total_packets=total_packets,
        ftp_packets=ftp_packets,
        total_bytes=total_bytes,
        ftp_bytes=ftp_bytes,
        unique_clients=len(client_counts),
        unique_servers=len(server_counts),
        client_counts=client_counts,
        server_counts=server_counts,
        server_ports=server_ports,
        command_counts=command_counts,
        response_counts=response_counts,
        user_counts=user_counts,
        password_counts=password_counts,
        host_counts=host_counts,
        banner_counts=banner_counts,
        server_software=server_software,
        system_types=system_types,
        feature_counts=feature_counts,
        suspicious_commands=suspicious_commands,
        mac_addresses={key: set(value) for key, value in mac_addresses.items()},
        credential_hits=credential_hits,
        transfers=sorted(transfers, key=lambda item: item.bytes, reverse=True),
        detections=detections,
        errors=errors,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration_seconds,
    )
