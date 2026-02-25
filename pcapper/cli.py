from __future__ import annotations

import argparse
from dataclasses import dataclass
import difflib
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .analyzer import analyze_pcap, merge_pcap_summaries
from .coloring import set_color_override
from .discovery import find_pcaps, is_supported_pcap
from .config import find_config, load_config
from .plugins import load_plugins, plugin_map, PluginSpec
from .reporting import (
    render_summary,
    render_vlan_summary,
    render_vlan_rollup,
    render_icmp_summary,
    render_dns_summary,
    render_beacon_summary,
    render_threats_summary,
    render_files_summary,
    render_protocols_summary,
    render_services_summary,
    render_smb_summary,
    render_ntlm_summary,
    render_netbios_summary,
    render_arp_summary,
    render_dhcp_summary,
    render_modbus_summary,
    render_modbus_rollup,
    render_dnp3_summary,
    render_dnp3_rollup,
    render_iec104_summary,
    render_bacnet_summary,
    render_enip_summary,
    render_profinet_summary,
    render_s7_summary,
    render_opc_summary,
    render_ethercat_summary,
    render_fins_summary,
    render_crimson_summary,
    render_pcworx_summary,
    render_melsec_summary,
    render_cip_summary,
    render_odesys_summary,
    render_niagara_summary,
    render_mms_summary,
    render_srtp_summary,
    render_df1_summary,
    render_pccc_summary,
    render_csp_summary,
    render_modicon_summary,
    render_yokogawa_summary,
    render_honeywell_summary,
    render_mqtt_summary,
    render_coap_summary,
    render_hart_summary,
    render_prconos_summary,
    render_iccp_summary,
    render_ips_summary,
    render_http_summary,
    render_sizes_summary,
    render_ftp_summary,
    render_nfs_summary,
    render_strings_summary,
    render_search_summary,
    render_search_rollup,
    render_creds_summary,
    render_secrets_summary,
    render_certificates_summary,
    render_health_summary,
    render_compromised_summary,
    render_hosts_summary,
    render_hostname_summary,
    render_hostdetails_summary,
    render_timeline_summary,
    render_domain_summary,
    render_ldap_summary,
    render_kerberos_summary,
    render_tls_summary,
    render_ssh_summary,
    render_rdp_summary,
    render_telnet_summary,
    render_vnc_summary,
    render_teamviewer_summary,
    render_winrm_summary,
    render_wmic_summary,
    render_powershell_summary,
    render_syslog_summary,
    render_snmp_summary,
    render_smtp_summary,
    render_rpc_summary,
    render_tcp_summary,
    render_udp_summary,
    render_udp_rollup,
    render_exfil_summary,
    render_generic_rollup,
    set_redact_secrets,
    set_verbose_output,
    render_pcapmeta_summary,
    render_quic_summary,
    render_http2_summary,
    render_encrypted_dns_summary,
    render_ntp_summary,
    render_vpn_summary,
    render_routing_summary,
    render_goose_summary,
    render_sv_summary,
    render_lldp_dcp_summary,
    render_ptp_summary,
    render_opc_classic_summary,
    render_streams_summary,
    render_ctf_summary,
    render_ioc_summary,
    render_ot_commands_summary,
    render_iec101_103_summary,
)
from .pcap_cache import load_packets_if_allowed, load_filtered_packets, get_reader, get_cache_config
from .exporting import ExportBundle, export_json, export_csv, export_sqlite
from .vlan import analyze_vlans
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
from .threats import analyze_threats, merge_threats_summaries
from .files import analyze_files, merge_files_summaries
from .protocols import analyze_protocols, merge_protocols_summaries
from .services import analyze_services, merge_services_summaries
from .smb import analyze_smb
from .ntlm import analyze_ntlm
from .netbios import analyze_netbios
from .arp import analyze_arp
from .dhcp import analyze_dhcp
from .modbus import analyze_modbus
from .dnp3 import analyze_dnp3
from .iec104 import analyze_iec104
from .bacnet import analyze_bacnet
from .enip import analyze_enip, merge_enip_summaries
from .profinet import analyze_profinet
from .s7 import analyze_s7
from .opc import analyze_opc
from .ethercat import analyze_ethercat
from .fins import analyze_fins
from .crimson import analyze_crimson
from .pcworx import analyze_pcworx
from .melsec import analyze_melsec
from .cip import analyze_cip, merge_cip_summaries
from .odesys import analyze_odesys
from .niagara import analyze_niagara
from .mms import analyze_mms
from .srtp import analyze_srtp
from .df1 import analyze_df1
from .pccc import analyze_pccc
from .csp import analyze_csp
from .modicon import analyze_modicon
from .yokogawa import analyze_yokogawa
from .honeywell import analyze_honeywell
from .mqtt import analyze_mqtt
from .coap import analyze_coap
from .hart import analyze_hart
from .prconos import analyze_prconos
from .iccp import analyze_iccp
from .ips import analyze_ips, merge_ips_summaries
from .http import analyze_http
from .sizes import analyze_sizes
from .ftp import analyze_ftp, merge_ftp_summaries
from .nfs import analyze_nfs
from .strings import analyze_strings
from .search import analyze_search
from .creds import analyze_creds
from .secrets import analyze_secrets
from .certificates import analyze_certificates
from .health import analyze_health, merge_health_summaries
from .compromised import analyze_compromised, merge_compromised_summaries
from .hosts import analyze_hosts, merge_hosts_summaries
from .hostname import analyze_hostname, merge_hostname_summaries
from .hostdetails import analyze_hostdetails, merge_hostdetails_summaries
from .timeline import analyze_timeline, merge_timeline_summaries, OT_CATEGORIES, NON_OT_CATEGORIES, TIMELINE_CATEGORIES
from .domain import analyze_domain
from .ldap import analyze_ldap
from .kerberos import analyze_kerberos
from .tls import analyze_tls
from .ssh import analyze_ssh, merge_ssh_summaries
from .rdp import analyze_rdp, merge_rdp_summaries
from .telnet import analyze_telnet, merge_telnet_summaries
from .vnc import analyze_vnc, merge_vnc_summaries
from .teamviewer import analyze_teamviewer, merge_teamviewer_summaries
from .winrm import analyze_winrm, merge_winrm_summaries
from .wmic import analyze_wmic, merge_wmic_summaries
from .powershell import analyze_powershell, merge_powershell_summaries
from .syslog import analyze_syslog
from .snmp import analyze_snmp, merge_snmp_summaries
from .smtp import analyze_smtp, merge_smtp_summaries
from .rpc import analyze_rpc, merge_rpc_summaries
from .tcp import analyze_tcp
from .udp import analyze_udp
from .exfil import analyze_exfil
from .pcapmeta import analyze_pcapmeta
from .quic import analyze_quic
from .http2 import analyze_http2
from .encrypted_dns import analyze_encrypted_dns
from .ntp import analyze_ntp
from .vpn import analyze_vpn
from .routing import analyze_routing, merge_routing_summaries
from .goose import analyze_goose
from .sv import analyze_sv
from .lldp_dcp import analyze_lldp_dcp
from .ptp import analyze_ptp
from .opc_classic import analyze_opc_classic
from .streams import analyze_streams
from .ctf import analyze_ctf
from .ioc import analyze_iocs
from .ot_commands import analyze_ot_commands, load_ot_control_config, OtControlConfig
from .iec101_103 import analyze_iec101_103
from .utils import parse_time_arg, hexdump

_PLUGIN_SPECS: list[PluginSpec] | None = None
_PLUGIN_ERRORS: list[str] = []


def _load_plugins_once() -> tuple[list[PluginSpec], list[str]]:
    global _PLUGIN_SPECS, _PLUGIN_ERRORS
    if _PLUGIN_SPECS is None:
        result = load_plugins()
        _PLUGIN_SPECS = result.plugins
        _PLUGIN_ERRORS = result.errors
    return list(_PLUGIN_SPECS), list(_PLUGIN_ERRORS)


def _builtin_flag_map() -> dict[str, str]:
    return {
        "--search": "search",
        "--packet": "packet",
        "--creds": "creds",
        "--secrets": "secrets",
        "--vlan": "vlan",
        "--icmp": "icmp",
        "--dns": "dns",
        "--http": "http",
        "--ftp": "ftp",
        "--tls": "tls",
        "--ssh": "ssh",
        "--rdp": "rdp",
        "--telnet": "telnet",
        "--vnc": "vnc",
        "--teamviewer": "teamviewer",
        "--winrm": "winrm",
        "--wmic": "wmic",
        "--powershell": "powershell",
        "--syslog": "syslog",
        "--snmp": "snmp",
        "--smtp": "smtp",
        "--rpc": "rpc",
        "--tcp": "tcp",
        "--udp": "udp",
        "--exfil": "exfil",
        "--sizes": "sizes",
        "--ips": "ips",
        "--beacon": "beacon",
        "--threats": "threats",
        "--quic": "quic",
        "--http2": "http2",
        "--encrypted-dns": "encrypted_dns",
        "--ntp": "ntp",
        "--vpn": "vpn",
        "--opc-classic": "opc_classic",
        "--streams": "streams",
        "--ctf": "ctf",
        "--ioc": "ioc",
        "--files": "files",
        "--protocols": "protocols",
        "--routing": "routing",
        "--services": "services",
        "--smb": "smb",
        "--nfs": "nfs",
        "--strings": "strings",
        "--certificates": "certificates",
        "--timeline": "timeline",
        "--domain": "domain",
        "--ldap": "ldap",
        "--kerberos": "kerberos",
        "--health": "health",
        "--hostname": "hostname",
        "--hostdetails": "hostdetails",
        "--hosts": "hosts",
        "--compromised": "compromised",
        "--ntlm": "ntlm",
        "--netbios": "netbios",
        "--arp": "arp",
        "--dhcp": "dhcp",
        "--modbus": "modbus",
        "--dnp3": "dnp3",
        "--iec104": "iec104",
        "--bacnet": "bacnet",
        "--enip": "enip",
        "--profinet": "profinet",
        "--s7": "s7",
        "--opc": "opc",
        "--ethercat": "ethercat",
        "--fins": "fins",
        "--crimson": "crimson",
        "--pcworx": "pcworx",
        "--melsec": "melsec",
        "--cip": "cip",
        "--odesys": "odesys",
        "--niagara": "niagara",
        "--mms": "mms",
        "--srtp": "srtp",
        "--df1": "df1",
        "--pccc": "pccc",
        "--csp": "csp",
        "--modicon": "modicon",
        "--yokogawa": "yokogawa",
        "--honeywell": "honeywell",
        "--mqtt": "mqtt",
        "--coap": "coap",
        "--hart": "hart",
        "--prconos": "prconos",
        "--iccp": "iccp",
        "--goose": "goose",
        "--sv": "sv",
        "--lldp": "lldp",
        "--ptp": "ptp",
        "--pcapmeta": "pcapmeta",
        "--ot-commands": "ot_commands",
        "--ot-commands-fast": "ot_commands",
        "--iec101-103": "iec101_103",
    }


def _filtered_plugins(flag_map: dict[str, str]) -> tuple[list[PluginSpec], list[str]]:
    plugins, errors = _load_plugins_once()
    seen_flags = set(flag_map.keys())
    seen_steps = set(flag_map.values())
    filtered: list[PluginSpec] = []
    for spec in plugins:
        if spec.flag in seen_flags:
            errors.append(f"plugin flag collision: {spec.flag}")
            continue
        if spec.name in seen_steps:
            errors.append(f"plugin name collision: {spec.name}")
            continue
        filtered.append(spec)
        seen_flags.add(spec.flag)
        seen_steps.add(spec.name)
    return filtered, errors


def _ordered_steps(argv: list[str], plugins: list[PluginSpec] | None = None) -> list[str]:
    flag_map = _builtin_flag_map()
    if plugins is None:
        plugins, _errors = _filtered_plugins(flag_map)
    for spec in plugins:
        flag_map[spec.flag] = spec.name
    ordered: list[str] = []
    seen: set[str] = set()
    for arg in argv:
        step = flag_map.get(arg)
        if step and step not in seen:
            ordered.append(step)
            seen.add(step)
    return ordered


def _build_banner() -> str:
    ot_ics_quotes = [
        "Safety before speed. Reliability before novelty.",
        "In OT, availability is the first control.",
        "A quiet control network is a healthy one.",
        "Know the process, not just the packets.",
        "What changes state can change safety.",
        "Latency is a signal. Jitter is a story.",
        "Every write is a decision; log it.",
        "Trust the physics, verify the traffic.",
        "Asset context turns alerts into action.",
        "A stable process leaves a stable trail.",
    ]
    override = os.environ.get("PCAPPER_QUOTE", "").strip()
    if override:
        quote = override
    else:
        seed_raw = os.environ.get("PCAPPER_QUOTE_SEED", "").strip()
        if seed_raw:
            try:
                seed_value = int(seed_raw)
            except ValueError:
                seed_value = sum(ord(ch) for ch in seed_raw)
        elif os.environ.get("PYTEST_CURRENT_TEST"):
            seed_value = 0
        else:
            seed_value = datetime.now(timezone.utc).date().toordinal()
        quote = ot_ics_quotes[seed_value % len(ot_ics_quotes)]
    banner = [
        "=====================================================================================",
        "   ██████╗  ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗     ",
        "   ██╔══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗    ",
        "   ██████╔╝██║      ███████║██████╔╝██████╔╝█████╗  ██████╔╝    ",
        "   ██╔═══╝ ██║      ██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗    ",
        "   ██║     ╚██████╗ ██║  ██║██║     ██║     ███████╗██║  ██║    ",
        "   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝ ICS/OT",
        "=====================================================================================",
        f"  PCAPPER v{__version__}  ::  Quote of the Day: \"{quote}\"",
        "=====================================================================================",
    ]
    return "\n".join(banner)


@dataclass(frozen=True)
class LogConfig:
    path: Path | None
    json: bool
    stream: Any | None = None


def _collect_argv_options(argv: list[str]) -> set[str]:
    options: set[str] = set()
    for token in argv:
        if token.startswith("-"):
            options.add(token.split("=", 1)[0])
    return options


def _coerce_config_value(action: argparse.Action, value: Any) -> Any:
    if value is None:
        return None
    if isinstance(action, argparse._StoreTrueAction):
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)
    if isinstance(action, argparse._StoreFalseAction):
        if isinstance(value, str):
            return not (value.strip().lower() in {"1", "true", "yes", "on"})
        return not bool(value)
    if action.dest == "timeline_categories" and isinstance(value, list):
        return ",".join(str(item) for item in value)
    if action.type:
        try:
            return action.type(value)
        except Exception:
            return value
    return value


def _extract_config_defaults(config: dict[str, Any]) -> dict[str, Any]:
    defaults: dict[str, Any] = {}
    if isinstance(config.get("defaults"), dict):
        defaults.update(config["defaults"])  # type: ignore[arg-type]
    for key in ("log_file", "log_json", "config"):
        if key in config:
            defaults[key] = config[key]
    logging_block = config.get("logging")
    if isinstance(logging_block, dict):
        for key in ("log_file", "log_json"):
            if key in logging_block:
                defaults[key] = logging_block[key]
    return defaults


def _apply_config_defaults(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    config: dict[str, Any],
    argv: list[str],
) -> None:
    defaults = _extract_config_defaults(config)
    if not defaults:
        return
    provided = _collect_argv_options(argv)
    for action in parser._actions:
        if not action.option_strings:
            continue
        dest = action.dest
        if dest not in defaults:
            continue
        if any(opt in provided for opt in action.option_strings):
            continue
        value = _coerce_config_value(action, defaults[dest])
        setattr(args, dest, value)


def _log_event(log_config: LogConfig | None, event: str, **fields: Any) -> None:
    if not log_config:
        return
    payload = {"ts": datetime.now(timezone.utc).isoformat(), "event": event}
    payload.update(fields)
    line = json.dumps(payload, separators=(",", ":")) if log_config.json else " ".join(
        [payload["ts"], event] + [f"{key}={value}" for key, value in fields.items()]
    )
    try:
        if log_config.path:
            log_config.path.parent.mkdir(parents=True, exist_ok=True)
            with log_config.path.open("a", encoding="utf-8") as handle:
                handle.write(f"{line}\n")
        elif log_config.stream:
            log_config.stream.write(f"{line}\n")
            log_config.stream.flush()
    except Exception:
        return


def _run_self_check(
    plugins: list[PluginSpec],
    plugin_errors: list[str],
    config_path: Path | None,
) -> int:
    print("PCAPPER SELF-CHECK")
    print("==================")
    if config_path:
        print(f"Config: {config_path}")
    else:
        print("Config: (none)")

    checks: list[tuple[str, str, str]] = []

    def _check_import(name: str, required: bool = True) -> None:
        try:
            __import__(name)
            checks.append((name, "OK", "imported"))
        except Exception as exc:
            status = "FAIL" if required else "WARN"
            checks.append((name, status, f"{type(exc).__name__}: {exc}"))

    _check_import("dpkt", required=True)
    _check_import("scapy", required=True)
    _check_import("geoip2", required=False)
    _check_import("cryptography", required=False)
    _check_import("pydicom", required=False)

    try:
        from importlib import resources as importlib_resources

        required_files = [
            "enip_mappings.json",
            "siemens_mappings.json",
            "niagara_opcodes.json",
            "odesys_opcodes.json",
        ]
        for filename in required_files:
            exists = (importlib_resources.files("pcapper") / filename).is_file()
            checks.append((filename, "OK" if exists else "WARN", "package data"))
    except Exception as exc:
        checks.append(("package-data", "WARN", f"{type(exc).__name__}: {exc}"))

    try:
        from scapy.all import conf  # type: ignore

        use_pcap = bool(getattr(conf, "use_pcap", False))
        checks.append(("libpcap", "OK" if use_pcap else "WARN", "scapy.conf.use_pcap"))
    except Exception as exc:
        checks.append(("libpcap", "WARN", f"{type(exc).__name__}: {exc}"))

    if plugin_errors:
        for err in plugin_errors:
            checks.append(("plugins", "WARN", err))
    elif plugins:
        checks.append(("plugins", "OK", f"{len(plugins)} loaded"))
    else:
        checks.append(("plugins", "OK", "none"))

    max_label = max(len(item[0]) for item in checks) if checks else 0
    failures = 0
    for name, status, detail in checks:
        if status == "FAIL":
            failures += 1
        print(f"{name:<{max_label}}  [{status}]  {detail}")

    return 1 if failures else 0


def _build_log_config(args: argparse.Namespace) -> LogConfig | None:
    path = Path(args.log_file).expanduser() if getattr(args, "log_file", None) else None
    log_json = bool(getattr(args, "log_json", False))
    if path is None and not log_json:
        return None
    stream = None if path else sys.stderr
    return LogConfig(path=path, json=log_json, stream=stream)


def _render_plugin_summary(spec: PluginSpec, summary: object, verbose: bool = False) -> str:
    if spec.render:
        try:
            return spec.render(summary, verbose=verbose)  # type: ignore[arg-type]
        except TypeError:
            return spec.render(summary)
    title = spec.title or spec.name.upper()
    return render_generic_rollup(title, [summary])


def _has_glob_wildcards(value: str) -> bool:
    return any(ch in value for ch in "*?[]")


_CASE_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_.()\\[\\]-]")
_WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _sanitize_case_name(value: str) -> str:
    raw = str(value).strip()
    if not raw:
        return "case"
    base = Path(raw).name
    base = base.replace(" ", "_")
    base = _CASE_NAME_SAFE_RE.sub("_", base)
    base = base.strip(" .")
    if not base:
        base = "case"
    stem = Path(base).stem
    if stem.upper() in _WINDOWS_RESERVED_NAMES:
        suffix = Path(base).suffix
        base = f"{stem}_"
        if suffix:
            base = f"{base}{suffix}"
    if len(base) > 80:
        base = base[:80]
    return base


def _expand_target_wildcard(pattern: Path, recursive: bool) -> list[Path]:
    expanded_pattern = str(pattern.expanduser())
    matches = [Path(value) for value in glob.glob(expanded_pattern, recursive=recursive)]

    paths: list[Path] = []
    seen: set[Path] = set()
    for matched in sorted(matches):
        candidates: list[Path]
        if matched.is_dir():
            candidates = find_pcaps(matched, recursive=recursive)
        elif is_supported_pcap(matched):
            candidates = [matched]
        else:
            candidates = []

        for candidate in candidates:
            if candidate not in seen:
                seen.add(candidate)
                paths.append(candidate)
    return paths


def _normalize_timeline_category(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _print_timeline_categories() -> None:
    print("Supported timeline categories:")
    print("Non-OT:")
    for name in sorted(NON_OT_CATEGORIES, key=str.casefold):
        print(f"  - {name}")
    print("OT/ICS:")
    for name in sorted(OT_CATEGORIES, key=str.casefold):
        print(f"  - {name}")


def _parse_timeline_categories(raw: str | None) -> tuple[set[str] | None, bool, list[str]]:
    if raw is None:
        return None, False, []

    tokens = [token.strip() for token in raw.split(",")]
    if not tokens:
        return None, True, []

    for token in tokens:
        normalized = _normalize_timeline_category(token)
        if not normalized or normalized in {"false", "no", "none", "0"}:
            return None, True, []

    supported = {
        _normalize_timeline_category(name): name for name in TIMELINE_CATEGORIES
    }
    categories: set[str] = set()
    invalid: list[str] = []
    for token in tokens:
        normalized = _normalize_timeline_category(token)
        if not normalized:
            continue
        match = supported.get(normalized)
        if match:
            categories.add(match)
        else:
            invalid.append(token)

    if not categories:
        return None, True, []

    return categories, False, invalid


class PcapperArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        if "unrecognized arguments:" in message:
            unknown = message.split("unrecognized arguments:", 1)[1].strip().split()
            options = list(getattr(self, "_option_string_actions", {}).keys())
            hints: list[str] = []
            for token in unknown:
                matches = difflib.get_close_matches(token, options, n=1, cutoff=0.7)
                if matches:
                    hints.append(f"{token} -> {matches[0]}")
            if hints:
                message = f"{message}\nDid you mean:\n  " + "\n  ".join(hints)
        super().error(message)


def build_parser(plugins: list[PluginSpec] | None = None) -> argparse.ArgumentParser:
    banner = _build_banner()
    parser = PcapperArgumentParser(
        prog="pcapper",
        description=f"{banner}\n\nModular PCAP analyzer for fast triage and reporting across IT + OT/ICS traffic.",
        formatter_class=argparse.RawTextHelpFormatter,
        allow_abbrev=False,
    )
    parser.add_argument(
        "target",
        type=Path,
        nargs="+",
        help="Path(s) to pcap/pcapng file(s), wildcard pattern(s), or director(ies) of captures.",
    )
    general = parser.add_argument_group("GENERAL FLAGS")
    general.add_argument(
        "--config",
        metavar="PATH",
        help="Path to pcapper TOML config file (defaults: ./pcapper.toml, ~/.pcapper.toml, ~/.config/pcapper/config.toml).",
    )
    general.add_argument(
        "--self-check",
        action="store_true",
        help="Run dependency and environment self-checks and exit.",
    )
    general.add_argument(
        "--list-plugins",
        action="store_true",
        help="List discovered plugins and exit.",
    )
    general.add_argument(
        "--log-file",
        metavar="PATH",
        help="Write structured log events to PATH.",
    )
    general.add_argument(
        "--log-json",
        action="store_true",
        help="Emit logs as JSON lines (default is key=value).",
    )
    general.add_argument(
        "--base",
        action="store_true",
        help="Include the standard base capture summary even when other analysis flags are used.",
    )
    general.add_argument(
        "--extract",
        metavar="FILENAME",
        help="Extract a discovered file by name into ./files (use with --files).",
    )
    general.add_argument(
        "-ip",
        dest="timeline_ip",
        help="Target IP for host-centric analysis (use with --timeline, --hostdetails, or --services; optional for --hostname).",
    )
    general.add_argument(
        "-l",
        "--limit-protocols",
        type=int,
        default=15,
        help="Number of protocols to show in the summary.",
    )
    general.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    general.add_argument(
        "--no-status",
        action="store_true",
        help="Disable the processing status bar.",
    )
    general.add_argument(
        "--profile",
        action="store_true",
        help="Enable cProfile and print a performance summary to stderr.",
    )
    general.add_argument(
        "--profile-out",
        metavar="PATH",
        help="Write cProfile stats to PATH (use with --profile).",
    )
    general.add_argument(
        "--show-secrets",
        action="store_true",
        help="Display secrets/credentials in output (default is redacted).",
    )
    general.add_argument(
        "--search",
        metavar="STRING",
        help="Search packet payloads for a string (case-insensitive) and list matches.",
    )
    general.add_argument(
        "--packet",
        metavar="N",
        type=int,
        help="Show packet N in ASCII/HEX format (1-based index).",
    )
    general.add_argument(
        "-case",
        dest="search_case",
        action="store_true",
        help="Make --search case-sensitive.",
    )
    general.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively search for pcaps when target is a directory.",
    )
    general.add_argument(
        "-summarize",
        "--summarize",
        action="store_true",
        help="Summarize supported analysis across all pcaps (e.g., --modbus, --dnp3).",
    )
    general.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose details in analysis output.",
    )
    general.add_argument(
        "-vt",
        "--vt",
        dest="vt",
        action="store_true",
        help="Enable VirusTotal lookups for DNS queries/domains and HTTP URLs/domains (requires VT_API_KEY).",
    )
    general.add_argument(
        "--view",
        metavar="FILENAME",
        help="View extracted file content in ASCII/HEX (use with --files).",
    )
    general.add_argument(
        "-raw",
        dest="view_raw",
        action="store_true",
        help="Show --view output as raw text (no ASCII/HEX).",
    )
    general.add_argument(
        "--bpf",
        metavar="EXPR",
        help="Apply a BPF filter (requires libpcap support via scapy).",
    )
    general.add_argument(
        "--timeline-bins",
        type=int,
        default=24,
        help="Number of time buckets to use for timeline OT activity sparklines.",
    )
    general.add_argument(
        "--timeline-storyline-off",
        action="store_true",
        help="Disable the OT attack storyline block in timeline output.",
    )
    general.add_argument(
        "-categories",
        "--timeline-categories",
        dest="timeline_categories",
        metavar="LIST",
        help="Comma-separated timeline event categories to include (use -categories false or empty to list supported categories).",
    )
    general.add_argument(
        "--time-start",
        metavar="TIME",
        help="Only include packets at/after this time (epoch or ISO 8601).",
    )
    general.add_argument(
        "--time-end",
        metavar="TIME",
        help="Only include packets at/before this time (epoch or ISO 8601).",
    )
    general.add_argument(
        "--json",
        metavar="PATH",
        help="Write JSON export of results to PATH.",
    )
    general.add_argument(
        "--csv",
        metavar="PATH",
        help="Write CSV export of results to PATH.",
    )
    general.add_argument(
        "--sqlite",
        metavar="PATH",
        help="Write SQLite export of results to PATH.",
    )
    export_redact_group = general.add_mutually_exclusive_group()
    export_redact_group.add_argument(
        "--export-redact",
        action="store_true",
        help="Force redaction of secrets in export outputs.",
    )
    export_redact_group.add_argument(
        "--export-raw",
        action="store_true",
        help="Disable redaction in export outputs (may include secrets).",
    )
    general.add_argument(
        "--case-dir",
        metavar="DIR",
        help="Write exports/extracted files to a case directory.",
    )
    general.add_argument(
        "--case-name",
        metavar="NAME",
        help="Optional name for the case package directory.",
    )
    general.add_argument(
        "--follow",
        metavar="FLOW",
        help="Follow a TCP stream (use with --streams). Format: src_ip:src_port->dst_ip:dst_port",
    )
    general.add_argument(
        "--follow-id",
        metavar="STREAM_ID",
        help="Follow a TCP stream by stream ID (use with --streams).",
    )
    general.add_argument(
        "--lookup-stream-id",
        metavar="STREAM_ID",
        help="Lookup a TCP stream ID and print its 5-tuple (use with --streams).",
    )
    general.add_argument(
        "--streams-full",
        action="store_true",
        help="Dump every stream line in stream analysis (not just top 10).",
    )
    general.add_argument(
        "--ioc-file",
        metavar="PATH",
        help="Path to IOC list file (use with --ioc).",
    )

    it_group = parser.add_argument_group("IT/ENTERPRISE FUNCTIONS")
    it_flags = [
        ("--arp", "Include ARP analysis (conversations, poisoning signals, anomalies, artifacts)."),
        ("--beacon", "Include beaconing analysis in the output."),
        ("--certificates", "Include TLS certificate extraction and analysis."),
        ("--creds", "Scan for credential exposure (HTTP, FTP, SMTP, DNS, etc.)."),
        ("--compromised", "Assess likely compromised hosts (multi-signal correlation)."),
        ("--secrets", "Discover reversible encoded/obfuscated secrets (base64, hex, url-encoded, JWT)."),
        ("--dhcp", "Include DHCP analysis (leases, options, clients/servers, attacks, anomalies)."),
        ("--dns", "Include DNS analysis in the output."),
        ("--domain", "Include MS AD and domain analysis (services, users, DCs, artifacts)."),
        ("--exfil", "Include exfiltration heuristics and anomaly analysis."),
        ("--files", "Include file transfer discovery in the output."),
        ("--ftp", "Include FTP analysis (credentials, transfers, threats, anomalies)."),
        ("--health", "Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs)."),
        (
            "--hostdetails",
            "Deep host-centric threat hunting/forensics for a target IP (services, peers, attacks, beaconing, exfil, artifacts; use with -ip).",
        ),
        ("--hostname", "Find hostnames for a target IP across DNS/HTTP/TLS/SMB/NetBIOS (use with -ip)."),
        ("--hosts", "Include host inventory analysis (MAC/IP/hostname/OS/ports/traffic)."),
        ("--http", "Include HTTP analysis in the output."),
        ("--icmp", "Include ICMP analysis in the output."),
        ("--ips", "Include IP address intelligence and conversation analysis."),
        ("--kerberos", "Include Kerberos analysis (requests, errors, principals, attacks)."),
        ("--ldap", "Include LDAP analysis (queries, users, servers, anomalies, secrets)."),
        ("--netbios", "Include NetBIOS name service analysis (Names, Groups, Roles)."),
        ("--nfs", "Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies)."),
        ("--ntlm", "Include NTLM authentication analysis (Users, Domains, Versions)."),
        ("--protocols", "Include detailed protocol hierarchy and anomaly analysis."),
        ("--routing", "Include routing protocol analysis (OSPF, IS-IS, BGP, RIP, EIGRP, VRRP, HSRP)."),
        ("--rdp", "Include RDP analysis (sessions, hostnames, anomalies, threats)."),
        ("--services", "Include service discovery and cybersecurity risk analysis."),
        ("--sizes", "Include packet size distribution analysis."),
        ("--smb", "Include SMB protocol analysis (Versioning, Shares, Anomalies)."),
        ("--ssh", "Include SSH analysis (sessions, versions, plaintext, anomalies)."),
        ("--strings", "Include cleartext strings extraction and anomaly analysis."),
        ("--syslog", "Include syslog analysis (messages, clients, severity, anomalies)."),
        ("--snmp", "Include SNMP analysis (versions, communities, OIDs, host details, threats)."),
        ("--smtp", "Include SMTP analysis (commands, auth, recipients, threats, exfil)."),
        ("--rpc", "Include RPC analysis (binds, interfaces, commands, threats)."),
        ("--tcp", "Include TCP analysis in the output."),
        ("--teamviewer", "Include TeamViewer analysis (sessions, hints, anomalies, threats)."),
        ("--telnet", "Include Telnet analysis (sessions, credentials, anomalies, threats)."),
        ("--threats", "Include consolidated threat detections in the output."),
        ("--quic", "Include QUIC (HTTP/3) analysis in the output."),
        ("--http2", "Include HTTP/2 analysis (cleartext/upgrade indicators)."),
        ("--encrypted-dns", "Include encrypted DNS analysis (DoH/DoT/DoQ)."),
        ("--ntp", "Include NTP analysis (versions, modes, anomalies)."),
        ("--vpn", "Include VPN/tunnel detection (IKE, IPsec, OpenVPN, WireGuard, etc)."),
        ("--timeline", "Include a threat-hunting timeline for a specific IP (use with -ip)."),
        ("--tls", "Include TLS/HTTPS analysis in the output."),
        ("--udp", "Include UDP analysis in the output."),
        ("--vlan", "Include VLAN analysis in the output."),
        ("--vnc", "Include VNC analysis (sessions, banners, anomalies, threats)."),
        ("--winrm", "Include WinRM analysis (HTTP/HTTPS, anomalies, threats)."),
        ("--wmic", "Include WMIC/WMI analysis (commands, hosts, anomalies, threats)."),
        ("--powershell", "Include PowerShell analysis (commands, artifacts, threats)."),
        ("--opc-classic", "Include OPC Classic (DCOM) analysis."),
        ("--streams", "Include TCP stream summary (use --follow for details)."),
        ("--ctf", "Include CTF flag finder and decoder analysis."),
        ("--ioc", "Include IOC matching analysis (use with --ioc-file)."),
        ("--pcapmeta", "Include pcap metadata analysis (linktype, snaplen, interfaces)."),
    ]
    for flag, help_text in sorted(it_flags, key=lambda item: item[0]):
        it_group.add_argument(flag, action="store_true", help=help_text)

    ics_group = parser.add_argument_group("OT/ICS/INDUSTRIAL FUNCTIONS")
    ics_flags = [
        ("--bacnet", "Include BACnet analysis (BVLC functions, endpoints, anomalies)."),
        ("--cip", "Include CIP analysis (object operations)."),
        ("--coap", "Include CoAP analysis (RESTful IoT/ICS)."),
        ("--crimson", "Include Crimson V3 analysis (HMI/tag traffic)."),
        ("--csp", "Include CSP analysis (ControlNet service protocol)."),
        ("--df1", "Include Allen-Bradley DF1 analysis (serial framing)."),
        ("--dnp3", "Include DNP3 protocol analysis (Functions, Restarts, File Ops)."),
        ("--enip", "Include EtherNet/IP analysis (encapsulation, sessions, I/O)."),
        ("--ethercat", "Include EtherCAT analysis (datagrams, operations)."),
        ("--fins", "Include Omron FINS analysis (commands, endpoints)."),
        ("--hart", "Include HART-IP analysis (field device communications)."),
        ("--honeywell", "Include Honeywell CDA analysis (DCS traffic)."),
        ("--iccp", "Include ICCP/TASE.2 analysis (inter-control center)."),
        ("--iec104", "Include IEC-104 analysis (APCI/ASDU, control events, anomalies)."),
        ("--melsec", "Include MELSEC-Q analysis (MC protocol)."),
        ("--mms", "Include IEC 61850 MMS analysis (substation automation)."),
        ("--modbus", "Include Modbus/TCP status and security analysis (Functions, Units, Anomalies)."),
        ("--modicon", "Include Modicon/Unity analysis (Modbus family)."),
        ("--mqtt", "Include MQTT analysis (publish/subscribe IoT/ICS)."),
        ("--niagara", "Include Niagara Fox analysis (building automation)."),
        ("--odesys", "Include ODESYS analysis (programming traffic)."),
        ("--opc", "Include OPC UA analysis (secure channel, messages)."),
        ("--pccc", "Include PCCC analysis (AB/DF1 over IP)."),
        ("--pcworx", "Include PCWorx analysis (PLC operations)."),
        ("--prconos", "Include ProConOS analysis (ProSoft protocol)."),
        ("--profinet", "Include Profinet analysis (RT/PNIO, endpoints, anomalies)."),
        ("--s7", "Include Siemens S7 analysis (TPKT/COTP, jobs, anomalies)."),
        ("--srtp", "Include GE SRTP analysis (PLC communications)."),
        ("--goose", "Include IEC 61850 GOOSE analysis (L2 events)."),
        ("--sv", "Include IEC 61850 Sampled Values analysis (L2)."),
        ("--lldp", "Include LLDP/Profinet DCP asset discovery analysis."),
        ("--ptp", "Include IEEE 1588 PTP time-sync analysis."),
        ("--ot-commands", "Include normalized OT control/write command analysis."),
        ("--ot-commands-fast", "Fast OT command scan (port heuristics + cached packets)."),
        ("--iec101-103", "Include IEC 60870-5-101/103 heuristic analysis."),
        ("--yokogawa", "Include Yokogawa Vnet/IP analysis."),
    ]
    for flag, help_text in sorted(ics_flags, key=lambda item: item[0]):
        ics_group.add_argument(flag, action="store_true", help=help_text)
    ics_group.add_argument(
        "--ot-commands-config",
        help="Path to OT command control map config (JSON/YAML).",
    )
    ics_group.add_argument(
        "--ot-commands-sessions",
        type=int,
        default=10,
        help="Limit rows in OT command sessions table (default: 10).",
    )
    if plugins is None:
        plugins, _errors = _filtered_plugins(_builtin_flag_map())
    for spec in sorted(plugins, key=lambda item: item.flag):
        group = it_group if spec.group == "it" else ics_group
        group.add_argument(
            spec.flag,
            dest=spec.dest(),
            action="store_true",
            help=spec.help,
        )
    return parser


def _analyze_paths(
    paths: list[Path],
    protocol_limit: int,
    show_base: bool,
    show_status: bool,
    search_query: str | None,
    search_case: bool,
    show_vlan: bool,
    show_icmp: bool,
    show_dns: bool,
    dns_vt: bool,
    show_http: bool,
    show_ftp: bool,
    show_tls: bool,
    show_ssh: bool,
    show_rdp: bool,
    show_telnet: bool,
    show_vnc: bool,
    show_teamviewer: bool,
    show_winrm: bool,
    show_wmic: bool,
    show_powershell: bool,
    show_syslog: bool,
    show_snmp: bool,
    show_smtp: bool,
    show_rpc: bool,
    show_tcp: bool,
    show_udp: bool,
    show_exfil: bool,
    show_sizes: bool,
    show_ips: bool,
    show_beacon: bool,
    show_threats: bool,
    show_files: bool,
    show_protocols: bool,
    show_routing: bool,
    show_services: bool,
    show_smb: bool,
    show_nfs: bool,
    show_strings: bool,
    show_creds: bool,
    show_secrets_scan: bool,
    show_secrets: bool,
    show_certificates: bool,
    show_health: bool,
    show_compromised: bool,
    show_hosts: bool,
    show_hostname: bool,
    show_hostdetails: bool,
    show_timeline: bool,
    timeline_ip: str | None,
    timeline_bins: int,
    timeline_storyline_off: bool,
    timeline_categories: set[str] | None,
    show_ntlm: bool,
    show_netbios: bool,
    show_arp: bool,
    show_modbus: bool,
    show_dnp3: bool,
    show_iec104: bool,
    show_bacnet: bool,
    show_enip: bool,
    show_profinet: bool,
    show_s7: bool,
    show_opc: bool,
    show_ethercat: bool,
    show_fins: bool,
    show_crimson: bool,
    show_pcworx: bool,
    show_melsec: bool,
    show_cip: bool,
    show_odesys: bool,
    show_niagara: bool,
    show_mms: bool,
    show_srtp: bool,
    show_df1: bool,
    show_pccc: bool,
    show_csp: bool,
    show_modicon: bool,
    show_yokogawa: bool,
    show_honeywell: bool,
    show_mqtt: bool,
    show_coap: bool,
    show_hart: bool,
    show_prconos: bool,
    show_iccp: bool,
    verbose: bool,
    extract_name: str | None,
    view_name: str | None,
    view_raw: bool,
    packet_index: int | None,
    show_domain: bool,
    show_ldap: bool,
    show_kerberos: bool,
    ordered_steps: list[str],
    summarize: bool,
    show_dhcp: bool = False,
    show_quic: bool = False,
    show_http2: bool = False,
    show_encrypted_dns: bool = False,
    show_ntp: bool = False,
    show_vpn: bool = False,
    show_goose: bool = False,
    show_sv: bool = False,
    show_lldp: bool = False,
    show_ptp: bool = False,
    show_opc_classic: bool = False,
    show_streams: bool = False,
    follow_stream: str | None = None,
    follow_stream_id: str | None = None,
    lookup_stream_id: str | None = None,
    streams_full: bool = False,
    show_ctf: bool = False,
    show_ioc: bool = False,
    ioc_file: str | None = None,
    show_pcapmeta: bool = False,
    show_ot_commands: bool = False,
    show_ot_commands_fast: bool = False,
    ot_commands_config: OtControlConfig | None = None,
    ot_commands_sessions_limit: int = 10,
    show_iec101_103: bool = False,
    bpf: str | None = None,
    time_start: float | None = None,
    time_end: float | None = None,
    export_json_path: Path | None = None,
    export_csv_path: Path | None = None,
    export_sqlite_path: Path | None = None,
    export_redact: bool = True,
    case_dir: Path | None = None,
    log_config: LogConfig | None = None,
    plugins: list[PluginSpec] | None = None,
) -> int:
    if not paths:
        return 1

    summarize_rollups = summarize and len(paths) > 0
    render_base_summary = show_base or len(ordered_steps) == 0
    base_rollups = []
    modbus_rollups = []
    dnp3_rollups = []
    rollups: dict[str, list[object]] = {}
    use_packets = len(ordered_steps) > 1 or (render_base_summary and len(ordered_steps) > 0)
    multi_export = len(paths) > 1 and not summarize
    plugin_lookup = plugin_map(plugins or [])

    if case_dir:
        case_dir.mkdir(parents=True, exist_ok=True)

    def _render_packet(path: Path, index: int, packets: list[object] | None) -> None:
        if index <= 0:
            print("--packet must be a positive integer.")
            return

        pkt = None
        if packets is not None:
            if index - 1 < len(packets):
                pkt = packets[index - 1]
            else:
                print(f"Packet {index} not found in loaded packet list.")
                return
        else:
            reader, status, _stream, _size_bytes, _file_type = get_reader(
                path,
                packets=None,
                meta=None,
                show_status=step_status,
            )
            try:
                for i, item in enumerate(reader, start=1):
                    if i == index:
                        pkt = item
                        break
            finally:
                status.finish()
                try:
                    reader.close()
                except Exception:
                    pass
            if pkt is None:
                print(f"Packet {index} not found in capture.")
                return

        raw = None
        try:
            raw = bytes(pkt)
        except Exception:
            original = getattr(pkt, "original", None)
            if isinstance(original, (bytes, bytearray)):
                raw = bytes(original)

        print("=" * 72)
        print(f"PACKET VIEW :: {path.name} :: #{index}")
        print("=" * 72)
        try:
            summary = pkt.summary()  # type: ignore[attr-defined]
        except Exception:
            summary = None
        if summary:
            print(summary)
        if raw:
            print(hexdump(raw))
        else:
            print("<packet bytes unavailable>")
        print("=" * 72)

    def _resolve_export_path(base: Path, pcap_path: Path, suffix: str) -> Path:
        if case_dir and not base.is_absolute():
            base = case_dir / base
        if base.suffix:
            if multi_export:
                out_dir = base.parent / base.stem
                out_dir.mkdir(parents=True, exist_ok=True)
                return out_dir / f"{pcap_path.stem}{base.suffix}"
            return base
        out_dir = base
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / f"{pcap_path.stem}.{suffix}"

    requested_steps = set(ordered_steps)

    def _annotate_smb_with_quic(smb_summary, quic_summary) -> None:
        if not quic_summary or not getattr(quic_summary, "quic_packets", 0):
            return
        if not hasattr(smb_summary, "analysis_notes") or smb_summary.analysis_notes is None:
            smb_summary.analysis_notes = []
        notes: list[str] = smb_summary.analysis_notes
        smb_servers = {srv.ip for srv in getattr(smb_summary, "servers", []) if getattr(srv, "ip", None)}
        smb_clients = {cli.ip for cli in getattr(smb_summary, "clients", []) if getattr(cli, "ip", None)}
        quic_servers = set(getattr(quic_summary, "servers", {}).keys())
        quic_clients = set(getattr(quic_summary, "clients", {}).keys())
        overlap_servers = smb_servers & quic_servers
        overlap_clients = smb_clients & quic_clients

        def _preview(ips: set[str]) -> str:
            if not ips:
                return "-"
            items = sorted(ips)
            if len(items) > 3:
                return ", ".join(items[:3]) + f" (+{len(items) - 3} more)"
            return ", ".join(items)

        if overlap_servers or overlap_clients:
            note = (
                "QUIC traffic observed involving SMB endpoints "
                f"(servers: {_preview(overlap_servers)}; clients: {_preview(overlap_clients)}). "
                "If SMB-over-QUIC is enabled, SMB activity may be encapsulated in QUIC and not visible in TCP SMB parsing."
            )
        else:
            note = (
                "QUIC traffic observed; SMB-over-QUIC (UDP/443) can encapsulate SMB and will not appear in TCP-based SMB parsing. "
                "Confirm SMB-over-QUIC policy or endpoint logs if suspected."
            )
        if note not in notes:
            notes.append(note)

    def _annotate_tls_with_quic(tls_summary, quic_summary) -> None:
        if not quic_summary or not getattr(quic_summary, "quic_packets", 0):
            return
        if not hasattr(tls_summary, "analysis_notes") or tls_summary.analysis_notes is None:
            tls_summary.analysis_notes = []
        notes: list[str] = tls_summary.analysis_notes
        tls_servers = set(getattr(tls_summary, "server_counts", {}).keys())
        tls_clients = set(getattr(tls_summary, "client_counts", {}).keys())
        quic_servers = set(getattr(quic_summary, "servers", {}).keys())
        quic_clients = set(getattr(quic_summary, "clients", {}).keys())
        overlap_servers = tls_servers & quic_servers
        overlap_clients = tls_clients & quic_clients

        def _preview(ips: set[str]) -> str:
            if not ips:
                return "-"
            items = sorted(ips)
            if len(items) > 3:
                return ", ".join(items[:3]) + f" (+{len(items) - 3} more)"
            return ", ".join(items)

        if overlap_servers or overlap_clients:
            note = (
                "QUIC traffic observed involving TLS endpoints "
                f"(servers: {_preview(overlap_servers)}; clients: {_preview(overlap_clients)}). "
                "HTTP/3/TLS over QUIC will not appear in TCP TLS parsing."
            )
        else:
            note = (
                "QUIC traffic observed; HTTP/3/TLS over QUIC uses UDP/443 and is not visible in TCP TLS parsing. "
                "Use --quic for QUIC metadata."
            )
        if note not in notes:
            notes.append(note)

    for idx, path in enumerate(paths, start=1):
        packets = None
        meta = None
        step_status = show_status
        export_summaries: dict[str, object] = {}
        _log_event(log_config, "pcap_start", path=str(path), index=idx, total=len(paths))

        if bpf or time_start or time_end:
            packets, meta = load_filtered_packets(
                path,
                show_status=show_status,
                bpf=bpf,
                time_start=time_start,
                time_end=time_end,
            )
        elif use_packets:
            max_file_override = None
            enabled, max_cache, _max_file = get_cache_config()
            if enabled and max_cache > 0 and use_packets:
                try:
                    size_bytes = path.stat().st_size
                except Exception:
                    size_bytes = 0
                if size_bytes and size_bytes <= max_cache:
                    max_file_override = max_cache
            packets, meta = load_packets_if_allowed(
                path,
                show_status=show_status,
                max_file_override=max_file_override,
            )
            if packets is not None:
                step_status = show_status

        if render_base_summary:
            summary = analyze_pcap(path, show_status=step_status, packets=packets, meta=meta)
            if summarize_rollups:
                base_rollups.append(summary)
            else:
                print(render_summary(summary, protocol_limit=protocol_limit))
            export_summaries["base"] = summary

        for step in ordered_steps:
            if step == "search" and search_query:
                search_summary = analyze_search(
                    path,
                    search_query,
                    show_status=step_status,
                    packets=packets,
                    meta=meta,
                    case_sensitive=search_case,
                )
                if summarize_rollups:
                    rollups.setdefault("search", []).append(search_summary)
                else:
                    print(render_search_summary(search_summary))
                export_summaries["search"] = search_summary
            elif step == "packet" and packet_index is not None:
                _render_packet(path, packet_index, packets)
            elif step == "vlan" and show_vlan:
                vlan_summary = analyze_vlans(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("vlan", []).append(vlan_summary)
                else:
                    print(render_vlan_summary(vlan_summary, verbose=verbose))
                export_summaries["vlan"] = vlan_summary
            elif step == "icmp" and show_icmp:
                icmp_summary = analyze_icmp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("icmp", []).append(icmp_summary)
                else:
                    print(render_icmp_summary(icmp_summary, verbose=verbose))
                export_summaries["icmp"] = icmp_summary
            elif step == "dns" and show_dns:
                dns_summary = analyze_dns(
                    path,
                    show_status=step_status,
                    packets=packets,
                    meta=meta,
                    vt_lookup=dns_vt,
                )
                if summarize_rollups:
                    rollups.setdefault("dns", []).append(dns_summary)
                else:
                    print(render_dns_summary(dns_summary, verbose=verbose))
                export_summaries["dns"] = dns_summary
            elif step == "http" and show_http:
                http_summary = analyze_http(
                    path,
                    show_status=step_status,
                    packets=packets,
                    meta=meta,
                    vt_lookup=dns_vt,
                )
                if summarize_rollups:
                    rollups.setdefault("http", []).append(http_summary)
                else:
                    print(render_http_summary(http_summary, verbose=verbose))
                export_summaries["http"] = http_summary
            elif step == "ftp" and show_ftp:
                ftp_summary = analyze_ftp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ftp", []).append(ftp_summary)
                else:
                    print(render_ftp_summary(ftp_summary, verbose=verbose))
                export_summaries["ftp"] = ftp_summary
            elif step == "tls" and show_tls:
                quic_summary = None
                if show_quic and "quic" in requested_steps:
                    quic_summary = export_summaries.get("quic")
                    if quic_summary is None:
                        quic_summary = analyze_quic(path, show_status=step_status)
                        export_summaries["quic"] = quic_summary
                tls_summary = analyze_tls(path, show_status=step_status, packets=packets, meta=meta)
                if quic_summary is not None:
                    _annotate_tls_with_quic(tls_summary, quic_summary)
                if summarize_rollups:
                    rollups.setdefault("tls", []).append(tls_summary)
                else:
                    print(render_tls_summary(tls_summary, verbose=verbose))
                export_summaries["tls"] = tls_summary
            elif step == "ssh" and show_ssh:
                ssh_summary = analyze_ssh(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ssh", []).append(ssh_summary)
                else:
                    print(render_ssh_summary(ssh_summary, verbose=verbose))
                export_summaries["ssh"] = ssh_summary
            elif step == "rdp" and show_rdp:
                rdp_summary = analyze_rdp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("rdp", []).append(rdp_summary)
                else:
                    print(render_rdp_summary(rdp_summary, verbose=verbose))
                export_summaries["rdp"] = rdp_summary
            elif step == "telnet" and show_telnet:
                telnet_summary = analyze_telnet(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("telnet", []).append(telnet_summary)
                else:
                    print(render_telnet_summary(telnet_summary, verbose=verbose))
                export_summaries["telnet"] = telnet_summary
            elif step == "vnc" and show_vnc:
                vnc_summary = analyze_vnc(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("vnc", []).append(vnc_summary)
                else:
                    print(render_vnc_summary(vnc_summary, verbose=verbose))
                export_summaries["vnc"] = vnc_summary
            elif step == "teamviewer" and show_teamviewer:
                tv_summary = analyze_teamviewer(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("teamviewer", []).append(tv_summary)
                else:
                    print(render_teamviewer_summary(tv_summary, verbose=verbose))
                export_summaries["teamviewer"] = tv_summary
            elif step == "winrm" and show_winrm:
                winrm_summary = analyze_winrm(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("winrm", []).append(winrm_summary)
                else:
                    print(render_winrm_summary(winrm_summary, verbose=verbose))
                export_summaries["winrm"] = winrm_summary
            elif step == "wmic" and show_wmic:
                wmic_summary = analyze_wmic(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("wmic", []).append(wmic_summary)
                else:
                    print(render_wmic_summary(wmic_summary, verbose=verbose))
                export_summaries["wmic"] = wmic_summary
            elif step == "powershell" and show_powershell:
                ps_summary = analyze_powershell(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("powershell", []).append(ps_summary)
                else:
                    print(render_powershell_summary(ps_summary, verbose=verbose))
                export_summaries["powershell"] = ps_summary
            elif step == "syslog" and show_syslog:
                syslog_summary = analyze_syslog(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("syslog", []).append(syslog_summary)
                else:
                    print(render_syslog_summary(syslog_summary, verbose=verbose))
                export_summaries["syslog"] = syslog_summary
            elif step == "snmp" and show_snmp:
                snmp_summary = analyze_snmp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("snmp", []).append(snmp_summary)
                else:
                    print(render_snmp_summary(snmp_summary, verbose=verbose))
                export_summaries["snmp"] = snmp_summary
            elif step == "smtp" and show_smtp:
                smtp_summary = analyze_smtp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("smtp", []).append(smtp_summary)
                else:
                    print(render_smtp_summary(smtp_summary, verbose=verbose))
                export_summaries["smtp"] = smtp_summary
            elif step == "rpc" and show_rpc:
                rpc_summary = analyze_rpc(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("rpc", []).append(rpc_summary)
                else:
                    print(render_rpc_summary(rpc_summary, verbose=verbose))
                export_summaries["rpc"] = rpc_summary
            elif step == "tcp" and show_tcp:
                tcp_summary = analyze_tcp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("tcp", []).append(tcp_summary)
                else:
                    print(render_tcp_summary(tcp_summary, verbose=verbose))
                export_summaries["tcp"] = tcp_summary
            elif step == "udp" and show_udp:
                udp_summary = analyze_udp(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("udp", []).append(udp_summary)
                else:
                    print(render_udp_summary(udp_summary, verbose=verbose))
                export_summaries["udp"] = udp_summary
            elif step == "exfil" and show_exfil:
                exfil_summary = analyze_exfil(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("exfil", []).append(exfil_summary)
                else:
                    print(render_exfil_summary(exfil_summary, verbose=verbose))
                export_summaries["exfil"] = exfil_summary
            elif step == "sizes" and show_sizes:
                size_summary = analyze_sizes(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("sizes", []).append(size_summary)
                else:
                    print(render_sizes_summary(size_summary, verbose=verbose))
                export_summaries["sizes"] = size_summary
            elif step == "ips" and show_ips:
                ips_summary = analyze_ips(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ips", []).append(ips_summary)
                else:
                    print(render_ips_summary(ips_summary, verbose=verbose))
                export_summaries["ips"] = ips_summary
            elif step == "beacon" and show_beacon:
                beacon_summary = analyze_beacons(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("beacon", []).append(beacon_summary)
                else:
                    print(render_beacon_summary(beacon_summary, verbose=verbose))
                export_summaries["beacon"] = beacon_summary
            elif step == "threats" and show_threats:
                threat_summary = analyze_threats(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("threats", []).append(threat_summary)
                else:
                    print(render_threats_summary(threat_summary, verbose=verbose))
                export_summaries["threats"] = threat_summary
            elif step == "quic" and show_quic:
                quic_summary = export_summaries.get("quic")
                if quic_summary is None:
                    quic_summary = analyze_quic(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("quic", []).append(quic_summary)
                else:
                    print(render_quic_summary(quic_summary))
                export_summaries["quic"] = quic_summary
            elif step == "http2" and show_http2:
                http2_summary = analyze_http2(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("http2", []).append(http2_summary)
                else:
                    print(render_http2_summary(http2_summary))
                export_summaries["http2"] = http2_summary
            elif step == "encrypted_dns" and show_encrypted_dns:
                edns_summary = analyze_encrypted_dns(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("encrypted_dns", []).append(edns_summary)
                else:
                    print(render_encrypted_dns_summary(edns_summary))
                export_summaries["encrypted_dns"] = edns_summary
            elif step == "ntp" and show_ntp:
                ntp_summary = analyze_ntp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ntp", []).append(ntp_summary)
                else:
                    print(render_ntp_summary(ntp_summary))
                export_summaries["ntp"] = ntp_summary
            elif step == "vpn" and show_vpn:
                vpn_summary = analyze_vpn(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("vpn", []).append(vpn_summary)
                else:
                    print(render_vpn_summary(vpn_summary))
                export_summaries["vpn"] = vpn_summary
            elif step == "files" and show_files:
                files_summary = analyze_files(
                    path,
                    extract_name=extract_name,
                    output_dir=(case_dir / "files") if case_dir else None,
                    view_name=view_name,
                    view_raw=view_raw,
                    show_status=step_status,
                    include_x509=verbose,
                )
                if summarize_rollups:
                    rollups.setdefault("files", []).append(files_summary)
                else:
                    print(render_files_summary(files_summary, verbose=verbose))
                export_summaries["files"] = files_summary
            elif step == "protocols" and show_protocols:
                proto_summary = analyze_protocols(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("protocols", []).append(proto_summary)
                else:
                    print(render_protocols_summary(proto_summary, verbose=verbose))
                export_summaries["protocols"] = proto_summary
            elif step == "routing" and show_routing:
                routing_summary = analyze_routing(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("routing", []).append(routing_summary)
                else:
                    print(render_routing_summary(routing_summary, verbose=verbose))
                export_summaries["routing"] = routing_summary
            elif step == "services" and show_services:
                svc_summary = analyze_services(path, show_status=step_status, filter_ip=timeline_ip)
                if summarize_rollups:
                    rollups.setdefault("services", []).append(svc_summary)
                else:
                    print(render_services_summary(svc_summary))
                export_summaries["services"] = svc_summary
            elif step == "smb" and show_smb:
                quic_summary = None
                if show_quic and "quic" in requested_steps:
                    quic_summary = export_summaries.get("quic")
                    if quic_summary is None:
                        quic_summary = analyze_quic(path, show_status=step_status)
                        export_summaries["quic"] = quic_summary
                smb_summary = analyze_smb(path, show_status=step_status)
                if quic_summary is not None:
                    _annotate_smb_with_quic(smb_summary, quic_summary)
                if summarize_rollups:
                    rollups.setdefault("smb", []).append(smb_summary)
                else:
                    print(render_smb_summary(smb_summary, verbose=verbose))
                export_summaries["smb"] = smb_summary
            elif step == "nfs" and show_nfs:
                nfs_summary = analyze_nfs(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("nfs", []).append(nfs_summary)
                else:
                    print(render_nfs_summary(nfs_summary))
                export_summaries["nfs"] = nfs_summary
            elif step == "strings" and show_strings:
                strings_summary = analyze_strings(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("strings", []).append(strings_summary)
                else:
                    print(render_strings_summary(strings_summary))
                export_summaries["strings"] = strings_summary
            elif step == "creds" and show_creds:
                creds_summary = analyze_creds(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("creds", []).append(creds_summary)
                else:
                    print(render_creds_summary(creds_summary, show_secrets=show_secrets))
                export_summaries["creds"] = creds_summary
            elif step == "secrets" and show_secrets_scan:
                secrets_summary = analyze_secrets(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("secrets", []).append(secrets_summary)
                else:
                    print(render_secrets_summary(secrets_summary, show_secrets=show_secrets))
                export_summaries["secrets"] = secrets_summary
            elif step == "certificates" and show_certificates:
                cert_summary = analyze_certificates(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("certificates", []).append(cert_summary)
                else:
                    print(render_certificates_summary(cert_summary))
                export_summaries["certificates"] = cert_summary
            elif step == "health" and show_health:
                health_summary = analyze_health(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("health", []).append(health_summary)
                else:
                    print(render_health_summary(health_summary))
                export_summaries["health"] = health_summary
            elif step == "compromised" and show_compromised:
                compromised_summary = analyze_compromised(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("compromised", []).append(compromised_summary)
                else:
                    print(render_compromised_summary(compromised_summary, verbose=verbose))
                export_summaries["compromised"] = compromised_summary
            elif step == "pcapmeta" and show_pcapmeta:
                meta_summary = analyze_pcapmeta(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("pcapmeta", []).append(meta_summary)
                else:
                    print(render_pcapmeta_summary(meta_summary))
                export_summaries["pcapmeta"] = meta_summary
            elif step == "streams" and show_streams:
                stream_summary = analyze_streams(
                    path,
                    show_status=step_status,
                    packets=packets,
                    meta=meta,
                    follow=follow_stream,
                    follow_id=follow_stream_id,
                    lookup_id=lookup_stream_id,
                    streams_full=streams_full,
                )
                if summarize_rollups:
                    rollups.setdefault("streams", []).append(stream_summary)
                else:
                    print(render_streams_summary(stream_summary))
                export_summaries["streams"] = stream_summary
            elif step == "ctf" and show_ctf:
                ctf_summary = analyze_ctf(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ctf", []).append(ctf_summary)
                else:
                    print(render_ctf_summary(ctf_summary))
                export_summaries["ctf"] = ctf_summary
            elif step == "ioc" and show_ioc and ioc_file:
                ioc_summary = analyze_iocs(path, Path(ioc_file), show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ioc", []).append(ioc_summary)
                else:
                    print(render_ioc_summary(ioc_summary))
                export_summaries["ioc"] = ioc_summary
            elif step == "opc_classic" and show_opc_classic:
                opc_summary = analyze_opc_classic(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("opc_classic", []).append(opc_summary)
                else:
                    print(render_opc_classic_summary(opc_summary))
                export_summaries["opc_classic"] = opc_summary
            elif step == "hosts" and show_hosts:
                hosts_summary = analyze_hosts(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("hosts", []).append(hosts_summary)
                else:
                    print(render_hosts_summary(hosts_summary, verbose=verbose))
                export_summaries["hosts"] = hosts_summary
            elif step == "hostname" and show_hostname:
                hostname_summary = analyze_hostname(path, timeline_ip, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("hostname", []).append(hostname_summary)
                else:
                    print(render_hostname_summary(hostname_summary, verbose=verbose))
                export_summaries["hostname"] = hostname_summary
            elif step == "hostdetails" and show_hostdetails and timeline_ip:
                hostdetails_summary = analyze_hostdetails(path, timeline_ip, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("hostdetails", []).append(hostdetails_summary)
                else:
                    print(render_hostdetails_summary(hostdetails_summary, verbose=verbose))
                export_summaries["hostdetails"] = hostdetails_summary
            elif step == "timeline" and show_timeline and timeline_ip:
                timeline_summary = analyze_timeline(
                    path,
                    timeline_ip,
                    show_status=step_status,
                    timeline_bins=timeline_bins,
                    timeline_storyline_off=timeline_storyline_off,
                    categories=timeline_categories,
                )
                if summarize_rollups:
                    rollups.setdefault("timeline", []).append(timeline_summary)
                else:
                    print(render_timeline_summary(timeline_summary, verbose=verbose))
                export_summaries["timeline"] = timeline_summary
            elif step == "domain" and show_domain:
                domain_summary = analyze_domain(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("domain", []).append(domain_summary)
                else:
                    print(render_domain_summary(domain_summary))
                export_summaries["domain"] = domain_summary
            elif step == "ldap" and show_ldap:
                ldap_summary = analyze_ldap(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ldap", []).append(ldap_summary)
                else:
                    print(render_ldap_summary(ldap_summary))
                export_summaries["ldap"] = ldap_summary
            elif step == "kerberos" and show_kerberos:
                kerberos_summary = analyze_kerberos(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("kerberos", []).append(kerberos_summary)
                else:
                    print(render_kerberos_summary(kerberos_summary))
                export_summaries["kerberos"] = kerberos_summary
            elif step == "ntlm" and show_ntlm:
                ntlm_summary = analyze_ntlm(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ntlm", []).append(ntlm_summary)
                else:
                    print(render_ntlm_summary(ntlm_summary))
                export_summaries["ntlm"] = ntlm_summary
            elif step == "netbios" and show_netbios:
                nb_summary = analyze_netbios(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("netbios", []).append(nb_summary)
                else:
                    print(render_netbios_summary(nb_summary))
                export_summaries["netbios"] = nb_summary
            elif step == "arp" and show_arp:
                arp_summary = analyze_arp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("arp", []).append(arp_summary)
                else:
                    print(render_arp_summary(arp_summary, verbose=verbose))
                export_summaries["arp"] = arp_summary
            elif step == "dhcp" and show_dhcp:
                dhcp_summary = analyze_dhcp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("dhcp", []).append(dhcp_summary)
                else:
                    print(render_dhcp_summary(dhcp_summary, verbose=verbose))
                export_summaries["dhcp"] = dhcp_summary
            elif step == "modbus" and show_modbus:
                modbus_summary = analyze_modbus(path, show_status=step_status)
                if summarize_rollups:
                    modbus_rollups.append(modbus_summary)
                else:
                    print(render_modbus_summary(modbus_summary, verbose=verbose))
                export_summaries["modbus"] = modbus_summary
            elif step == "dnp3" and show_dnp3:
                dnp3_summary = analyze_dnp3(path, show_status=step_status)
                if summarize_rollups:
                    dnp3_rollups.append(dnp3_summary)
                else:
                    print(render_dnp3_summary(dnp3_summary))
                export_summaries["dnp3"] = dnp3_summary
            elif step == "iec104" and show_iec104:
                summary = analyze_iec104(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("iec104", []).append(summary)
                else:
                    print(render_iec104_summary(summary))
                export_summaries["iec104"] = summary
            elif step == "bacnet" and show_bacnet:
                summary = analyze_bacnet(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("bacnet", []).append(summary)
                else:
                    print(render_bacnet_summary(summary))
                export_summaries["bacnet"] = summary
            elif step == "enip" and show_enip:
                summary = analyze_enip(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("enip", []).append(summary)
                else:
                    print(render_enip_summary(summary))
                export_summaries["enip"] = summary
            elif step == "profinet" and show_profinet:
                summary = analyze_profinet(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("profinet", []).append(summary)
                else:
                    print(render_profinet_summary(summary))
                export_summaries["profinet"] = summary
            elif step == "s7" and show_s7:
                summary = analyze_s7(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("s7", []).append(summary)
                else:
                    print(render_s7_summary(summary))
                export_summaries["s7"] = summary
            elif step == "opc" and show_opc:
                summary = analyze_opc(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("opc", []).append(summary)
                else:
                    print(render_opc_summary(summary))
                export_summaries["opc"] = summary
            elif step == "ethercat" and show_ethercat:
                summary = analyze_ethercat(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ethercat", []).append(summary)
                else:
                    print(render_ethercat_summary(summary))
                export_summaries["ethercat"] = summary
            elif step == "fins" and show_fins:
                summary = analyze_fins(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("fins", []).append(summary)
                else:
                    print(render_fins_summary(summary))
                export_summaries["fins"] = summary
            elif step == "crimson" and show_crimson:
                summary = analyze_crimson(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("crimson", []).append(summary)
                else:
                    print(render_crimson_summary(summary))
                export_summaries["crimson"] = summary
            elif step == "pcworx" and show_pcworx:
                summary = analyze_pcworx(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("pcworx", []).append(summary)
                else:
                    print(render_pcworx_summary(summary))
                export_summaries["pcworx"] = summary
            elif step == "melsec" and show_melsec:
                summary = analyze_melsec(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("melsec", []).append(summary)
                else:
                    print(render_melsec_summary(summary))
                export_summaries["melsec"] = summary
            elif step == "cip" and show_cip:
                summary = analyze_cip(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("cip", []).append(summary)
                else:
                    print(render_cip_summary(summary))
                export_summaries["cip"] = summary
            elif step == "odesys" and show_odesys:
                summary = analyze_odesys(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("odesys", []).append(summary)
                else:
                    print(render_odesys_summary(summary))
                export_summaries["odesys"] = summary
            elif step == "niagara" and show_niagara:
                summary = analyze_niagara(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("niagara", []).append(summary)
                else:
                    print(render_niagara_summary(summary))
                export_summaries["niagara"] = summary
            elif step == "mms" and show_mms:
                summary = analyze_mms(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("mms", []).append(summary)
                else:
                    print(render_mms_summary(summary))
                export_summaries["mms"] = summary
            elif step == "srtp" and show_srtp:
                summary = analyze_srtp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("srtp", []).append(summary)
                else:
                    print(render_srtp_summary(summary))
                export_summaries["srtp"] = summary
            elif step == "df1" and show_df1:
                summary = analyze_df1(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("df1", []).append(summary)
                else:
                    print(render_df1_summary(summary))
                export_summaries["df1"] = summary
            elif step == "pccc" and show_pccc:
                summary = analyze_pccc(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("pccc", []).append(summary)
                else:
                    print(render_pccc_summary(summary))
                export_summaries["pccc"] = summary
            elif step == "csp" and show_csp:
                summary = analyze_csp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("csp", []).append(summary)
                else:
                    print(render_csp_summary(summary))
                export_summaries["csp"] = summary
            elif step == "modicon" and show_modicon:
                summary = analyze_modicon(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("modicon", []).append(summary)
                else:
                    print(render_modicon_summary(summary))
                export_summaries["modicon"] = summary
            elif step == "yokogawa" and show_yokogawa:
                summary = analyze_yokogawa(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("yokogawa", []).append(summary)
                else:
                    print(render_yokogawa_summary(summary))
                export_summaries["yokogawa"] = summary
            elif step == "honeywell" and show_honeywell:
                summary = analyze_honeywell(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("honeywell", []).append(summary)
                else:
                    print(render_honeywell_summary(summary))
                export_summaries["honeywell"] = summary
            elif step == "mqtt" and show_mqtt:
                summary = analyze_mqtt(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("mqtt", []).append(summary)
                else:
                    print(render_mqtt_summary(summary))
                export_summaries["mqtt"] = summary
            elif step == "coap" and show_coap:
                summary = analyze_coap(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("coap", []).append(summary)
                else:
                    print(render_coap_summary(summary))
                export_summaries["coap"] = summary
            elif step == "hart" and show_hart:
                summary = analyze_hart(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("hart", []).append(summary)
                else:
                    print(render_hart_summary(summary))
                export_summaries["hart"] = summary
            elif step == "prconos" and show_prconos:
                summary = analyze_prconos(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("prconos", []).append(summary)
                else:
                    print(render_prconos_summary(summary))
                export_summaries["prconos"] = summary
            elif step == "iccp" and show_iccp:
                summary = analyze_iccp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("iccp", []).append(summary)
                else:
                    print(render_iccp_summary(summary))
                export_summaries["iccp"] = summary
            elif step == "goose" and show_goose:
                summary = analyze_goose(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("goose", []).append(summary)
                else:
                    print(render_goose_summary(summary))
                export_summaries["goose"] = summary
            elif step == "sv" and show_sv:
                summary = analyze_sv(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("sv", []).append(summary)
                else:
                    print(render_sv_summary(summary))
                export_summaries["sv"] = summary
            elif step == "lldp" and show_lldp:
                summary = analyze_lldp_dcp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("lldp", []).append(summary)
                else:
                    print(render_lldp_dcp_summary(summary))
                export_summaries["lldp"] = summary
            elif step == "ptp" and show_ptp:
                summary = analyze_ptp(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("ptp", []).append(summary)
                else:
                    print(render_ptp_summary(summary))
                export_summaries["ptp"] = summary
            elif step == "ot_commands" and show_ot_commands:
                summary = analyze_ot_commands(
                    path,
                    show_status=step_status,
                    fast=show_ot_commands_fast,
                    config=ot_commands_config,
                )
                if summarize_rollups:
                    rollups.setdefault("ot_commands", []).append(summary)
                else:
                    print(render_ot_commands_summary(summary, session_limit=ot_commands_sessions_limit))
                export_summaries["ot_commands"] = summary
            elif step == "iec101_103" and show_iec101_103:
                summary = analyze_iec101_103(path, show_status=step_status)
                if summarize_rollups:
                    rollups.setdefault("iec101_103", []).append(summary)
                else:
                    print(render_iec101_103_summary(summary))
                export_summaries["iec101_103"] = summary
            elif step in plugin_lookup:
                spec = plugin_lookup[step]
                if spec.analyze is None:
                    continue
                summary = spec.analyze(path, show_status=step_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault(step, []).append(summary)
                else:
                    print(_render_plugin_summary(spec, summary, verbose=verbose))
                export_summaries[spec.export_key or spec.name] = summary
        if (export_json_path or export_csv_path or export_sqlite_path) and not summarize_rollups:
            bundle = ExportBundle(path=path, summaries=export_summaries)
            if export_json_path:
                export_json(bundle, _resolve_export_path(export_json_path, path, "json"), redact=export_redact)
            if export_csv_path:
                export_csv(bundle, _resolve_export_path(export_csv_path, path, "csv"), redact=export_redact)
            if export_sqlite_path:
                export_sqlite(bundle, _resolve_export_path(export_sqlite_path, path, "sqlite"), redact=export_redact)

        _log_event(
            log_config,
            "pcap_end",
            path=str(path),
            index=idx,
            total=len(paths),
            summaries=sorted(export_summaries.keys()),
        )
        if idx < len(paths):
            print()

    if summarize_rollups:
        if base_rollups:
            merged_base = merge_pcap_summaries(base_rollups)
            print(render_summary(merged_base, protocol_limit=protocol_limit))
            if rollups or modbus_rollups or dnp3_rollups:
                print()
        merge_handlers: dict[str, tuple[callable, callable]] = {
            "ips": (merge_ips_summaries, lambda s: render_ips_summary(s, verbose=verbose)),
            "timeline": (merge_timeline_summaries, lambda s: render_timeline_summary(s, verbose=verbose)),
            "compromised": (merge_compromised_summaries, lambda s: render_compromised_summary(s, verbose=verbose)),
            "hosts": (merge_hosts_summaries, lambda s: render_hosts_summary(s, verbose=verbose)),
            "hostname": (merge_hostname_summaries, lambda s: render_hostname_summary(s, verbose=verbose)),
            "hostdetails": (merge_hostdetails_summaries, lambda s: render_hostdetails_summary(s, verbose=verbose)),
            "ftp": (merge_ftp_summaries, lambda s: render_ftp_summary(s, verbose=verbose)),
            "ssh": (merge_ssh_summaries, lambda s: render_ssh_summary(s, verbose=verbose)),
            "protocols": (merge_protocols_summaries, lambda s: render_protocols_summary(s, verbose=verbose)),
            "routing": (merge_routing_summaries, lambda s: render_routing_summary(s, verbose=verbose)),
            "services": (merge_services_summaries, render_services_summary),
            "health": (merge_health_summaries, render_health_summary),
            "rdp": (merge_rdp_summaries, lambda s: render_rdp_summary(s, verbose=verbose)),
            "telnet": (merge_telnet_summaries, lambda s: render_telnet_summary(s, verbose=verbose)),
            "vnc": (merge_vnc_summaries, lambda s: render_vnc_summary(s, verbose=verbose)),
            "teamviewer": (merge_teamviewer_summaries, lambda s: render_teamviewer_summary(s, verbose=verbose)),
            "winrm": (merge_winrm_summaries, lambda s: render_winrm_summary(s, verbose=verbose)),
            "wmic": (merge_wmic_summaries, lambda s: render_wmic_summary(s, verbose=verbose)),
            "powershell": (merge_powershell_summaries, lambda s: render_powershell_summary(s, verbose=verbose)),
            "threats": (merge_threats_summaries, lambda s: render_threats_summary(s, verbose=verbose)),
            "snmp": (merge_snmp_summaries, lambda s: render_snmp_summary(s, verbose=verbose)),
            "smtp": (merge_smtp_summaries, lambda s: render_smtp_summary(s, verbose=verbose)),
            "rpc": (merge_rpc_summaries, lambda s: render_rpc_summary(s, verbose=verbose)),
            "enip": (merge_enip_summaries, render_enip_summary),
            "cip": (merge_cip_summaries, render_cip_summary),
            "files": (merge_files_summaries, lambda s: render_files_summary(s, verbose=verbose)),
        }
        title_map = {
            "search": "SEARCH RESULTS",
            "vlan": "VLAN ANALYSIS",
            "icmp": "ICMP ANALYSIS",
            "dns": "DNS ANALYSIS",
            "http": "HTTP ANALYSIS",
            "ftp": "FTP ANALYSIS",
            "tls": "TLS/HTTPS ANALYSIS",
            "ssh": "SSH ANALYSIS",
            "rdp": "RDP ANALYSIS",
            "telnet": "TELNET ANALYSIS",
            "vnc": "VNC ANALYSIS",
            "teamviewer": "TEAMVIEWER ANALYSIS",
            "winrm": "WINRM ANALYSIS",
            "wmic": "WMIC/WMI ANALYSIS",
            "powershell": "POWERSHELL ANALYSIS",
            "syslog": "SYSLOG ANALYSIS",
            "snmp": "SNMP ANALYSIS",
            "smtp": "SMTP ANALYSIS",
            "rpc": "RPC ANALYSIS",
            "tcp": "TCP ANALYSIS",
            "udp": "UDP ANALYSIS",
            "exfil": "EXFILTRATION ANALYSIS",
            "sizes": "PACKET SIZE ANALYSIS",
            "ips": "IP INTELLIGENCE ANALYSIS",
            "beacon": "BEACON ANALYSIS",
            "threats": "THREAT DETECTIONS",
            "quic": "QUIC ANALYSIS",
            "http2": "HTTP/2 ANALYSIS",
            "encrypted_dns": "ENCRYPTED DNS ANALYSIS",
            "ntp": "NTP ANALYSIS",
            "vpn": "VPN/TUNNEL ANALYSIS",
            "files": "FILE TRANSFER ANALYSIS",
            "protocols": "PROTOCOL ANALYSIS",
            "routing": "ROUTING ANALYSIS",
            "services": "SERVICE ANALYSIS",
            "smb": "SMB ANALYSIS",
            "nfs": "NFS ANALYSIS",
            "strings": "STRINGS ANALYSIS",
            "creds": "CREDENTIAL EXPOSURE",
            "secrets": "SECRET DISCOVERY",
            "certificates": "CERTIFICATE ANALYSIS",
            "health": "TRAFFIC HEALTH ANALYSIS",
            "compromised": "COMPROMISE ASSESSMENT",
            "hosts": "HOST INVENTORY",
            "hostname": "HOSTNAME DISCOVERY",
            "hostdetails": "HOST DETAILS",
            "timeline": "TIMELINE ANALYSIS",
            "domain": "DOMAIN ANALYSIS",
            "ldap": "LDAP ANALYSIS",
            "kerberos": "KERBEROS ANALYSIS",
            "ntlm": "NTLM ANALYSIS",
            "netbios": "NETBIOS ANALYSIS",
            "arp": "ARP ANALYSIS",
            "dhcp": "DHCP ANALYSIS",
            "iec104": "IEC-104 ANALYSIS",
            "bacnet": "BACNET ANALYSIS",
            "enip": "ETHERNET/IP ANALYSIS",
            "profinet": "PROFINET ANALYSIS",
            "s7": "S7 ANALYSIS",
            "opc": "OPC UA ANALYSIS",
            "ethercat": "ETHERCAT ANALYSIS",
            "fins": "FINS ANALYSIS",
            "crimson": "CRIMSON V3 ANALYSIS",
            "pcworx": "PCWORX ANALYSIS",
            "melsec": "MELSEC-Q ANALYSIS",
            "cip": "CIP ANALYSIS",
            "odesys": "ODESYS ANALYSIS",
            "niagara": "NIAGARA FOX ANALYSIS",
            "mms": "IEC 61850 MMS ANALYSIS",
            "srtp": "GE SRTP ANALYSIS",
            "df1": "DF1 ANALYSIS",
            "pccc": "PCCC ANALYSIS",
            "csp": "CSP ANALYSIS",
            "modicon": "MODICON ANALYSIS",
            "yokogawa": "YOKOGAWA VNET/IP ANALYSIS",
            "honeywell": "HONEYWELL CDA ANALYSIS",
            "mqtt": "MQTT ANALYSIS",
            "coap": "COAP ANALYSIS",
            "hart": "HART-IP ANALYSIS",
            "prconos": "PROCONOS ANALYSIS",
            "iccp": "ICCP/TASE.2 ANALYSIS",
            "goose": "GOOSE ANALYSIS",
            "sv": "SV ANALYSIS",
            "lldp": "LLDP/DCP ANALYSIS",
            "ptp": "PTP ANALYSIS",
            "opc_classic": "OPC CLASSIC ANALYSIS",
            "streams": "STREAM ANALYSIS",
            "ctf": "CTF ANALYSIS",
            "ioc": "IOC ANALYSIS",
            "pcapmeta": "PCAP METADATA",
            "ot_commands": "OT COMMANDS",
            "iec101_103": "IEC 101/103 ANALYSIS",
        }
        for spec in plugin_lookup.values():
            title_map.setdefault(spec.name, spec.title or spec.name.upper())
            if spec.merge and spec.render:
                merge_handlers[spec.name] = (
                    spec.merge,
                    lambda s, _spec=spec: _render_plugin_summary(_spec, s, verbose=verbose),
                )
        ordered_rollups = [step for step in ordered_steps if rollups.get(step)]
        for step in ordered_rollups:
            if step in ("modbus", "dnp3", "vlan"):
                continue
            if rollups.get(step):
                if step == "search":
                    print(render_search_rollup(rollups[step]))
                elif step == "udp":
                    print(render_udp_rollup(rollups[step], verbose=verbose))
                elif step in merge_handlers:
                    merge_fn, render_fn = merge_handlers[step]
                    merged = merge_fn(rollups[step])
                    print(render_fn(merged))
                else:
                    print(render_generic_rollup(title_map.get(step, step.upper()), rollups[step]))
                print()
        if rollups.get("vlan"):
            print(render_vlan_rollup(rollups["vlan"], verbose=verbose))
            print()
        if show_modbus and modbus_rollups:
            print(render_modbus_rollup(modbus_rollups))
            if show_dnp3 and dnp3_rollups:
                print()
        if show_dnp3 and dnp3_rollups:
            print(render_dnp3_rollup(dnp3_rollups))
        if (export_json_path or export_csv_path or export_sqlite_path):
            merged_summaries: dict[str, object] = {}
            if base_rollups:
                merged_summaries["base"] = merge_pcap_summaries(base_rollups)
            for key, values in rollups.items():
                if key in plugin_lookup and plugin_lookup[key].merge:
                    spec = plugin_lookup[key]
                    merged_summaries[spec.export_key or spec.name] = spec.merge(values)
                else:
                    merged_summaries[key] = values
            bundle = ExportBundle(path=Path("ALL_PCAPS"), summaries=merged_summaries)
            if export_json_path:
                export_json(bundle, export_json_path, redact=export_redact)
            if export_csv_path:
                export_csv(bundle, export_csv_path, redact=export_redact)
            if export_sqlite_path:
                export_sqlite(bundle, export_sqlite_path, redact=export_redact)
    return 0


def main() -> int:
    plugins, plugin_errors = _filtered_plugins(_builtin_flag_map())
    parser = build_parser(plugins)
    if len(sys.argv) == 1:
        print(_build_banner())
        print("Usage: pcapper <target> [options]")
        print("Run with -h for full help and options.")
        return 0
    args = parser.parse_args()
    config_path = find_config(getattr(args, "config", None) or os.environ.get("PCAPPER_CONFIG"))
    config_result = load_config(config_path)
    _apply_config_defaults(parser, args, config_result.data, sys.argv[1:])
    log_config = _build_log_config(args)
    _log_event(log_config, "start", version=__version__, config=str(config_result.path) if config_result.path else "")
    print(_build_banner())

    if getattr(args, "list_plugins", False):
        if plugin_errors:
            print("Plugin load warnings:")
            for err in plugin_errors:
                print(f"  - {err}")
        if not plugins:
            print("No plugins discovered.")
        else:
            print("Plugins:")
            for spec in sorted(plugins, key=lambda item: item.flag):
                print(f"  {spec.flag} -> {spec.name} ({spec.group})")
        _log_event(log_config, "list_plugins", count=len(plugins))
        return 0

    if getattr(args, "self_check", False):
        result = _run_self_check(plugins, plugin_errors, config_result.path)
        _log_event(log_config, "self_check", status="ok" if result == 0 else "fail")
        return result

    ordered_steps = _ordered_steps(sys.argv, plugins)
    builtin_steps = list(dict.fromkeys(_builtin_flag_map().values()))
    for step in builtin_steps:
        value = getattr(args, step, None)
        if step not in ordered_steps:
            if isinstance(value, bool) and value:
                ordered_steps.append(step)
            elif value is not None and not isinstance(value, bool):
                ordered_steps.append(step)
    for spec in plugins:
        if getattr(args, spec.dest(), False) and spec.name not in ordered_steps:
            ordered_steps.append(spec.name)

    if getattr(args, "ot_commands_fast", False):
        args.ot_commands = True

    timeline_categories, show_category_list, invalid_categories = _parse_timeline_categories(
        getattr(args, "timeline_categories", None)
    )
    if show_category_list:
        _print_timeline_categories()
        return 0
    if invalid_categories:
        invalid_text = ", ".join(item.strip() for item in invalid_categories if item.strip())
        if invalid_text:
            print(f"Unknown timeline categories: {invalid_text}")
        _print_timeline_categories()
        return 2

    if args.no_color:
        set_color_override(False)
    set_redact_secrets(not args.show_secrets)
    set_verbose_output(args.verbose)
    if getattr(args, "vt", False) and not args.dns:
        args.dns = True
    if getattr(args, "vt", False) and "dns" not in ordered_steps:
        ordered_steps.append("dns")

    if args.limit_protocols <= 0:
        print("--limit-protocols must be a positive integer.")
        return 2
    if getattr(args, "packet", None) is not None and args.packet <= 0:
        print("--packet must be a positive integer.")
        return 2
    if getattr(args, "ot_commands_sessions", 10) <= 0:
        print("--ot-commands-sessions must be a positive integer.")
        return 2
    if args.timeline_bins <= 0:
        print("--timeline-bins must be a positive integer.")
        return 2
    if args.profile_out and not args.profile:
        print("--profile-out requires --profile.")
        return 2

    if args.timeline and not args.timeline_ip:
        print("Timeline analysis requires a target IP. Use -ip <address> with --timeline.")
        return 2
    if args.hostdetails and not args.timeline_ip:
        print("Host details analysis requires a target IP. Use -ip <address> with --hostdetails.")
        return 2
    if args.ioc and not args.ioc_file:
        print("IOC analysis requires --ioc-file <path>.")
        return 2
    if getattr(args, "follow", None) and getattr(args, "follow_id", None):
        print("Use only one of --follow or --follow-id.")
        return 2
    if getattr(args, "lookup_stream_id", None) and not getattr(args, "streams", False):
        print("--lookup-stream-id requires --streams.")
        return 2

    time_start = parse_time_arg(getattr(args, "time_start", None))
    time_end = parse_time_arg(getattr(args, "time_end", None))
    if (args.time_start and time_start is None) or (args.time_end and time_end is None):
        print("Invalid --time-start or --time-end format. Use epoch seconds or ISO 8601 (e.g. 2025-01-01T00:00:00Z).")
        return 2

    ot_commands_config: OtControlConfig | None = None
    if getattr(args, "ot_commands_config", None):
        try:
            ot_commands_config = load_ot_control_config(Path(args.ot_commands_config).expanduser())
        except Exception as exc:
            print(f"Invalid --ot-commands-config: {exc}")
            return 2

    case_dir = Path(args.case_dir).expanduser() if getattr(args, "case_dir", None) else None
    if case_dir:
        if args.case_name:
            safe_name = _sanitize_case_name(args.case_name)
            case_dir = case_dir / safe_name

    raw_targets = args.target if isinstance(args.target, list) else [args.target]
    paths: list[Path] = []
    seen_paths: set[Path] = set()

    for raw_target in raw_targets:
        target = Path(raw_target).expanduser()

        if _has_glob_wildcards(str(raw_target)):
            wildcard_paths = _expand_target_wildcard(Path(raw_target), recursive=args.recursive)
            if not wildcard_paths:
                print(f"No pcap/pcapng files found matching pattern: {raw_target}")
                return 2
            for path in wildcard_paths:
                if path not in seen_paths:
                    seen_paths.add(path)
                    paths.append(path)
            continue

        if not target.exists():
            print(f"Target not found: {raw_target}")
            return 2

        if target.is_file():
            if not is_supported_pcap(target):
                print("Target is not a supported pcap/pcapng file.")
                return 2
            resolved = target
            if resolved not in seen_paths:
                seen_paths.add(resolved)
                paths.append(resolved)
            continue

        discovered = find_pcaps(target, recursive=args.recursive)
        for path in discovered:
            if path not in seen_paths:
                seen_paths.add(path)
                paths.append(path)

    if not paths:
        print("No pcap/pcapng files found.")
        return 2

    export_json_path = Path(args.json).expanduser() if getattr(args, "json", None) else None
    export_csv_path = Path(args.csv).expanduser() if getattr(args, "csv", None) else None
    export_sqlite_path = Path(args.sqlite).expanduser() if getattr(args, "sqlite", None) else None
    if case_dir and not (export_json_path or export_csv_path or export_sqlite_path):
        export_json_path = case_dir / "pcapper.json"

    if args.export_raw:
        export_redact = False
    elif args.export_redact:
        export_redact = True
    else:
        export_redact = not args.show_secrets

    def _run_analysis() -> int:
        return _analyze_paths(
            paths,
            args.limit_protocols,
            show_base=args.base,
            show_status=not args.no_status,
            search_query=args.search,
            search_case=args.search_case,
            show_vlan=args.vlan,
            show_icmp=args.icmp,
            show_dns=args.dns,
            dns_vt=args.vt,
            show_http=args.http,
            show_ftp=args.ftp,
            show_tls=args.tls,
            show_ssh=args.ssh,
            show_rdp=args.rdp,
            show_telnet=args.telnet,
            show_vnc=args.vnc,
            show_teamviewer=args.teamviewer,
            show_winrm=args.winrm,
            show_wmic=args.wmic,
            show_powershell=args.powershell,
            show_syslog=args.syslog,
            show_snmp=args.snmp,
            show_smtp=args.smtp,
            show_rpc=args.rpc,
            show_tcp=args.tcp,
            show_udp=args.udp,
            show_exfil=args.exfil,
            show_sizes=args.sizes,
            show_ips=args.ips,
            show_beacon=args.beacon,
            show_threats=args.threats,
            show_files=args.files,
            show_protocols=args.protocols,
            show_routing=args.routing,
            show_services=args.services,
            show_smb=args.smb,
            show_nfs=args.nfs,
            show_strings=args.strings,
            show_creds=args.creds,
            show_secrets_scan=getattr(args, "secrets", False),
            show_secrets=args.show_secrets,
            show_certificates=args.certificates,
            show_health=args.health,
            show_compromised=getattr(args, "compromised", False),
            show_hosts=getattr(args, "hosts", False),
            show_hostname=args.hostname,
            show_hostdetails=args.hostdetails,
            show_timeline=args.timeline,
            timeline_ip=args.timeline_ip,
            timeline_bins=args.timeline_bins,
            timeline_storyline_off=args.timeline_storyline_off,
            timeline_categories=timeline_categories,
            show_ntlm=args.ntlm,
            show_netbios=args.netbios,
            show_arp=args.arp,
            show_dhcp=getattr(args, "dhcp", False),
            show_modbus=args.modbus,
            show_dnp3=args.dnp3,
            show_iec104=args.iec104,
            show_bacnet=args.bacnet,
            show_enip=args.enip,
            show_profinet=args.profinet,
            show_s7=args.s7,
            show_opc=args.opc,
            show_ethercat=args.ethercat,
            show_fins=args.fins,
            show_crimson=args.crimson,
            show_pcworx=args.pcworx,
            show_melsec=args.melsec,
            show_cip=args.cip,
            show_odesys=args.odesys,
            show_niagara=args.niagara,
            show_mms=args.mms,
            show_srtp=args.srtp,
            show_df1=args.df1,
            show_pccc=args.pccc,
            show_csp=args.csp,
            show_modicon=args.modicon,
            show_yokogawa=args.yokogawa,
            show_honeywell=args.honeywell,
            show_mqtt=args.mqtt,
            show_coap=args.coap,
            show_hart=args.hart,
            show_prconos=args.prconos,
            show_iccp=args.iccp,
            verbose=args.verbose,
            extract_name=args.extract,
            view_name=args.view,
            view_raw=args.view_raw,
            packet_index=args.packet,
            show_domain=args.domain,
            show_ldap=args.ldap,
            show_kerberos=args.kerberos,
            ordered_steps=ordered_steps,
            summarize=args.summarize,
            show_quic=getattr(args, "quic", False),
            show_http2=getattr(args, "http2", False),
            show_encrypted_dns=getattr(args, "encrypted_dns", False),
            show_ntp=getattr(args, "ntp", False),
            show_vpn=getattr(args, "vpn", False),
            show_goose=getattr(args, "goose", False),
            show_sv=getattr(args, "sv", False),
            show_lldp=getattr(args, "lldp", False),
            show_ptp=getattr(args, "ptp", False),
            show_opc_classic=getattr(args, "opc_classic", False),
            show_streams=getattr(args, "streams", False),
            follow_stream=getattr(args, "follow", None),
            follow_stream_id=getattr(args, "follow_id", None),
            lookup_stream_id=getattr(args, "lookup_stream_id", None),
            streams_full=getattr(args, "streams_full", False),
            show_ctf=getattr(args, "ctf", False),
            show_ioc=getattr(args, "ioc", False),
            ioc_file=getattr(args, "ioc_file", None),
            show_pcapmeta=getattr(args, "pcapmeta", False),
            show_ot_commands=getattr(args, "ot_commands", False),
            show_ot_commands_fast=getattr(args, "ot_commands_fast", False),
            ot_commands_config=ot_commands_config,
            ot_commands_sessions_limit=getattr(args, "ot_commands_sessions", 10),
            show_iec101_103=getattr(args, "iec101_103", False),
            bpf=getattr(args, "bpf", None),
            time_start=time_start,
            time_end=time_end,
            export_json_path=export_json_path,
            export_csv_path=export_csv_path,
            export_sqlite_path=export_sqlite_path,
            export_redact=export_redact,
            case_dir=case_dir,
            log_config=log_config,
            plugins=plugins,
        )

    if not args.profile:
        result = _run_analysis()
        _log_event(log_config, "end", status="ok" if result == 0 else "fail")
        return result

    import cProfile
    import io
    import pstats

    profiler = cProfile.Profile()
    profiler.enable()
    try:
        result = _run_analysis()
    finally:
        profiler.disable()
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream).sort_stats("cumtime")
        stats.print_stats(40)
        print(stream.getvalue(), file=sys.stderr)
        if args.profile_out:
            out_path = Path(args.profile_out).expanduser()
            out_path.parent.mkdir(parents=True, exist_ok=True)
            profiler.dump_stats(str(out_path))
    _log_event(log_config, "end", status="ok" if result == 0 else "fail")
    return result
