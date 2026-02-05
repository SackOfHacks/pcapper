from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import analyze_pcap
from .pcap_cache import PacketListReader, load_packets, get_pcap_index
from .coloring import set_color_override, header
from .ioc import collect_iocs, export_iocs_json, export_iocs_csv, export_iocs_stix, write_iocs
from .discovery import find_pcaps, is_supported_pcap
from .reporting import (
    render_summary,
    render_dashboard,
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
    render_modbus_summary,
    render_modbus_rollup,
    render_dnp3_summary,
    render_dnp3_rollup,
    render_ips_summary,
    render_http_summary,
    render_sizes_summary,
    render_nfs_summary,
    render_strings_summary,
    render_certificates_summary,
    render_health_summary,
    render_timeline_summary,
    render_domain_summary,
    render_ldap_summary,
    render_kerberos_summary,
    render_tls_summary,
    render_tcp_summary,
    render_udp_summary,
    render_exfil_summary,
    render_generic_rollup,
    render_creds_summary,
    render_creds_rollup,
    render_iocs_summary,
    render_email_summary,
)
from .vlan import analyze_vlans
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
from .threats import analyze_threats
from .files import analyze_files
from .protocols import analyze_protocols
from .services import analyze_services
from .smb import analyze_smb
from .ntlm import analyze_ntlm
from .netbios import analyze_netbios
from .modbus import analyze_modbus
from .dnp3 import analyze_dnp3
from .ips import analyze_ips
from .http import analyze_http
from .sizes import analyze_sizes
from .nfs import analyze_nfs
from .strings import analyze_strings
from .certificates import analyze_certificates
from .health import analyze_health
from .timeline import analyze_timeline, export_timeline_json, write_timeline_json
from .domain import analyze_domain
from .ldap import analyze_ldap
from .kerberos import analyze_kerberos
from .tls import analyze_tls
from .tcp import analyze_tcp
from .udp import analyze_udp
from .exfil import analyze_exfil
from .creds import analyze_creds
from .email import analyze_email


def _ordered_steps(argv: list[str]) -> list[str]:
    flag_map = {
        "--email": "email",
        "--ioc": "ioc",
        "--vlan": "vlan",
        "--icmp": "icmp",
        "--dns": "dns",
        "--http": "http",
        "--tls": "tls",
        "--tcp": "tcp",
        "--udp": "udp",
        "--exfil": "exfil",
        "--sizes": "sizes",
        "--ips": "ips",
        "--beacon": "beacon",
        "--threats": "threats",
        "--files": "files",
        "--protocols": "protocols",
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
        "--ntlm": "ntlm",
        "--netbios": "netbios",
        "--modbus": "modbus",
        "--dnp3": "dnp3",
        "--creds": "creds",
    }
    ordered: list[str] = []
    seen: set[str] = set()
    for arg in argv:
        step = flag_map.get(arg)
        if step and step not in seen:
            ordered.append(step)
            seen.add(step)
    return ordered


def _patch_readers(packets: list[object], meta) -> None:
    import pcapper.progress as progress
    import pcapper.vlan as vlan
    import pcapper.icmp as icmp
    import pcapper.dns as dns
    import pcapper.http as http
    import pcapper.sizes as sizes
    import pcapper.ips as ips
    import pcapper.beacon as beacon
    import pcapper.threats as threats
    import pcapper.files as files
    import pcapper.protocols as protocols
    import pcapper.services as services
    import pcapper.smb as smb
    import pcapper.nfs as nfs
    import pcapper.strings as strings
    import pcapper.certificates as certificates
    import pcapper.health as health
    import pcapper.timeline as timeline
    import pcapper.domain as domain
    import pcapper.ldap as ldap
    import pcapper.kerberos as kerberos
    import pcapper.ntlm as ntlm
    import pcapper.netbios as netbios
    import pcapper.modbus as modbus
    import pcapper.dnp3 as dnp3
    import pcapper.tls as tls
    import pcapper.tcp as tcp
    import pcapper.udp as udp
    import pcapper.exfil as exfil

    modules = [
        vlan,
        icmp,
        dns,
        http,
        sizes,
        ips,
        beacon,
        threats,
        files,
        protocols,
        services,
        smb,
        nfs,
        strings,
        certificates,
        health,
        timeline,
        domain,
        ldap,
        kerberos,
        ntlm,
        netbios,
        modbus,
        dnp3,
        tls,
        tcp,
        udp,
        exfil,
    ]

    def _reader_factory(*_args, **_kwargs):
        return PacketListReader(packets, meta)

    def _status_factory(path, enabled: bool = True, desc: str | None = None):
        return progress.build_statusbar(path, enabled=False, desc=desc)

    for module in modules:
        if hasattr(module, "PcapReader"):
            module.PcapReader = _reader_factory  # type: ignore[attr-defined]
        if hasattr(module, "PcapNgReader"):
            module.PcapNgReader = _reader_factory  # type: ignore[attr-defined]
        if hasattr(module, "build_statusbar"):
            module.build_statusbar = _status_factory  # type: ignore[attr-defined]


def _build_banner() -> str:
    compile_date = datetime.now(timezone.utc).date().isoformat()
    banner = [
        "======================================================================",
        "   ██████╗  ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗  ",
        "   ██╔══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗ ",
        "   ██████╔╝██║      ███████║██████╔╝██████╔╝█████╗  ██████╔╝ ",
        "   ██╔═══╝ ██║      ██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗ ",
        "   ██║     ╚██████╗ ██║  ██║██║     ██║     ███████╗██║  ██║ ",
        "   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝ ",
        "======================================================================",
        f"  PCAPPER v{__version__}  ::  Compile Date {compile_date}",
        "======================================================================",
    ]
    return "\n".join(banner)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _profile_output_path(base: str, pcap_path: Path) -> str:
    base_path = Path(base).expanduser()
    if base_path.exists() and base_path.is_dir():
        return str(base_path / f"{pcap_path.stem}.profile.json")
    if base.endswith(('/', '\\')):
        return str(Path(base) / f"{pcap_path.stem}.profile.json")
    if base_path.suffix.lower() != ".json":
        return str(base_path.with_suffix(".json"))
    return str(base_path)


def _build_profile(
    summary,
    *,
    dns_summary=None,
    http_summary=None,
    ips_summary=None,
    beacon_summary=None,
    threats_summary=None,
    files_summary=None,
    creds_summary=None,
) -> dict[str, object]:
    profile: dict[str, object] = {
        "pcap": summary.path.name,
        "file_type": summary.file_type,
        "size_bytes": summary.size_bytes,
        "packet_count": summary.packet_count,
        "duration_seconds": summary.duration_seconds,
        "protocol_counts": dict(getattr(summary, "protocol_counts", {}) or {}),
    }
    if dns_summary is not None:
        profile["dns"] = {
            "total_packets": dns_summary.total_packets,
            "unique_qnames": dns_summary.unique_qnames,
            "unique_clients": dns_summary.unique_clients,
            "unique_servers": dns_summary.unique_servers,
            "rcode_counts": dict(dns_summary.rcode_counts),
            "top_qnames": dns_summary.qname_counts.most_common(5),
        }
    if http_summary is not None:
        profile["http"] = {
            "total_requests": http_summary.total_requests,
            "total_responses": http_summary.total_responses,
            "unique_clients": http_summary.unique_clients,
            "unique_servers": http_summary.unique_servers,
            "top_hosts": http_summary.host_counts.most_common(5),
        }
    if ips_summary is not None:
        profile["ips"] = {
            "unique_ips": ips_summary.unique_ips,
            "unique_sources": ips_summary.unique_sources,
            "unique_destinations": ips_summary.unique_destinations,
            "top_sources": ips_summary.src_counts.most_common(5),
            "top_destinations": ips_summary.dst_counts.most_common(5),
        }
    if beacon_summary is not None:
        profile["beacon"] = {
            "candidate_count": beacon_summary.candidate_count,
            "top_candidates": [
                {
                    "src": c.src_ip,
                    "dst": c.dst_ip,
                    "proto": c.proto,
                    "score": round(c.score, 3),
                    "count": c.count,
                }
                for c in beacon_summary.candidates[:5]
            ],
        }
    if threats_summary is not None:
        profile["threats"] = {
            "detections": [
                {
                    "severity": item.get("severity"),
                    "summary": item.get("summary"),
                    "source": item.get("source"),
                }
                for item in threats_summary.detections[:10]
            ]
        }
    if files_summary is not None:
        profile["files"] = {
            "artifacts": len(files_summary.artifacts),
            "detections": len(files_summary.detections),
            "hash_clusters": len(getattr(files_summary, "hash_clusters", []) or []),
            "yara_hits": len(getattr(files_summary, "yara_hits", []) or []),
        }
    if creds_summary is not None:
        hits = getattr(creds_summary, "hits", None)
        profile["creds"] = {
            "total_hits": getattr(creds_summary, "total_hits", len(hits or [])),
        }
    return profile


def _diff_profiles(current: dict[str, object], baseline: dict[str, object]) -> dict[str, object]:
    diff: dict[str, object] = {}
    keys = {"size_bytes", "packet_count", "duration_seconds"}
    for key in keys:
        cur = current.get(key)
        base = baseline.get(key)
        if isinstance(cur, (int, float)) and isinstance(base, (int, float)):
            diff[key] = {
                "current": cur,
                "baseline": base,
                "delta": cur - base,
            }
    for section in ("dns", "http", "ips", "beacon", "files", "creds"):
        cur_section = current.get(section)
        base_section = baseline.get(section)
        if isinstance(cur_section, dict) and isinstance(base_section, dict):
            section_diff: dict[str, object] = {}
            for key, cur_val in cur_section.items():
                base_val = base_section.get(key)
                if isinstance(cur_val, (int, float)) and isinstance(base_val, (int, float)):
                    section_diff[key] = {
                        "current": cur_val,
                        "baseline": base_val,
                        "delta": cur_val - base_val,
                    }
            if section_diff:
                diff[section] = section_diff
    return diff


def _run_module_task(task: dict[str, object]) -> tuple[str, object]:
    name = str(task.get("name"))
    path = Path(str(task.get("path")))
    kwargs = task.get("kwargs") or {}
    if name == "vlan":
        return name, analyze_vlans(path, show_status=False)
    if name == "icmp":
        return name, analyze_icmp(path, show_status=False)
    if name == "dns":
        return name, analyze_dns(path, show_status=False)
    if name == "http":
        return name, analyze_http(path, show_status=False)
    if name == "tls":
        return name, analyze_tls(path, show_status=False)
    if name == "tcp":
        return name, analyze_tcp(path, show_status=False)
    if name == "udp":
        return name, analyze_udp(path, show_status=False)
    if name == "exfil":
        return name, analyze_exfil(path, show_status=False)
    if name == "email":
        return name, analyze_email(path, show_status=False)
    if name == "sizes":
        return name, analyze_sizes(path, show_status=False)
    if name == "ips":
        return name, analyze_ips(path, show_status=False)
    if name == "beacon":
        return name, analyze_beacons(path, show_status=False)
    if name == "threats":
        return name, analyze_threats(path, show_status=False)
    if name == "files":
        return name, analyze_files(path, show_status=False, **kwargs)
    if name == "protocols":
        return name, analyze_protocols(path, show_status=False)
    if name == "services":
        return name, analyze_services(path, show_status=False)
    if name == "smb":
        return name, analyze_smb(path, show_status=False)
    if name == "nfs":
        return name, analyze_nfs(path, show_status=False)
    if name == "strings":
        return name, analyze_strings(path, show_status=False)
    if name == "certificates":
        return name, analyze_certificates(path, show_status=False)
    if name == "health":
        return name, analyze_health(path, show_status=False)
    if name == "timeline":
        return name, analyze_timeline(path, **kwargs)
    if name == "domain":
        return name, analyze_domain(path, show_status=False)
    if name == "ldap":
        return name, analyze_ldap(path, show_status=False)
    if name == "kerberos":
        return name, analyze_kerberos(path, show_status=False)
    if name == "ntlm":
        return name, analyze_ntlm(path, show_status=False)
    if name == "netbios":
        return name, analyze_netbios(path, show_status=False)
    if name == "modbus":
        return name, analyze_modbus(path, show_status=False)
    if name == "dnp3":
        return name, analyze_dnp3(path, show_status=False)
    if name == "creds":
        return name, analyze_creds(path, show_status=False)
    return name, None


def build_parser() -> argparse.ArgumentParser:
    banner = _build_banner()
    parser = argparse.ArgumentParser(
        prog="pcapper",
        description=f"{banner}\n\nModular PCAP analyzer for fast triage and reporting.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Path to a pcap/pcapng file or directory of captures.",
    )

    general = parser.add_argument_group(header("General Options"))
    analysis = parser.add_argument_group(header("Analysis Modules"))
    timeline = parser.add_argument_group(header("Timeline Options"))
    file_actions = parser.add_argument_group(header("File Actions"))
    output = parser.add_argument_group(header("Output Controls"))
    ioc_export = parser.add_argument_group(header("IOC Export"))

    general.add_argument(
        "--index-cache",
        action="store_true",
        help="Build/use a PCAP index cache for faster repeated runs.",
    )
    general.add_argument(
        "--index-refresh",
        action="store_true",
        help="Rebuild the PCAP index cache even if one exists.",
    )
    general.add_argument(
        "-l",
        "--limit-protocols",
        type=int,
        default=15,
        help="Number of protocols to show in the summary.",
    )
    general.add_argument(
        "--mp",
        action="store_true",
        help="Run analysis modules in parallel processes.",
    )
    general.add_argument(
        "--mp-workers",
        type=int,
        default=0,
        help="Number of worker processes for --mp (default: CPU count).",
    )
    general.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively search for pcaps when target is a directory.",
    )
    general.add_argument(
        "--stream",
        action="store_true",
        help="Stream modules from disk (disable in-memory packet cache).",
    )
    general.add_argument(
        "-summarize",
        "--summarize",
        action="store_true",
        help="Summarize supported analysis across all pcaps (e.g., --modbus, --dnp3).",
    )

    analysis.add_argument(
        "--beacon",
        action="store_true",
        help="Include beaconing analysis in the output.",
    )
    analysis.add_argument(
        "--certificates",
        action="store_true",
        help="Include TLS certificate extraction and analysis.",
    )
    analysis.add_argument(
        "--creds",
        action="store_true",
        help="Include credential hunting across HTTP, SMB, NTLM, and Kerberos.",
    )
    analysis.add_argument(
        "--dns",
        action="store_true",
        help="Include DNS analysis in the output.",
    )
    analysis.add_argument(
        "--dnp3",
        action="store_true",
        help="Include DNP3 protocol analysis (Functions, Restarts, File Ops).",
    )
    analysis.add_argument(
        "--domain",
        action="store_true",
        help="Include MS AD and domain analysis (services, users, DCs, artifacts).",
    )
    analysis.add_argument(
        "--email",
        action="store_true",
        help="Include email protocol analysis (SMTP/POP/IMAP/LMTP/ManageSieve).",
    )
    analysis.add_argument(
        "--exfil",
        action="store_true",
        help="Include exfiltration heuristics and anomaly analysis.",
    )
    analysis.add_argument(
        "--files",
        action="store_true",
        help="Include file transfer discovery in the output.",
    )
    analysis.add_argument(
        "--health",
        action="store_true",
        help="Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs).",
    )
    analysis.add_argument(
        "--http",
        action="store_true",
        help="Include HTTP analysis in the output.",
    )
    analysis.add_argument(
        "--icmp",
        action="store_true",
        help="Include ICMP analysis in the output.",
    )
    analysis.add_argument(
        "--ioc",
        action="store_true",
        help="Extract and display indicators of compromise (IOCs).",
    )
    analysis.add_argument(
        "--ips",
        action="store_true",
        help="Include IP address intelligence and conversation analysis.",
    )
    analysis.add_argument(
        "--kerberos",
        action="store_true",
        help="Include Kerberos analysis (requests, errors, principals, attacks).",
    )
    analysis.add_argument(
        "--ldap",
        action="store_true",
        help="Include LDAP analysis (queries, users, servers, anomalies, secrets).",
    )
    analysis.add_argument(
        "--modbus",
        action="store_true",
        help="Include Modbus/TCP status and security analysis (Functions, Units, Anomalies).",
    )
    analysis.add_argument(
        "--netbios",
        action="store_true",
        help="Include NetBIOS name service analysis (Names, Groups, Roles).",
    )
    analysis.add_argument(
        "--nfs",
        action="store_true",
        help="Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies).",
    )
    analysis.add_argument(
        "--ntlm",
        action="store_true",
        help="Include NTLM authentication analysis (Users, Domains, Versions).",
    )
    analysis.add_argument(
        "--protocols",
        action="store_true",
        help="Include detailed protocol hierarchy and anomaly analysis.",
    )
    analysis.add_argument(
        "--services",
        action="store_true",
        help="Include service discovery and cybersecurity risk analysis.",
    )
    analysis.add_argument(
        "--sizes",
        action="store_true",
        help="Include packet size distribution analysis.",
    )
    analysis.add_argument(
        "--smb",
        action="store_true",
        help="Include SMB protocol analysis (Versioning, Shares, Anomalies).",
    )
    analysis.add_argument(
        "--strings",
        action="store_true",
        help="Include cleartext strings extraction and anomaly analysis.",
    )
    analysis.add_argument(
        "--tcp",
        action="store_true",
        help="Include TCP analysis in the output.",
    )
    analysis.add_argument(
        "--threats",
        action="store_true",
        help="Include consolidated threat detections in the output.",
    )
    analysis.add_argument(
        "--timeline",
        action="store_true",
        help="Include a threat-hunting timeline for a specific IP (use with -ip).",
    )
    analysis.add_argument(
        "--tls",
        action="store_true",
        help="Include TLS/HTTPS analysis in the output.",
    )
    analysis.add_argument(
        "--udp",
        action="store_true",
        help="Include UDP analysis in the output.",
    )
    analysis.add_argument(
        "--vlan",
        action="store_true",
        help="Include VLAN analysis in the output.",
    )

    timeline.add_argument(
        "-ip",
        dest="timeline_ip",
        help="Target IP for timeline analysis (use with --timeline).",
    )
    timeline.add_argument(
        "--timeline-filter-ip",
        dest="timeline_filter_ip",
        help="Filter timeline events by IP (src/dst).",
    )
    timeline.add_argument(
        "--timeline-filter-port",
        dest="timeline_filter_port",
        type=int,
        help="Filter timeline events by port.",
    )
    timeline.add_argument(
        "--timeline-filter-domain",
        dest="timeline_filter_domain",
        help="Filter timeline events by domain/host.",
    )
    timeline.add_argument(
        "--timeline-filter-user",
        dest="timeline_filter_user",
        help="Filter timeline events by user/principal.",
    )
    timeline.add_argument(
        "--timeline-json",
        action="store_true",
        help="Output timeline events as JSON for ingestion.",
    )
    timeline.add_argument(
        "--timeline-out",
        metavar="PATH",
        help="Write timeline JSON to file (defaults to stdout).",
    )

    file_actions.add_argument(
        "--extract",
        metavar="FILENAME",
        help="Extract a discovered file by name into ./files (use with --files).",
    )
    file_actions.add_argument(
        "--view",
        metavar="FILENAME",
        help="View extracted file content in ASCII/HEX (use with --files).",
    )

    output.add_argument(
        "--output",
        choices=["txt", "md", "json"],
        default="txt",
        help="Output format for reports (default: txt).",
    )
    output.add_argument(
        "--profile",
        metavar="PATH",
        help="Write a JSON profile snapshot for the capture.",
    )
    output.add_argument(
        "--baseline",
        metavar="PATH",
        help="Compare current run against a saved profile JSON.",
    )
    output.add_argument(
        "--compare",
        metavar="PCAP",
        help="Compare current capture against another PCAP/PCAPNG.",
    )
    output.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    output.add_argument(
        "--no-status",
        action="store_true",
        help="Disable the processing status bar.",
    )
    output.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose details in analysis output.",
    )

    ioc_export.add_argument(
        "--ioc-export",
        choices=["json", "csv", "stix"],
        help="Export collected IOCs in the selected format.",
    )
    ioc_export.add_argument(
        "--ioc-out",
        metavar="PATH",
        help="Write IOC export to a file (defaults to stdout).",
    )
    return parser


def _analyze_paths(
    paths: list[Path],
    protocol_limit: int,
    show_status: bool,
    show_vlan: bool,
    show_icmp: bool,
    show_dns: bool,
    show_http: bool,
    show_tls: bool,
    show_tcp: bool,
    show_udp: bool,
    show_exfil: bool,
    show_email: bool,
    show_sizes: bool,
    show_ips: bool,
    show_beacon: bool,
    show_ioc: bool,
    show_threats: bool,
    show_files: bool,
    show_protocols: bool,
    show_services: bool,
    show_smb: bool,
    show_nfs: bool,
    show_strings: bool,
    show_certificates: bool,
    show_health: bool,
    show_timeline: bool,
    timeline_ip: str | None,
    timeline_filter_ip: str | None,
    timeline_filter_port: int | None,
    timeline_filter_domain: str | None,
    timeline_filter_user: str | None,
    timeline_json: bool,
    timeline_out: str | None,
    show_ntlm: bool,
    show_netbios: bool,
    show_modbus: bool,
    show_dnp3: bool,
    show_creds: bool,
    verbose: bool,
    extract_name: str | None,
    view_name: str | None,
    show_domain: bool,
    show_ldap: bool,
    show_kerberos: bool,
    ordered_steps: list[str],
    summarize: bool,
    ioc_export: str | None,
    ioc_out: str | None,
    output_format: str,
    profile_path: str | None,
    baseline_path: str | None,
    compare_path: str | None,
    streaming: bool,
    mp_modules: bool,
    mp_workers: int,
    index_cache: bool,
    index_refresh: bool,
) -> int:
    if not paths:
        return 1

    summarize_rollups = summarize and len(paths) > 1
    modbus_rollups = []
    dnp3_rollups = []
    rollups: dict[str, list[object]] = {}
    json_reports: list[dict[str, object]] = []

    def _emit(section: str, *, buffer: list[str]) -> None:
        if output_format == "json":
            return
        if output_format == "md":
            buffer.append("```text")
            buffer.append(_strip_ansi(section))
            buffer.append("```")
        else:
            buffer.append(section)

    def _ioc_output_path(base: str, fmt: str, pcap_path: Path) -> str:
        base_path = Path(base).expanduser()
        if base_path.exists() and base_path.is_dir():
            return str(base_path / f"{pcap_path.stem}.iocs.{fmt}")
        if base.endswith(('/', '\\')):
            return str(Path(base) / f"{pcap_path.stem}.iocs.{fmt}")
        if len(paths) == 1:
            return str(base_path)
        suffix = base_path.suffix or f".{fmt}"
        stem = base_path.name[: -len(suffix)] if suffix and base_path.name.endswith(suffix) else base_path.name
        return str(base_path.with_name(f"{stem}-{pcap_path.stem}{suffix}"))

    for idx, path in enumerate(paths, start=1):
        output_sections: list[str] = []
        if index_cache:
            try:
                get_pcap_index(path, refresh=index_refresh, show_status=show_status)
            except Exception:
                pass

        use_streaming = streaming or mp_modules
        packets = None
        meta = None
        if not use_streaming:
            packets, meta = load_packets(path, show_status=show_status)
            _patch_readers(packets, meta)

        summary = analyze_pcap(path, show_status=False, packets=packets, meta=meta)
        _emit(render_summary(summary, protocol_limit=protocol_limit), buffer=output_sections)

        dns_summary = None
        http_summary = None
        ips_summary = None
        strings_summary = None
        files_summary = None
        creds_summary = None
        threat_summary = None
        beacon_summary = None
        ioc_items = None
        email_summary = None

        module_results: dict[str, object] = {}
        if mp_modules:
            tasks: list[dict[str, object]] = []
            for step in ordered_steps:
                if step == "vlan" and show_vlan:
                    tasks.append({"name": "vlan", "path": str(path)})
                elif step == "icmp" and show_icmp:
                    tasks.append({"name": "icmp", "path": str(path)})
                elif step == "dns" and show_dns:
                    tasks.append({"name": "dns", "path": str(path)})
                elif step == "http" and show_http:
                    tasks.append({"name": "http", "path": str(path)})
                elif step == "tls" and show_tls:
                    tasks.append({"name": "tls", "path": str(path)})
                elif step == "tcp" and show_tcp:
                    tasks.append({"name": "tcp", "path": str(path)})
                elif step == "udp" and show_udp:
                    tasks.append({"name": "udp", "path": str(path)})
                elif step == "exfil" and show_exfil:
                    tasks.append({"name": "exfil", "path": str(path)})
                elif step == "email" and show_email:
                    tasks.append({"name": "email", "path": str(path)})
                elif step == "sizes" and show_sizes:
                    tasks.append({"name": "sizes", "path": str(path)})
                elif step == "ips" and show_ips:
                    tasks.append({"name": "ips", "path": str(path)})
                elif step == "beacon" and show_beacon:
                    tasks.append({"name": "beacon", "path": str(path)})
                elif step == "threats" and show_threats:
                    tasks.append({"name": "threats", "path": str(path)})
                elif step == "files" and show_files:
                    tasks.append({
                        "name": "files",
                        "path": str(path),
                        "kwargs": {
                            "extract_name": extract_name,
                            "view_name": view_name,
                            "include_x509": verbose,
                        },
                    })
                elif step == "protocols" and show_protocols:
                    tasks.append({"name": "protocols", "path": str(path)})
                elif step == "services" and show_services:
                    tasks.append({"name": "services", "path": str(path)})
                elif step == "smb" and show_smb:
                    tasks.append({"name": "smb", "path": str(path)})
                elif step == "nfs" and show_nfs:
                    tasks.append({"name": "nfs", "path": str(path)})
                elif step == "strings" and show_strings:
                    tasks.append({"name": "strings", "path": str(path)})
                elif step == "creds" and show_creds:
                    tasks.append({"name": "creds", "path": str(path)})
                elif step == "certificates" and show_certificates:
                    tasks.append({"name": "certificates", "path": str(path)})
                elif step == "health" and show_health:
                    tasks.append({"name": "health", "path": str(path)})
                elif step == "timeline" and show_timeline and timeline_ip:
                    tasks.append({
                        "name": "timeline",
                        "path": str(path),
                        "kwargs": {
                            "target_ip": timeline_ip,
                            "show_status": False,
                            "filter_ip": timeline_filter_ip,
                            "filter_port": timeline_filter_port,
                            "filter_domain": timeline_filter_domain,
                            "filter_user": timeline_filter_user,
                        },
                    })
                elif step == "domain" and show_domain:
                    tasks.append({"name": "domain", "path": str(path)})
                elif step == "ldap" and show_ldap:
                    tasks.append({"name": "ldap", "path": str(path)})
                elif step == "kerberos" and show_kerberos:
                    tasks.append({"name": "kerberos", "path": str(path)})
                elif step == "ntlm" and show_ntlm:
                    tasks.append({"name": "ntlm", "path": str(path)})
                elif step == "netbios" and show_netbios:
                    tasks.append({"name": "netbios", "path": str(path)})
                elif step == "modbus" and show_modbus:
                    tasks.append({"name": "modbus", "path": str(path)})
                elif step == "dnp3" and show_dnp3:
                    tasks.append({"name": "dnp3", "path": str(path)})

            if tasks:
                try:
                    ctx = multiprocessing.get_context("fork")
                except ValueError:
                    ctx = multiprocessing.get_context()
                max_workers = mp_workers if mp_workers and mp_workers > 0 else (os.cpu_count() or 2)
                worker_count = max(1, min(max_workers, len(tasks)))
                with ctx.Pool(processes=worker_count) as pool:
                    for name, result in pool.map(_run_module_task, tasks):
                        module_results[name] = result

        for step in ordered_steps:
            if step == "vlan" and show_vlan:
                vlan_summary = module_results.get("vlan") if mp_modules else analyze_vlans(path, show_status=False)
                if vlan_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("vlan", []).append(vlan_summary)
                else:
                    _emit(render_vlan_summary(vlan_summary, verbose=verbose), buffer=output_sections)
            elif step == "icmp" and show_icmp:
                icmp_summary = module_results.get("icmp") if mp_modules else analyze_icmp(path, show_status=False)
                if icmp_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("icmp", []).append(icmp_summary)
                else:
                    _emit(render_icmp_summary(icmp_summary, verbose=verbose), buffer=output_sections)
            elif step == "dns" and show_dns:
                dns_summary = module_results.get("dns") if mp_modules else analyze_dns(path, show_status=False, packets=packets, meta=meta)
                if dns_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("dns", []).append(dns_summary)
                else:
                    _emit(render_dns_summary(dns_summary, verbose=verbose), buffer=output_sections)
            elif step == "http" and show_http:
                http_summary = module_results.get("http") if mp_modules else analyze_http(path, show_status=False, packets=packets, meta=meta)
                if http_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("http", []).append(http_summary)
                else:
                    _emit(render_http_summary(http_summary, verbose=verbose), buffer=output_sections)
            elif step == "tls" and show_tls:
                tls_summary = module_results.get("tls") if mp_modules else analyze_tls(path, show_status=False, packets=packets, meta=meta)
                if tls_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("tls", []).append(tls_summary)
                else:
                    _emit(render_tls_summary(tls_summary, verbose=verbose), buffer=output_sections)
            elif step == "tcp" and show_tcp:
                tcp_summary = module_results.get("tcp") if mp_modules else analyze_tcp(path, show_status=False, packets=packets, meta=meta)
                if tcp_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("tcp", []).append(tcp_summary)
                else:
                    _emit(render_tcp_summary(tcp_summary, verbose=verbose), buffer=output_sections)
            elif step == "udp" and show_udp:
                udp_summary = module_results.get("udp") if mp_modules else analyze_udp(path, show_status=False, packets=packets, meta=meta)
                if udp_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("udp", []).append(udp_summary)
                else:
                    _emit(render_udp_summary(udp_summary, verbose=verbose), buffer=output_sections)
            elif step == "exfil" and show_exfil:
                exfil_summary = module_results.get("exfil") if mp_modules else analyze_exfil(path, show_status=False, packets=packets, meta=meta)
                if exfil_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("exfil", []).append(exfil_summary)
                else:
                    _emit(render_exfil_summary(exfil_summary, verbose=verbose), buffer=output_sections)
            elif step == "sizes" and show_sizes:
                size_summary = module_results.get("sizes") if mp_modules else analyze_sizes(path, show_status=False)
                if size_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("sizes", []).append(size_summary)
                else:
                    _emit(render_sizes_summary(size_summary, verbose=verbose), buffer=output_sections)
            elif step == "email" and show_email:
                email_summary = module_results.get("email") if mp_modules else analyze_email(path, show_status=False)
                if email_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("email", []).append(email_summary)
                else:
                    _emit(render_email_summary(email_summary, verbose=verbose), buffer=output_sections)
            elif step == "ips" and show_ips:
                ips_summary = module_results.get("ips") if mp_modules else analyze_ips(path, show_status=False)
                if ips_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("ips", []).append(ips_summary)
                else:
                    _emit(render_ips_summary(ips_summary, verbose=verbose), buffer=output_sections)
            elif step == "beacon" and show_beacon:
                beacon_summary = module_results.get("beacon") if mp_modules else analyze_beacons(path, show_status=False)
                if beacon_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("beacon", []).append(beacon_summary)
                else:
                    _emit(render_beacon_summary(beacon_summary, verbose=verbose), buffer=output_sections)
            elif step == "threats" and show_threats:
                threat_summary = module_results.get("threats") if mp_modules else analyze_threats(path, show_status=False)
                if threat_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("threats", []).append(threat_summary)
                else:
                    _emit(render_threats_summary(threat_summary), buffer=output_sections)
            elif step == "files" and show_files:
                files_summary = module_results.get("files") if mp_modules else analyze_files(
                    path,
                    extract_name=extract_name,
                    view_name=view_name,
                    show_status=False,
                    include_x509=verbose,
                )
                if files_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("files", []).append(files_summary)
                else:
                    _emit(render_files_summary(files_summary), buffer=output_sections)
            elif step == "protocols" and show_protocols:
                proto_summary = module_results.get("protocols") if mp_modules else analyze_protocols(path, show_status=False)
                if proto_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("protocols", []).append(proto_summary)
                else:
                    _emit(render_protocols_summary(proto_summary, verbose=verbose), buffer=output_sections)
            elif step == "services" and show_services:
                svc_summary = module_results.get("services") if mp_modules else analyze_services(path, show_status=False)
                if svc_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("services", []).append(svc_summary)
                else:
                    _emit(render_services_summary(svc_summary), buffer=output_sections)
            elif step == "smb" and show_smb:
                smb_summary = module_results.get("smb") if mp_modules else analyze_smb(path, show_status=False)
                if smb_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("smb", []).append(smb_summary)
                else:
                    _emit(render_smb_summary(smb_summary, verbose=verbose), buffer=output_sections)
            elif step == "nfs" and show_nfs:
                nfs_summary = module_results.get("nfs") if mp_modules else analyze_nfs(path, show_status=False)
                if nfs_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("nfs", []).append(nfs_summary)
                else:
                    _emit(render_nfs_summary(nfs_summary), buffer=output_sections)
            elif step == "strings" and show_strings:
                strings_summary = module_results.get("strings") if mp_modules else analyze_strings(path, show_status=False)
                if strings_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("strings", []).append(strings_summary)
                else:
                    _emit(render_strings_summary(strings_summary), buffer=output_sections)
            elif step == "creds" and show_creds:
                creds_summary = module_results.get("creds") if mp_modules else analyze_creds(path, show_status=False, packets=packets, meta=meta)
                if creds_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("creds", []).append(creds_summary)
                else:
                    _emit(render_creds_summary(creds_summary), buffer=output_sections)
            elif step == "certificates" and show_certificates:
                cert_summary = module_results.get("certificates") if mp_modules else analyze_certificates(path, show_status=False)
                if cert_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("certificates", []).append(cert_summary)
                else:
                    _emit(render_certificates_summary(cert_summary), buffer=output_sections)
            elif step == "health" and show_health:
                health_summary = module_results.get("health") if mp_modules else analyze_health(path, show_status=False)
                if health_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("health", []).append(health_summary)
                else:
                    _emit(render_health_summary(health_summary), buffer=output_sections)
            elif step == "timeline" and show_timeline and timeline_ip:
                timeline_summary = module_results.get("timeline") if mp_modules else analyze_timeline(
                    path,
                    timeline_ip,
                    show_status=False,
                    filter_ip=timeline_filter_ip,
                    filter_port=timeline_filter_port,
                    filter_domain=timeline_filter_domain,
                    filter_user=timeline_filter_user,
                )
                if timeline_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("timeline", []).append(timeline_summary)
                else:
                    if timeline_json:
                        output = export_timeline_json(timeline_summary)
                        write_timeline_json(output, timeline_out)
                    else:
                        _emit(render_timeline_summary(timeline_summary), buffer=output_sections)
            elif step == "domain" and show_domain:
                domain_summary = module_results.get("domain") if mp_modules else analyze_domain(path, show_status=False, packets=packets, meta=meta)
                if domain_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("domain", []).append(domain_summary)
                else:
                    _emit(render_domain_summary(domain_summary), buffer=output_sections)
            elif step == "ldap" and show_ldap:
                ldap_summary = module_results.get("ldap") if mp_modules else analyze_ldap(path, show_status=False, packets=packets, meta=meta)
                if ldap_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("ldap", []).append(ldap_summary)
                else:
                    _emit(render_ldap_summary(ldap_summary), buffer=output_sections)
            elif step == "kerberos" and show_kerberos:
                kerberos_summary = module_results.get("kerberos") if mp_modules else analyze_kerberos(path, show_status=False, packets=packets, meta=meta)
                if kerberos_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("kerberos", []).append(kerberos_summary)
                else:
                    _emit(render_kerberos_summary(kerberos_summary), buffer=output_sections)
            elif step == "ntlm" and show_ntlm:
                ntlm_summary = module_results.get("ntlm") if mp_modules else analyze_ntlm(path, show_status=False)
                if ntlm_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("ntlm", []).append(ntlm_summary)
                else:
                    _emit(render_ntlm_summary(ntlm_summary), buffer=output_sections)
            elif step == "netbios" and show_netbios:
                nb_summary = module_results.get("netbios") if mp_modules else analyze_netbios(path, show_status=False)
                if nb_summary is None:
                    continue
                if summarize_rollups:
                    rollups.setdefault("netbios", []).append(nb_summary)
                else:
                    _emit(render_netbios_summary(nb_summary), buffer=output_sections)
            elif step == "modbus" and show_modbus:
                modbus_summary = module_results.get("modbus") if mp_modules else analyze_modbus(path, show_status=False)
                if modbus_summary is None:
                    continue
                if summarize_rollups:
                    modbus_rollups.append(modbus_summary)
                else:
                    _emit(render_modbus_summary(modbus_summary, verbose=verbose), buffer=output_sections)
            elif step == "dnp3" and show_dnp3:
                dnp3_summary = module_results.get("dnp3") if mp_modules else analyze_dnp3(path, show_status=False)
                if dnp3_summary is None:
                    continue
                if summarize_rollups:
                    dnp3_rollups.append(dnp3_summary)
                else:
                    _emit(render_dnp3_summary(dnp3_summary), buffer=output_sections)
            elif step == "ioc" and show_ioc:
                if dns_summary is None:
                    dns_summary = analyze_dns(path, show_status=False, packets=packets, meta=meta)
                if http_summary is None:
                    http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
                if ips_summary is None:
                    ips_summary = analyze_ips(path, show_status=False)
                if strings_summary is None:
                    strings_summary = analyze_strings(path, show_status=False)
                if files_summary is None:
                    files_summary = analyze_files(path, show_status=False)

                ioc_items = collect_iocs(
                    dns_summary=dns_summary,
                    http_summary=http_summary,
                    strings_summary=strings_summary,
                    files_summary=files_summary,
                    ips_summary=ips_summary,
                )
                if not summarize_rollups:
                    _emit(render_iocs_summary(ioc_items), buffer=output_sections)

        dashboard = render_dashboard(
            summary,
            dns_summary=dns_summary,
            http_summary=http_summary,
            ips_summary=ips_summary,
            beacon_summary=beacon_summary,
            threats_summary=threat_summary,
            files_summary=files_summary,
            creds_summary=creds_summary,
        )
        if dashboard and output_format != "json":
            if output_format == "md":
                dashboard_block = "\n".join(["```text", _strip_ansi(dashboard), "```"])
            else:
                dashboard_block = dashboard
            output_sections.insert(0, dashboard_block)

        profile = _build_profile(
            summary,
            dns_summary=dns_summary,
            http_summary=http_summary,
            ips_summary=ips_summary,
            beacon_summary=beacon_summary,
            threats_summary=threat_summary,
            files_summary=files_summary,
            creds_summary=creds_summary,
        )
        if ioc_items:
            profile["iocs"] = [
                {
                    "type": item.ioc_type,
                    "value": item.value,
                    "source": item.source,
                    "details": item.details or {},
                }
                for item in ioc_items
            ]

        if profile_path:
            out_path = _profile_output_path(profile_path, path)
            try:
                Path(out_path).write_text(json.dumps(profile, indent=2), encoding="utf-8")
            except Exception:
                pass

        compare_profile = None
        if compare_path:
            compare_target = Path(compare_path).expanduser()
            if compare_target.exists() and is_supported_pcap(compare_target):
                compare_summary = analyze_pcap(compare_target, show_status=False)
                compare_dns = analyze_dns(compare_target, show_status=False)
                compare_http = analyze_http(compare_target, show_status=False)
                compare_ips = analyze_ips(compare_target, show_status=False)
                compare_beacon = analyze_beacons(compare_target, show_status=False)
                compare_threats = analyze_threats(compare_target, show_status=False)
                compare_profile = _build_profile(
                    compare_summary,
                    dns_summary=compare_dns,
                    http_summary=compare_http,
                    ips_summary=compare_ips,
                    beacon_summary=compare_beacon,
                    threats_summary=compare_threats,
                )

        baseline_profile = None
        if baseline_path:
            try:
                baseline_profile = json.loads(Path(baseline_path).expanduser().read_text(encoding="utf-8"))
            except Exception:
                baseline_profile = None

        if compare_profile:
            diff = _diff_profiles(profile, compare_profile)
            if output_format == "json":
                profile["compare"] = {"against": str(compare_path), "diff": diff}
            else:
                _emit("Comparison Diff:\n" + json.dumps(diff, indent=2), buffer=output_sections)

        if baseline_profile:
            diff = _diff_profiles(profile, baseline_profile)
            if output_format == "json":
                profile["baseline"] = {"against": str(baseline_path), "diff": diff}
            else:
                _emit("Baseline Diff:\n" + json.dumps(diff, indent=2), buffer=output_sections)

        if output_format == "json":
            json_reports.append(profile)
        else:
            if output_sections:
                print("\n".join(output_sections))
        if output_format != "json" and idx < len(paths):
            print()

        if ioc_export:
            if dns_summary is None:
                dns_summary = analyze_dns(path, show_status=False, packets=packets, meta=meta)
            if http_summary is None:
                http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
            if ips_summary is None:
                ips_summary = analyze_ips(path, show_status=False)
            if strings_summary is None:
                strings_summary = analyze_strings(path, show_status=False)
            if files_summary is None:
                files_summary = analyze_files(path, show_status=False)

            iocs = collect_iocs(
                dns_summary=dns_summary,
                http_summary=http_summary,
                strings_summary=strings_summary,
                files_summary=files_summary,
                ips_summary=ips_summary,
            )
            if ioc_export == "json":
                output_text = export_iocs_json(iocs)
            elif ioc_export == "csv":
                output_text = export_iocs_csv(iocs)
            else:
                output_text = export_iocs_stix(iocs)
            out_path = None
            if ioc_out:
                out_path = _ioc_output_path(ioc_out, ioc_export, path)
            write_iocs(output_text, out_path)

    if output_format != "json" and summarize_rollups:
        rollup_sections: list[str] = []
        title_map = {
            "vlan": "VLAN ANALYSIS",
            "icmp": "ICMP ANALYSIS",
            "dns": "DNS ANALYSIS",
            "email": "EMAIL ANALYSIS",
            "http": "HTTP ANALYSIS",
            "tls": "TLS/HTTPS ANALYSIS",
            "tcp": "TCP ANALYSIS",
            "udp": "UDP ANALYSIS",
            "exfil": "EXFILTRATION ANALYSIS",
            "sizes": "PACKET SIZE ANALYSIS",
            "ips": "IP INTELLIGENCE ANALYSIS",
            "beacon": "BEACON ANALYSIS",
            "threats": "THREAT DETECTIONS",
            "files": "FILE TRANSFER ANALYSIS",
            "protocols": "PROTOCOL ANALYSIS",
            "services": "SERVICE ANALYSIS",
            "smb": "SMB ANALYSIS",
            "nfs": "NFS ANALYSIS",
            "strings": "STRINGS ANALYSIS",
            "certificates": "CERTIFICATE ANALYSIS",
            "health": "TRAFFIC HEALTH ANALYSIS",
            "timeline": "TIMELINE ANALYSIS",
            "domain": "DOMAIN ANALYSIS",
            "ldap": "LDAP ANALYSIS",
            "kerberos": "KERBEROS ANALYSIS",
            "ntlm": "NTLM ANALYSIS",
            "netbios": "NETBIOS ANALYSIS",
            "creds": "CREDENTIAL HUNTING",
        }
        rollup_steps = [step for step in title_map.keys() if rollups.get(step)]
        for step in rollup_steps:
            if step in ("modbus", "dnp3", "vlan"):
                continue
            if rollups.get(step):
                _emit(render_generic_rollup(title_map.get(step, step.upper()), rollups[step]), buffer=rollup_sections)
                _emit("", buffer=rollup_sections)
        if rollups.get("vlan"):
            _emit(render_vlan_rollup(rollups["vlan"], verbose=verbose), buffer=rollup_sections)
            _emit("", buffer=rollup_sections)
        if show_modbus and modbus_rollups:
            _emit(render_modbus_rollup(modbus_rollups), buffer=rollup_sections)
            if show_dnp3 and dnp3_rollups:
                _emit("", buffer=rollup_sections)
        if show_dnp3 and dnp3_rollups:
            _emit(render_dnp3_rollup(dnp3_rollups), buffer=rollup_sections)
        if rollups.get("creds"):
            _emit(render_creds_rollup(rollups["creds"]), buffer=rollup_sections)
            _emit("", buffer=rollup_sections)
        if rollup_sections:
            print("\n".join(rollup_sections))
    if output_format == "json":
        print(json.dumps({"reports": json_reports}, indent=2))
    return 0


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        print(_build_banner())
        print("Usage: pcapper <target> [options]")
        print("Run with -h for full help and options.")
        return 0
    args = parser.parse_args()
    print(_build_banner())

    ordered_steps = _ordered_steps(sys.argv)

    if args.no_color:
        set_color_override(False)

    if args.timeline and not args.timeline_ip:
        print("Timeline analysis requires a target IP. Use -ip <address> with --timeline.")
        return 2

    target: Path = args.target
    if not target.exists():
        print(f"Target not found: {target}")
        return 2

    if target.is_file():
        if not is_supported_pcap(target):
            print("Target is not a supported pcap/pcapng file.")
            return 2
        return _analyze_paths(
            [target],
            args.limit_protocols,
            show_status=not args.no_status,
            show_vlan=args.vlan,
            show_icmp=args.icmp,
            show_dns=args.dns,
            show_http=args.http,
            show_tls=args.tls,
            show_tcp=args.tcp,
            show_udp=args.udp,
            show_exfil=args.exfil,
            show_email=args.email,
            show_sizes=args.sizes,
            show_ips=args.ips,
            show_beacon=args.beacon,
            show_ioc=args.ioc,
            show_threats=args.threats,
            show_files=args.files,
            show_protocols=args.protocols,
            show_services=args.services,
            show_smb=args.smb,
            show_nfs=args.nfs,
            show_strings=args.strings,
            show_certificates=args.certificates,
            show_health=args.health,
            show_timeline=args.timeline,
            timeline_ip=args.timeline_ip,
            timeline_filter_ip=args.timeline_filter_ip,
            timeline_filter_port=args.timeline_filter_port,
            timeline_filter_domain=args.timeline_filter_domain,
            timeline_filter_user=args.timeline_filter_user,
            timeline_json=args.timeline_json,
            timeline_out=args.timeline_out,
            show_ntlm=args.ntlm,
            show_netbios=args.netbios,
            show_modbus=args.modbus,
            show_dnp3=args.dnp3,
            show_creds=args.creds,
            verbose=args.verbose,
            extract_name=args.extract,
            view_name=args.view,
            show_domain=args.domain,
            show_ldap=args.ldap,
            show_kerberos=args.kerberos,
            ordered_steps=ordered_steps,
            summarize=args.summarize,
            ioc_export=args.ioc_export,
            ioc_out=args.ioc_out,
            output_format=args.output,
            profile_path=args.profile,
            baseline_path=args.baseline,
            compare_path=args.compare,
            streaming=args.stream or args.mp,
            mp_modules=args.mp,
            mp_workers=args.mp_workers,
            index_cache=args.index_cache,
            index_refresh=args.index_refresh,
        )

    paths = find_pcaps(target, recursive=args.recursive)
    if not paths:
        print("No pcap/pcapng files found.")
        return 2

    return _analyze_paths(
        paths,
        args.limit_protocols,
        show_status=not args.no_status,
        show_vlan=args.vlan,
        show_icmp=args.icmp,
        show_dns=args.dns,
        show_http=args.http,
        show_tls=args.tls,
        show_tcp=args.tcp,
        show_udp=args.udp,
        show_exfil=args.exfil,
        show_email=args.email,
        show_sizes=args.sizes,
        show_ips=args.ips,
        show_beacon=args.beacon,
        show_ioc=args.ioc,
        show_threats=args.threats,
        show_files=args.files,
        show_protocols=args.protocols,
        show_services=args.services,
        show_smb=args.smb,
        show_nfs=args.nfs,
        show_strings=args.strings,
        show_certificates=args.certificates,
        show_health=args.health,
        show_timeline=args.timeline,
        timeline_ip=args.timeline_ip,
        timeline_filter_ip=args.timeline_filter_ip,
        timeline_filter_port=args.timeline_filter_port,
        timeline_filter_domain=args.timeline_filter_domain,
        timeline_filter_user=args.timeline_filter_user,
        timeline_json=args.timeline_json,
        timeline_out=args.timeline_out,
        show_ntlm=args.ntlm,
        show_netbios=args.netbios,
        show_modbus=args.modbus,
        show_dnp3=args.dnp3,
        show_creds=args.creds,
        verbose=args.verbose,
        extract_name=args.extract,
        view_name=args.view,
        show_domain=args.domain,
        show_ldap=args.ldap,
        show_kerberos=args.kerberos,
        ordered_steps=ordered_steps,
        summarize=args.summarize,
        ioc_export=args.ioc_export,
        ioc_out=args.ioc_out,
        output_format=args.output,
        profile_path=args.profile,
        baseline_path=args.baseline,
        compare_path=args.compare,
        streaming=args.stream or args.mp,
        mp_modules=args.mp,
        mp_workers=args.mp_workers,
        index_cache=args.index_cache,
        index_refresh=args.index_refresh,
    )
