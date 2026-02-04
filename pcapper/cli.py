from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import analyze_pcap
from .pcap_cache import PacketListReader, load_packets
from .coloring import set_color_override
from .discovery import find_pcaps, is_supported_pcap
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
    render_generic_rollup,
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
from .timeline import analyze_timeline
from .domain import analyze_domain
from .ldap import analyze_ldap


def _ordered_steps(argv: list[str]) -> list[str]:
    flag_map = {
        "--vlan": "vlan",
        "--icmp": "icmp",
        "--dns": "dns",
        "--http": "http",
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
        "--health": "health",
        "--ntlm": "ntlm",
        "--netbios": "netbios",
        "--modbus": "modbus",
        "--dnp3": "dnp3",
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
    import pcapper.ntlm as ntlm
    import pcapper.netbios as netbios
    import pcapper.modbus as modbus
    import pcapper.dnp3 as dnp3

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
        ntlm,
        netbios,
        modbus,
        dnp3,
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
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recursively search for pcaps when target is a directory.",
    )
    parser.add_argument(
        "-l",
        "--limit-protocols",
        type=int,
        default=15,
        help="Number of protocols to show in the summary.",
    )
    parser.add_argument(
        "--vlan",
        action="store_true",
        help="Include VLAN analysis in the output.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show verbose details in analysis output.",
    )
    parser.add_argument(
        "--icmp",
        action="store_true",
        help="Include ICMP analysis in the output.",
    )
    parser.add_argument(
        "--dns",
        action="store_true",
        help="Include DNS analysis in the output.",
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Include HTTP analysis in the output.",
    )
    parser.add_argument(
        "--sizes",
        action="store_true",
        help="Include packet size distribution analysis.",
    )
    parser.add_argument(
        "--ips",
        action="store_true",
        help="Include IP address intelligence and conversation analysis.",
    )
    parser.add_argument(
        "--beacon",
        action="store_true",
        help="Include beaconing analysis in the output.",
    )
    parser.add_argument(
        "--threats",
        action="store_true",
        help="Include consolidated threat detections in the output.",
    )
    parser.add_argument(
        "--files",
        action="store_true",
        help="Include file transfer discovery in the output.",
    )
    parser.add_argument(
        "--protocols",
        action="store_true",
        help="Include detailed protocol hierarchy and anomaly analysis.",
    )
    parser.add_argument(
        "--services",
        action="store_true",
        help="Include service discovery and cybersecurity risk analysis.",
    )
    parser.add_argument(
        "--smb",
        action="store_true",
        help="Include SMB protocol analysis (Versioning, Shares, Anomalies).",
    )
    parser.add_argument(
        "--nfs",
        action="store_true",
        help="Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies).",
    )
    parser.add_argument(
        "--strings",
        action="store_true",
        help="Include cleartext strings extraction and anomaly analysis.",
    )
    parser.add_argument(
        "--certificates",
        action="store_true",
        help="Include TLS certificate extraction and analysis.",
    )
    parser.add_argument(
        "--timeline",
        action="store_true",
        help="Include a threat-hunting timeline for a specific IP (use with -ip).",
    )
    parser.add_argument(
        "--domain",
        action="store_true",
        help="Include MS AD and domain analysis (services, users, DCs, artifacts).",
    )
    parser.add_argument(
        "--ldap",
        action="store_true",
        help="Include LDAP analysis (queries, users, servers, anomalies, secrets).",
    )
    parser.add_argument(
        "-ip",
        dest="timeline_ip",
        help="Target IP for timeline analysis (use with --timeline).",
    )
    parser.add_argument(
        "--health",
        action="store_true",
        help="Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs).",
    )
    parser.add_argument(
        "--ntlm",
        action="store_true",
        help="Include NTLM authentication analysis (Users, Domains, Versions).",
    )
    parser.add_argument(
        "--netbios",
        action="store_true",
        help="Include NetBIOS name service analysis (Names, Groups, Roles).",
    )
    parser.add_argument(
        "--modbus",
        action="store_true",
        help="Include Modbus/TCP status and security analysis (Functions, Units, Anomalies).",
    )
    parser.add_argument(
        "--dnp3",
        action="store_true",
        help="Include DNP3 protocol analysis (Functions, Restarts, File Ops).",
    )
    parser.add_argument(
        "--extract",
        metavar="FILENAME",
        help="Extract a discovered file by name into ./files (use with --files).",
    )
    parser.add_argument(
        "--view",
        metavar="FILENAME",
        help="View extracted file content in ASCII/HEX (use with --files).",
    )
    parser.add_argument(
        "--no-status",
        action="store_true",
        help="Disable the processing status bar.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    parser.add_argument(
        "-summarize",
        "--summarize",
        action="store_true",
        help="Summarize supported analysis across all pcaps (e.g., --modbus, --dnp3).",
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
    show_sizes: bool,
    show_ips: bool,
    show_beacon: bool,
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
    show_ntlm: bool,
    show_netbios: bool,
    show_modbus: bool,
    show_dnp3: bool,
    verbose: bool,
    extract_name: str | None,
    view_name: str | None,
    show_domain: bool,
    show_ldap: bool,
    ordered_steps: list[str],
    summarize: bool,
) -> int:
    if not paths:
        return 1

    summarize_rollups = summarize and len(paths) > 1
    modbus_rollups = []
    dnp3_rollups = []
    rollups: dict[str, list[object]] = {}

    for idx, path in enumerate(paths, start=1):
        packets, meta = load_packets(path, show_status=show_status)
        _patch_readers(packets, meta)

        summary = analyze_pcap(path, show_status=False, packets=packets, meta=meta)
        print(render_summary(summary, protocol_limit=protocol_limit))

        for step in ordered_steps:
            if step == "vlan" and show_vlan:
                vlan_summary = analyze_vlans(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("vlan", []).append(vlan_summary)
                else:
                    print(render_vlan_summary(vlan_summary, verbose=verbose))
            elif step == "icmp" and show_icmp:
                icmp_summary = analyze_icmp(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("icmp", []).append(icmp_summary)
                else:
                    print(render_icmp_summary(icmp_summary, verbose=verbose))
            elif step == "dns" and show_dns:
                dns_summary = analyze_dns(path, show_status=False, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("dns", []).append(dns_summary)
                else:
                    print(render_dns_summary(dns_summary, verbose=verbose))
            elif step == "http" and show_http:
                http_summary = analyze_http(path, show_status=False, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("http", []).append(http_summary)
                else:
                    print(render_http_summary(http_summary, verbose=verbose))
            elif step == "sizes" and show_sizes:
                size_summary = analyze_sizes(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("sizes", []).append(size_summary)
                else:
                    print(render_sizes_summary(size_summary, verbose=verbose))
            elif step == "ips" and show_ips:
                ips_summary = analyze_ips(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("ips", []).append(ips_summary)
                else:
                    print(render_ips_summary(ips_summary, verbose=verbose))
            elif step == "beacon" and show_beacon:
                beacon_summary = analyze_beacons(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("beacon", []).append(beacon_summary)
                else:
                    print(render_beacon_summary(beacon_summary, verbose=verbose))
            elif step == "threats" and show_threats:
                threat_summary = analyze_threats(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("threats", []).append(threat_summary)
                else:
                    print(render_threats_summary(threat_summary))
            elif step == "files" and show_files:
                files_summary = analyze_files(
                    path,
                    extract_name=extract_name,
                    view_name=view_name,
                    show_status=False,
                    include_x509=verbose,
                )
                if summarize_rollups:
                    rollups.setdefault("files", []).append(files_summary)
                else:
                    print(render_files_summary(files_summary))
            elif step == "protocols" and show_protocols:
                proto_summary = analyze_protocols(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("protocols", []).append(proto_summary)
                else:
                    print(render_protocols_summary(proto_summary, verbose=verbose))
            elif step == "services" and show_services:
                svc_summary = analyze_services(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("services", []).append(svc_summary)
                else:
                    print(render_services_summary(svc_summary))
            elif step == "smb" and show_smb:
                smb_summary = analyze_smb(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("smb", []).append(smb_summary)
                else:
                    print(render_smb_summary(smb_summary, verbose=verbose))
            elif step == "nfs" and show_nfs:
                nfs_summary = analyze_nfs(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("nfs", []).append(nfs_summary)
                else:
                    print(render_nfs_summary(nfs_summary))
            elif step == "strings" and show_strings:
                strings_summary = analyze_strings(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("strings", []).append(strings_summary)
                else:
                    print(render_strings_summary(strings_summary))
            elif step == "certificates" and show_certificates:
                cert_summary = analyze_certificates(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("certificates", []).append(cert_summary)
                else:
                    print(render_certificates_summary(cert_summary))
            elif step == "health" and show_health:
                health_summary = analyze_health(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("health", []).append(health_summary)
                else:
                    print(render_health_summary(health_summary))
            elif step == "timeline" and show_timeline and timeline_ip:
                timeline_summary = analyze_timeline(path, timeline_ip, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("timeline", []).append(timeline_summary)
                else:
                    print(render_timeline_summary(timeline_summary))
            elif step == "domain" and show_domain:
                domain_summary = analyze_domain(path, show_status=False, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("domain", []).append(domain_summary)
                else:
                    print(render_domain_summary(domain_summary))
            elif step == "ldap" and show_ldap:
                ldap_summary = analyze_ldap(path, show_status=False, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ldap", []).append(ldap_summary)
                else:
                    print(render_ldap_summary(ldap_summary))
            elif step == "ntlm" and show_ntlm:
                ntlm_summary = analyze_ntlm(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("ntlm", []).append(ntlm_summary)
                else:
                    print(render_ntlm_summary(ntlm_summary))
            elif step == "netbios" and show_netbios:
                nb_summary = analyze_netbios(path, show_status=False)
                if summarize_rollups:
                    rollups.setdefault("netbios", []).append(nb_summary)
                else:
                    print(render_netbios_summary(nb_summary))
            elif step == "modbus" and show_modbus:
                modbus_summary = analyze_modbus(path, show_status=False)
                if summarize_rollups:
                    modbus_rollups.append(modbus_summary)
                else:
                    print(render_modbus_summary(modbus_summary, verbose=verbose))
            elif step == "dnp3" and show_dnp3:
                dnp3_summary = analyze_dnp3(path, show_status=False)
                if summarize_rollups:
                    dnp3_rollups.append(dnp3_summary)
                else:
                    print(render_dnp3_summary(dnp3_summary))
        if idx < len(paths):
            print()

    if summarize_rollups:
        title_map = {
            "vlan": "VLAN ANALYSIS",
            "icmp": "ICMP ANALYSIS",
            "dns": "DNS ANALYSIS",
            "http": "HTTP ANALYSIS",
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
            "ntlm": "NTLM ANALYSIS",
            "netbios": "NETBIOS ANALYSIS",
        }
        for step in ordered_steps:
            if step in ("modbus", "dnp3", "vlan"):
                continue
            if rollups.get(step):
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
            show_sizes=args.sizes,
            show_ips=args.ips,
            show_beacon=args.beacon,
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
            show_ntlm=args.ntlm,
            show_netbios=args.netbios,
            show_modbus=args.modbus,
            show_dnp3=args.dnp3,
            verbose=args.verbose,
            extract_name=args.extract,
            view_name=args.view,
            show_domain=args.domain,
            show_ldap=args.ldap,
            ordered_steps=ordered_steps,
            summarize=args.summarize,
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
        show_sizes=args.sizes,
        show_ips=args.ips,
        show_beacon=args.beacon,
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
        show_ntlm=args.ntlm,
        show_netbios=args.netbios,
        show_modbus=args.modbus,
        show_dnp3=args.dnp3,
        verbose=args.verbose,
        extract_name=args.extract,
        view_name=args.view,
        show_domain=args.domain,
        show_ldap=args.ldap,
        ordered_steps=ordered_steps,
        summarize=args.summarize,
    )
