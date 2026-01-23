from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import analyze_pcap
from .coloring import set_color_override
from .discovery import find_pcaps, is_supported_pcap
from .reporting import (
    render_summary,
    render_vlan_summary,
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
    render_dnp3_summary,
    render_ips_summary,
    render_http_summary,
    render_sizes_summary,
    render_nfs_summary,
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcapper",
        description="Modular PCAP analyzer for fast triage and reporting.",
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
    show_ntlm: bool,
    show_netbios: bool,
    show_modbus: bool,
    show_dnp3: bool,
    verbose: bool,
    extract_name: str | None,
    view_name: str | None,
) -> int:
    if not paths:
        return 1

    for idx, path in enumerate(paths, start=1):
        summary = analyze_pcap(path, show_status=show_status)
        print(render_summary(summary, protocol_limit=protocol_limit))
        if show_vlan:
            vlan_summary = analyze_vlans(path, show_status=show_status)
            print(render_vlan_summary(vlan_summary, verbose=verbose))
        if show_icmp:
            icmp_summary = analyze_icmp(path, show_status=show_status)
            print(render_icmp_summary(icmp_summary, verbose=verbose))
        if show_dns:
            dns_summary = analyze_dns(path, show_status=show_status)
            print(render_dns_summary(dns_summary, verbose=verbose))
        if show_http:
            http_summary = analyze_http(path, show_status=show_status)
            print(render_http_summary(http_summary, verbose=verbose))
        if show_sizes:
            size_summary = analyze_sizes(path, show_status=show_status)
            print(render_sizes_summary(size_summary, verbose=verbose))
        if show_ips:
            ips_summary = analyze_ips(path, show_status=show_status)
            print(render_ips_summary(ips_summary, verbose=verbose))
        if show_beacon:
            beacon_summary = analyze_beacons(path, show_status=show_status)
            print(render_beacon_summary(beacon_summary, verbose=verbose))
        if show_threats:
            threat_summary = analyze_threats(path, show_status=show_status)
            print(render_threats_summary(threat_summary))
        if show_files:
            files_summary = analyze_files(path, extract_name=extract_name, view_name=view_name, show_status=show_status)
            print(render_files_summary(files_summary))
        if show_protocols:
            proto_summary = analyze_protocols(path, show_status=show_status)
            print(render_protocols_summary(proto_summary, verbose=verbose))
        if show_services:
            svc_summary = analyze_services(path, show_status=show_status)
            print(render_services_summary(svc_summary))
        if show_smb:
            smb_summary = analyze_smb(path, show_status=show_status)
            print(render_smb_summary(smb_summary))
        if show_nfs:
            nfs_summary = analyze_nfs(path, show_status=show_status)
            print(render_nfs_summary(nfs_summary))
        if show_ntlm:
            ntlm_summary = analyze_ntlm(path, show_status=show_status)
            print(render_ntlm_summary(ntlm_summary))
        if show_netbios:
            nb_summary = analyze_netbios(path, show_status=show_status)
            print(render_netbios_summary(nb_summary))
        if show_modbus:
            modbus_summary = analyze_modbus(path, show_status=show_status)
            print(render_modbus_summary(modbus_summary))
        if show_dnp3:
            dnp3_summary = analyze_dnp3(path, show_status=show_status)
            print(render_dnp3_summary(dnp3_summary))
        if idx < len(paths):
            print()
    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    compile_date = datetime.now(timezone.utc).date().isoformat()
    banner = [
        "============================================================",
        "  _____   _____   _____   _____   _____   _____ ",
        " |  _  | |  _  | |  _  | |  _  | |  _  | |  _  |",
        " | |_| | | |_| | | |_| | | |_| | | |_| | | |_| |",
        " |_____| |_____| |_____| |_____| |_____| |_____|",
        "     P  C  A  P  P  E  R",
        "============================================================",
        f"  PCAPPER v{__version__}  ::  Compile Date {compile_date}",
        "============================================================",
    ]
    print("\n".join(banner))

    if args.no_color:
        set_color_override(False)

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
            show_ntlm=args.ntlm,
            show_netbios=args.netbios,
            show_modbus=args.modbus,
            show_dnp3=args.dnp3,
            verbose=args.verbose,
            extract_name=args.extract,
            view_name=args.view,
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
        show_ntlm=args.ntlm,
        show_netbios=args.netbios,
        show_modbus=args.modbus,
        show_dnp3=args.dnp3,
        verbose=args.verbose,
        extract_name=args.extract,
        view_name=args.view,
    )
