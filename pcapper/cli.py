from __future__ import annotations

import argparse
import glob
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .analyzer import analyze_pcap, merge_pcap_summaries
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
    render_nfs_summary,
    render_strings_summary,
    render_search_summary,
    render_search_rollup,
    render_creds_summary,
    render_certificates_summary,
    render_health_summary,
    render_hostname_summary,
    render_timeline_summary,
    render_domain_summary,
    render_ldap_summary,
    render_kerberos_summary,
    render_tls_summary,
    render_ssh_summary,
    render_syslog_summary,
    render_tcp_summary,
    render_udp_summary,
    render_udp_rollup,
    render_exfil_summary,
    render_generic_rollup,
)
from .vlan import analyze_vlans
from .icmp import analyze_icmp
from .dns import analyze_dns
from .beacon import analyze_beacons
from .threats import analyze_threats, merge_threats_summaries
from .files import analyze_files
from .protocols import analyze_protocols
from .services import analyze_services
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
from .nfs import analyze_nfs
from .strings import analyze_strings
from .search import analyze_search
from .creds import analyze_creds
from .certificates import analyze_certificates
from .health import analyze_health
from .hostname import analyze_hostname, merge_hostname_summaries
from .timeline import analyze_timeline, merge_timeline_summaries
from .domain import analyze_domain
from .ldap import analyze_ldap
from .kerberos import analyze_kerberos
from .tls import analyze_tls
from .ssh import analyze_ssh
from .syslog import analyze_syslog
from .tcp import analyze_tcp
from .udp import analyze_udp
from .exfil import analyze_exfil


def _ordered_steps(argv: list[str]) -> list[str]:
    flag_map = {
        "--search": "search",
        "--creds": "creds",
        "--vlan": "vlan",
        "--icmp": "icmp",
        "--dns": "dns",
        "--http": "http",
        "--tls": "tls",
        "--ssh": "ssh",
        "--syslog": "syslog",
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
        "--hostname": "hostname",
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
    }
    ordered: list[str] = []
    seen: set[str] = set()
    for arg in argv:
        step = flag_map.get(arg)
        if step and step not in seen:
            ordered.append(step)
            seen.add(step)
    return ordered


def _build_banner() -> str:
    compile_date = datetime.now(timezone.utc).date().isoformat()
    banner = [
        "======================================================================",
        "   ██████╗  ██████╗  █████╗ ██████╗ ██████╗ ███████╗██████╗     ",
        "   ██╔══██╗██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗    ",
        "   ██████╔╝██║      ███████║██████╔╝██████╔╝█████╗  ██████╔╝    ",
        "   ██╔═══╝ ██║      ██╔══██║██╔═══╝ ██╔═══╝ ██╔══╝  ██╔══██╗    ",
        "   ██║     ╚██████╗ ██║  ██║██║     ██║     ███████╗██║  ██║    ",
        "   ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚══════╝╚═╝  ╚═╝ ICS",
        "======================================================================",
        f"  PCAPPER v{__version__}  ::  Compile Date {compile_date}",
        "======================================================================",
    ]
    return "\n".join(banner)


def _has_glob_wildcards(value: str) -> bool:
    return any(ch in value for ch in "*?[]")


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
        nargs="+",
        help="Path(s) to pcap/pcapng file(s), wildcard pattern(s), or director(ies) of captures.",
    )
    general = parser.add_argument_group("GENERAL FLAGS")
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
        help="Target IP for timeline/hostname analysis (use with --timeline or --hostname).",
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
        "--search",
        metavar="STRING",
        help="Search packet payloads for a string (case-insensitive) and list matches.",
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
        "--view",
        metavar="FILENAME",
        help="View extracted file content in ASCII/HEX (use with --files).",
    )

    it_group = parser.add_argument_group("IT/ENTERPRISE FUNCTIONS")
    it_flags = [
        ("--arp", "Include ARP analysis (conversations, poisoning signals, anomalies, artifacts)."),
        ("--beacon", "Include beaconing analysis in the output."),
        ("--certificates", "Include TLS certificate extraction and analysis."),
        ("--creds", "Scan for credential exposure (HTTP, FTP, SMTP, DNS, etc.)."),
        ("--dhcp", "Include DHCP analysis (leases, options, clients/servers, attacks, anomalies)."),
        ("--dns", "Include DNS analysis in the output."),
        ("--domain", "Include MS AD and domain analysis (services, users, DCs, artifacts)."),
        ("--exfil", "Include exfiltration heuristics and anomaly analysis."),
        ("--files", "Include file transfer discovery in the output."),
        ("--health", "Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs)."),
        ("--hostname", "Find hostnames for a target IP across DNS/HTTP/TLS/SMB/NetBIOS (use with -ip)."),
        ("--http", "Include HTTP analysis in the output."),
        ("--icmp", "Include ICMP analysis in the output."),
        ("--ips", "Include IP address intelligence and conversation analysis."),
        ("--kerberos", "Include Kerberos analysis (requests, errors, principals, attacks)."),
        ("--ldap", "Include LDAP analysis (queries, users, servers, anomalies, secrets)."),
        ("--netbios", "Include NetBIOS name service analysis (Names, Groups, Roles)."),
        ("--nfs", "Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies)."),
        ("--ntlm", "Include NTLM authentication analysis (Users, Domains, Versions)."),
        ("--protocols", "Include detailed protocol hierarchy and anomaly analysis."),
        ("--services", "Include service discovery and cybersecurity risk analysis."),
        ("--sizes", "Include packet size distribution analysis."),
        ("--smb", "Include SMB protocol analysis (Versioning, Shares, Anomalies)."),
        ("--ssh", "Include SSH analysis (sessions, versions, plaintext, anomalies)."),
        ("--strings", "Include cleartext strings extraction and anomaly analysis."),
        ("--syslog", "Include syslog analysis (messages, clients, severity, anomalies)."),
        ("--tcp", "Include TCP analysis in the output."),
        ("--threats", "Include consolidated threat detections in the output."),
        ("--timeline", "Include a threat-hunting timeline for a specific IP (use with -ip)."),
        ("--tls", "Include TLS/HTTPS analysis in the output."),
        ("--udp", "Include UDP analysis in the output."),
        ("--vlan", "Include VLAN analysis in the output."),
    ]
    for flag, help_text in it_flags:
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
        ("--yokogawa", "Include Yokogawa Vnet/IP analysis."),
    ]
    for flag, help_text in ics_flags:
        ics_group.add_argument(flag, action="store_true", help=help_text)
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
    show_http: bool,
    show_tls: bool,
    show_ssh: bool,
    show_syslog: bool,
    show_tcp: bool,
    show_udp: bool,
    show_exfil: bool,
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
    show_creds: bool,
    show_certificates: bool,
    show_health: bool,
    show_hostname: bool,
    show_timeline: bool,
    timeline_ip: str | None,
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
    show_domain: bool,
    show_ldap: bool,
    show_kerberos: bool,
    ordered_steps: list[str],
    summarize: bool,
    show_dhcp: bool = False,
) -> int:
    if not paths:
        return 1

    summarize_rollups = summarize and len(paths) > 0
    render_base_summary = show_base or len(ordered_steps) == 0
    base_rollups = []
    modbus_rollups = []
    dnp3_rollups = []
    rollups: dict[str, list[object]] = {}

    for idx, path in enumerate(paths, start=1):
        packets = None
        meta = None

        if render_base_summary:
            summary = analyze_pcap(path, show_status=show_status, packets=packets, meta=meta)
            if summarize_rollups:
                base_rollups.append(summary)
            else:
                print(render_summary(summary, protocol_limit=protocol_limit))

        for step in ordered_steps:
            if step == "search" and search_query:
                search_summary = analyze_search(
                    path,
                    search_query,
                    show_status=show_status,
                    packets=packets,
                    meta=meta,
                    case_sensitive=search_case,
                )
                if summarize_rollups:
                    rollups.setdefault("search", []).append(search_summary)
                else:
                    print(render_search_summary(search_summary))
            elif step == "vlan" and show_vlan:
                vlan_summary = analyze_vlans(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("vlan", []).append(vlan_summary)
                else:
                    print(render_vlan_summary(vlan_summary, verbose=verbose))
            elif step == "icmp" and show_icmp:
                icmp_summary = analyze_icmp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("icmp", []).append(icmp_summary)
                else:
                    print(render_icmp_summary(icmp_summary, verbose=verbose))
            elif step == "dns" and show_dns:
                dns_summary = analyze_dns(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("dns", []).append(dns_summary)
                else:
                    print(render_dns_summary(dns_summary, verbose=verbose))
            elif step == "http" and show_http:
                http_summary = analyze_http(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("http", []).append(http_summary)
                else:
                    print(render_http_summary(http_summary, verbose=verbose))
            elif step == "tls" and show_tls:
                tls_summary = analyze_tls(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("tls", []).append(tls_summary)
                else:
                    print(render_tls_summary(tls_summary, verbose=verbose))
            elif step == "ssh" and show_ssh:
                ssh_summary = analyze_ssh(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ssh", []).append(ssh_summary)
                else:
                    print(render_ssh_summary(ssh_summary, verbose=verbose))
            elif step == "syslog" and show_syslog:
                syslog_summary = analyze_syslog(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("syslog", []).append(syslog_summary)
                else:
                    print(render_syslog_summary(syslog_summary, verbose=verbose))
            elif step == "tcp" and show_tcp:
                tcp_summary = analyze_tcp(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("tcp", []).append(tcp_summary)
                else:
                    print(render_tcp_summary(tcp_summary, verbose=verbose))
            elif step == "udp" and show_udp:
                udp_summary = analyze_udp(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("udp", []).append(udp_summary)
                else:
                    print(render_udp_summary(udp_summary, verbose=verbose))
            elif step == "exfil" and show_exfil:
                exfil_summary = analyze_exfil(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("exfil", []).append(exfil_summary)
                else:
                    print(render_exfil_summary(exfil_summary, verbose=verbose))
            elif step == "sizes" and show_sizes:
                size_summary = analyze_sizes(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("sizes", []).append(size_summary)
                else:
                    print(render_sizes_summary(size_summary, verbose=verbose))
            elif step == "ips" and show_ips:
                ips_summary = analyze_ips(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("ips", []).append(ips_summary)
                else:
                    print(render_ips_summary(ips_summary, verbose=verbose))
            elif step == "beacon" and show_beacon:
                beacon_summary = analyze_beacons(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("beacon", []).append(beacon_summary)
                else:
                    print(render_beacon_summary(beacon_summary, verbose=verbose))
            elif step == "threats" and show_threats:
                threat_summary = analyze_threats(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("threats", []).append(threat_summary)
                else:
                    print(render_threats_summary(threat_summary, verbose=verbose))
            elif step == "files" and show_files:
                files_summary = analyze_files(
                    path,
                    extract_name=extract_name,
                    view_name=view_name,
                    show_status=show_status,
                    include_x509=verbose,
                )
                if summarize_rollups:
                    rollups.setdefault("files", []).append(files_summary)
                else:
                    print(render_files_summary(files_summary))
            elif step == "protocols" and show_protocols:
                proto_summary = analyze_protocols(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("protocols", []).append(proto_summary)
                else:
                    print(render_protocols_summary(proto_summary, verbose=verbose))
            elif step == "services" and show_services:
                svc_summary = analyze_services(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("services", []).append(svc_summary)
                else:
                    print(render_services_summary(svc_summary))
            elif step == "smb" and show_smb:
                smb_summary = analyze_smb(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("smb", []).append(smb_summary)
                else:
                    print(render_smb_summary(smb_summary, verbose=verbose))
            elif step == "nfs" and show_nfs:
                nfs_summary = analyze_nfs(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("nfs", []).append(nfs_summary)
                else:
                    print(render_nfs_summary(nfs_summary))
            elif step == "strings" and show_strings:
                strings_summary = analyze_strings(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("strings", []).append(strings_summary)
                else:
                    print(render_strings_summary(strings_summary))
            elif step == "creds" and show_creds:
                creds_summary = analyze_creds(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("creds", []).append(creds_summary)
                else:
                    print(render_creds_summary(creds_summary))
            elif step == "certificates" and show_certificates:
                cert_summary = analyze_certificates(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("certificates", []).append(cert_summary)
                else:
                    print(render_certificates_summary(cert_summary))
            elif step == "health" and show_health:
                health_summary = analyze_health(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("health", []).append(health_summary)
                else:
                    print(render_health_summary(health_summary))
            elif step == "hostname" and show_hostname:
                hostname_summary = analyze_hostname(path, timeline_ip, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("hostname", []).append(hostname_summary)
                else:
                    print(render_hostname_summary(hostname_summary, verbose=verbose))
            elif step == "timeline" and show_timeline and timeline_ip:
                timeline_summary = analyze_timeline(path, timeline_ip, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("timeline", []).append(timeline_summary)
                else:
                    print(render_timeline_summary(timeline_summary))
            elif step == "domain" and show_domain:
                domain_summary = analyze_domain(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("domain", []).append(domain_summary)
                else:
                    print(render_domain_summary(domain_summary))
            elif step == "ldap" and show_ldap:
                ldap_summary = analyze_ldap(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("ldap", []).append(ldap_summary)
                else:
                    print(render_ldap_summary(ldap_summary))
            elif step == "kerberos" and show_kerberos:
                kerberos_summary = analyze_kerberos(path, show_status=show_status, packets=packets, meta=meta)
                if summarize_rollups:
                    rollups.setdefault("kerberos", []).append(kerberos_summary)
                else:
                    print(render_kerberos_summary(kerberos_summary))
            elif step == "ntlm" and show_ntlm:
                ntlm_summary = analyze_ntlm(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("ntlm", []).append(ntlm_summary)
                else:
                    print(render_ntlm_summary(ntlm_summary))
            elif step == "netbios" and show_netbios:
                nb_summary = analyze_netbios(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("netbios", []).append(nb_summary)
                else:
                    print(render_netbios_summary(nb_summary))
            elif step == "arp" and show_arp:
                arp_summary = analyze_arp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("arp", []).append(arp_summary)
                else:
                    print(render_arp_summary(arp_summary, verbose=verbose))
            elif step == "dhcp" and show_dhcp:
                dhcp_summary = analyze_dhcp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("dhcp", []).append(dhcp_summary)
                else:
                    print(render_dhcp_summary(dhcp_summary, verbose=verbose))
            elif step == "modbus" and show_modbus:
                modbus_summary = analyze_modbus(path, show_status=show_status)
                if summarize_rollups:
                    modbus_rollups.append(modbus_summary)
                else:
                    print(render_modbus_summary(modbus_summary, verbose=verbose))
            elif step == "dnp3" and show_dnp3:
                dnp3_summary = analyze_dnp3(path, show_status=show_status)
                if summarize_rollups:
                    dnp3_rollups.append(dnp3_summary)
                else:
                    print(render_dnp3_summary(dnp3_summary))
            elif step == "iec104" and show_iec104:
                summary = analyze_iec104(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("iec104", []).append(summary)
                else:
                    print(render_iec104_summary(summary))
            elif step == "bacnet" and show_bacnet:
                summary = analyze_bacnet(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("bacnet", []).append(summary)
                else:
                    print(render_bacnet_summary(summary))
            elif step == "enip" and show_enip:
                summary = analyze_enip(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("enip", []).append(summary)
                else:
                    print(render_enip_summary(summary))
            elif step == "profinet" and show_profinet:
                summary = analyze_profinet(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("profinet", []).append(summary)
                else:
                    print(render_profinet_summary(summary))
            elif step == "s7" and show_s7:
                summary = analyze_s7(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("s7", []).append(summary)
                else:
                    print(render_s7_summary(summary))
            elif step == "opc" and show_opc:
                summary = analyze_opc(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("opc", []).append(summary)
                else:
                    print(render_opc_summary(summary))
            elif step == "ethercat" and show_ethercat:
                summary = analyze_ethercat(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("ethercat", []).append(summary)
                else:
                    print(render_ethercat_summary(summary))
            elif step == "fins" and show_fins:
                summary = analyze_fins(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("fins", []).append(summary)
                else:
                    print(render_fins_summary(summary))
            elif step == "crimson" and show_crimson:
                summary = analyze_crimson(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("crimson", []).append(summary)
                else:
                    print(render_crimson_summary(summary))
            elif step == "pcworx" and show_pcworx:
                summary = analyze_pcworx(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("pcworx", []).append(summary)
                else:
                    print(render_pcworx_summary(summary))
            elif step == "melsec" and show_melsec:
                summary = analyze_melsec(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("melsec", []).append(summary)
                else:
                    print(render_melsec_summary(summary))
            elif step == "cip" and show_cip:
                summary = analyze_cip(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("cip", []).append(summary)
                else:
                    print(render_cip_summary(summary))
            elif step == "odesys" and show_odesys:
                summary = analyze_odesys(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("odesys", []).append(summary)
                else:
                    print(render_odesys_summary(summary))
            elif step == "niagara" and show_niagara:
                summary = analyze_niagara(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("niagara", []).append(summary)
                else:
                    print(render_niagara_summary(summary))
            elif step == "mms" and show_mms:
                summary = analyze_mms(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("mms", []).append(summary)
                else:
                    print(render_mms_summary(summary))
            elif step == "srtp" and show_srtp:
                summary = analyze_srtp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("srtp", []).append(summary)
                else:
                    print(render_srtp_summary(summary))
            elif step == "df1" and show_df1:
                summary = analyze_df1(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("df1", []).append(summary)
                else:
                    print(render_df1_summary(summary))
            elif step == "pccc" and show_pccc:
                summary = analyze_pccc(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("pccc", []).append(summary)
                else:
                    print(render_pccc_summary(summary))
            elif step == "csp" and show_csp:
                summary = analyze_csp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("csp", []).append(summary)
                else:
                    print(render_csp_summary(summary))
            elif step == "modicon" and show_modicon:
                summary = analyze_modicon(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("modicon", []).append(summary)
                else:
                    print(render_modicon_summary(summary))
            elif step == "yokogawa" and show_yokogawa:
                summary = analyze_yokogawa(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("yokogawa", []).append(summary)
                else:
                    print(render_yokogawa_summary(summary))
            elif step == "honeywell" and show_honeywell:
                summary = analyze_honeywell(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("honeywell", []).append(summary)
                else:
                    print(render_honeywell_summary(summary))
            elif step == "mqtt" and show_mqtt:
                summary = analyze_mqtt(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("mqtt", []).append(summary)
                else:
                    print(render_mqtt_summary(summary))
            elif step == "coap" and show_coap:
                summary = analyze_coap(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("coap", []).append(summary)
                else:
                    print(render_coap_summary(summary))
            elif step == "hart" and show_hart:
                summary = analyze_hart(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("hart", []).append(summary)
                else:
                    print(render_hart_summary(summary))
            elif step == "prconos" and show_prconos:
                summary = analyze_prconos(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("prconos", []).append(summary)
                else:
                    print(render_prconos_summary(summary))
            elif step == "iccp" and show_iccp:
                summary = analyze_iccp(path, show_status=show_status)
                if summarize_rollups:
                    rollups.setdefault("iccp", []).append(summary)
                else:
                    print(render_iccp_summary(summary))
        if idx < len(paths):
            print()

    if summarize_rollups:
        if base_rollups:
            merged_base = merge_pcap_summaries(base_rollups)
            print(render_summary(merged_base, protocol_limit=protocol_limit))
            if rollups or modbus_rollups or dnp3_rollups:
                print()
        title_map = {
            "search": "SEARCH RESULTS",
            "vlan": "VLAN ANALYSIS",
            "icmp": "ICMP ANALYSIS",
            "dns": "DNS ANALYSIS",
            "http": "HTTP ANALYSIS",
            "tls": "TLS/HTTPS ANALYSIS",
            "ssh": "SSH ANALYSIS",
            "syslog": "SYSLOG ANALYSIS",
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
            "creds": "CREDENTIAL EXPOSURE",
            "certificates": "CERTIFICATE ANALYSIS",
            "health": "TRAFFIC HEALTH ANALYSIS",
            "hostname": "HOSTNAME DISCOVERY",
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
        }
        rollup_steps = [step for step in title_map.keys() if rollups.get(step)]
        for step in rollup_steps:
            if step in ("modbus", "dnp3", "vlan"):
                continue
            if rollups.get(step):
                if step == "search":
                    print(render_search_rollup(rollups[step]))
                elif step == "ips":
                    merged_ips = merge_ips_summaries(rollups[step])
                    print(render_ips_summary(merged_ips, verbose=verbose))
                elif step == "timeline":
                    merged_timeline = merge_timeline_summaries(rollups[step])
                    print(render_timeline_summary(merged_timeline))
                elif step == "hostname":
                    merged_hostname = merge_hostname_summaries(rollups[step])
                    print(render_hostname_summary(merged_hostname, verbose=verbose))
                elif step == "threats":
                    merged_threats = merge_threats_summaries(rollups[step])
                    print(render_threats_summary(merged_threats, verbose=verbose))
                elif step == "enip":
                    merged_enip = merge_enip_summaries(rollups[step])
                    print(render_enip_summary(merged_enip))
                elif step == "cip":
                    merged_cip = merge_cip_summaries(rollups[step])
                    print(render_cip_summary(merged_cip))
                elif step == "udp":
                    print(render_udp_rollup(rollups[step], verbose=verbose))
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
        show_http=args.http,
        show_tls=args.tls,
        show_ssh=args.ssh,
        show_syslog=args.syslog,
        show_tcp=args.tcp,
        show_udp=args.udp,
        show_exfil=args.exfil,
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
        show_creds=args.creds,
        show_certificates=args.certificates,
        show_health=args.health,
        show_hostname=args.hostname,
        show_timeline=args.timeline,
        timeline_ip=args.timeline_ip,
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
        show_domain=args.domain,
        show_ldap=args.ldap,
        show_kerberos=args.kerberos,
        ordered_steps=ordered_steps,
        summarize=args.summarize,
    )
