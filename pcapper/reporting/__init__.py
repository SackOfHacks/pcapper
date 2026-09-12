"""Rendered report output for every pcapper analyzer.

Formerly one 30,000-line module. It is now one module per analyzer, with
the shared primitives in :mod:`._common`. Every name the old module
defined is re-exported here, so existing imports keep working unchanged.
"""

# ruff: noqa: F401

from ._common import (
    SECTION_BAR,
    SUBSECTION_BAR,
    _FULL_OUTPUT_LIMIT,
    _IPV4_RE,
    _IPV6_RE,
    _OT_ATTACK_KEYWORDS,
    _OT_CMD_CONTROL_KW,
    _OT_CMD_READ_KW,
    _OT_CMD_REVIEW_KW,
    _OT_CMD_WRITE_VERB,
    _OT_FULL_OUTPUT,
    _OUI_ANNOTATE,
    _PLAINTEXT_WORD_RE,
    _PROTO_SEV_RANK,
    _QUIET_MODE,
    _SizeBucketLike,
    _VERBOSE_OUTPUT,
    _always_full_render,
    _annotate_macs,
    _apply_verbose_limit,
    _collapse_detection_details,
    _collapse_rollup_detections,
    _conv_value,
    _counter_table,
    _filtered_detections,
    _finalize_output,
    _format_client_server_table,
    _format_counter,
    _format_kv,
    _format_sessions_table,
    _format_table,
    _highlight_public_ips,
    _is_meaningful_plaintext,
    _limit_value,
    _meaningful_plaintext_items,
    _merge_detection_evidence_lines,
    _merge_ranked_detection_pairs,
    _normalize_finding,
    _ot_attack_for_title,
    _ot_command_risk,
    _ot_full_output,
    _ot_full_render,
    _oui_annotate,
    _quiet_mode,
    _redact_in_text,
    _redact_secret,
    _render_deterministic_checks,
    _render_industrial_summary,
    _render_ot_protocol_summary,
    _render_ot_verdict,
    _render_protocol_verdict,
    _short_browser_role,
    _truncate_text,
    _verbose_output,
    is_oui_annotation_enabled,
    is_quiet_mode,
    set_oui_annotation,
    set_quiet_mode,
    set_verbose_output,
)
from .aim import (
    render_aim_summary,
)
from .arp import (
    render_arp_summary,
)
from .bacnet import (
    render_bacnet_summary,
)
from .baseline_delta import (
    render_baseline_delta,
)
from .beacon import (
    _BEACON_SEV_RANK,
    _beacon_classify,
    _beacon_ip_is_private,
    _beacon_ip_is_public,
    render_beacon_summary,
)
from .bsap import (
    render_bsap_summary,
)
from .carve import (
    render_carve_summary,
)
from .certificates import (
    render_certificates_summary,
)
from .cip import (
    _render_cip_baseline_sections,
    _render_cip_verdict,
    render_cip_summary,
)
from .coap import (
    render_coap_summary,
)
from .codesys import (
    render_codesys_summary,
)
from .compromised import (
    _COMPROMISE_ISSUE_REASONS,
    _compromise_issue_reason,
    _dedupe_compromise_issues,
    render_compromised_summary,
)
from .control_loop import (
    render_control_loop_summary,
)
from .correlation import (
    render_correlation_summary,
)
from .creds import (
    render_creds_summary,
)
from .crimson import (
    render_crimson_summary,
)
from .csp import (
    render_csp_summary,
)
from .ctf import (
    render_ctf_summary,
)
from .decode import (
    render_decode_summary,
)
from .decrypt import (
    render_decrypt_summary,
)
from .df1 import (
    render_df1_summary,
)
from .dhcp import (
    render_dhcp_summary,
)
from .dnp3 import (
    render_dnp3_rollup,
    render_dnp3_summary,
)
from .dns import (
    render_dns_summary,
)
from .domain import (
    render_domain_summary,
)
from .email import (
    _email_mitre_techniques,
    render_email_summary,
)
from .encrypted_dns import (
    render_encrypted_dns_summary,
)
from .enip import (
    _render_enip_baseline_sections,
    _render_enip_verdict,
    render_enip_summary,
)
from .ethercat import (
    render_ethercat_summary,
)
from .exfil import (
    render_exfil_summary,
)
from .files import (
    render_files_summary,
)
from .fins import (
    render_fins_summary,
)
from .ftp import (
    render_ftp_summary,
)
from .generic import (
    render_generic_rollup,
)
from .genisys import (
    render_genisys_summary,
)
from .goose import (
    render_goose_summary,
)
from .hart import (
    render_hart_summary,
)
from .health import (
    render_health_summary,
)
from .honeywell import (
    render_honeywell_summary,
)
from .hostdetails import (
    _HD_REMOTE_ACCESS_PORTS,
    _hd_remote_access_flag,
    _packet_number_hint,
    render_hostdetails_summary,
)
from .hostname import (
    render_hostname_summary,
)
from .hosts import (
    render_hosts_summary,
)
from .http import (
    _HTTP_STATUS_TEXT,
    _http_status_text,
    render_http_summary,
)
from .http2 import (
    render_http2_summary,
)
from .iccp import (
    render_iccp_summary,
)
from .icmp import (
    render_icmp_summary,
)
from .iec101_103 import (
    render_iec101_103_summary,
)
from .iec104 import (
    render_iec104_summary,
)
from .ioc import (
    render_ioc_summary,
)
from .ip_lookup import (
    render_ip_lookup_summary,
)
from .ips import (
    render_ips_summary,
)
from .kerberos import (
    render_kerberos_summary,
)
from .ldap import (
    render_ldap_summary,
)
from .lldp_dcp import (
    render_lldp_dcp_summary,
)
from .mac_lookup import (
    render_mac_lookup_summary,
)
from .malware import (
    render_malware_summary,
)
from .melsec import (
    render_melsec_summary,
)
from .mitre import (
    _MITRE_KILLCHAIN_ORDER,
    _MITRE_TACTIC_ACTION,
    _mitre_kill_chain_rows,
    _mitre_tactic_action,
    render_mitre_summary,
)
from .mms import (
    render_mms_summary,
)
from .modbus import (
    _identity_text,
    _render_modbus_baseline_sections,
    _render_modbus_verdict,
    render_modbus_rollup,
    render_modbus_summary,
)
from .modicon import (
    render_modicon_summary,
)
from .mqtt import (
    render_mqtt_summary,
)
from .netbios import (
    render_netbios_summary,
)
from .nfs import (
    render_nfs_summary,
)
from .niagara import (
    render_niagara_summary,
)
from .ntlm import (
    render_ntlm_summary,
)
from .ntp import (
    render_ntp_summary,
)
from .obfuscation import (
    render_obfuscation_summary,
)
from .opc import (
    render_opc_summary,
)
from .opc_classic import (
    render_opc_classic_summary,
)
from .ot_commands import (
    render_ot_commands_summary,
)
from .overview import (
    _OVERVIEW_IOT_SIGNAL_TOKENS,
    _OVERVIEW_OT_SIGNAL_TOKENS,
    _overview_activity_text,
    _overview_detected_devices,
    _overview_hunt_lead_section,
    _overview_lead_lookfor,
    _overview_list_preview,
    _overview_metrics_text,
    _overview_next_command,
    _overview_priority_style,
    _overview_rate_text,
    _overview_ts,
    _overview_window_text,
    render_overview_summary,
)
from .pcapmeta import (
    render_pcapmeta_summary,
)
from .pccc import (
    render_pccc_summary,
)
from .pcworx import (
    render_pcworx_summary,
)
from .powershell import (
    render_powershell_summary,
)
from .prconos import (
    render_prconos_summary,
)
from .profinet import (
    render_profinet_summary,
)
from .protocols import (
    _INSECURE_WIRE_PROTOCOLS,
    _protocols_mitre_techniques,
    render_protocols_summary,
)
from .ptp import (
    render_ptp_summary,
)
from .qos import (
    render_qos_summary,
)
from .quic import (
    render_quic_summary,
)
from .rdp import (
    render_rdp_summary,
)
from .routing import (
    render_routing_summary,
)
from .rpc import (
    render_rpc_summary,
)
from .rules import (
    render_rules_summary,
)
from .s7 import (
    render_s7_summary,
)
from .safety import (
    render_safety_summary,
)
from .scan import (
    _SCAN_SEVERITY_RANK,
    _SCAN_STEALTH_MARKERS,
    _scan_mitre_techniques,
    _scan_source_severity,
    render_scan_summary,
)
from .search import (
    _highlight_search_text,
    render_search_rollup,
    render_search_summary,
)
from .secrets import (
    render_secrets_summary,
)
from .services import (
    _service_asset_key,
    _services_mitre_techniques,
    render_services_summary,
)
from .sizes import (
    render_sizes_summary,
)
from .smb import (
    render_smb_summary,
)
from .snmp import (
    render_snmp_summary,
)
from .srtp import (
    render_srtp_summary,
)
from .ssdp import (
    render_ssdp_summary,
)
from .ssh import (
    render_ssh_summary,
)
from .streams import (
    render_streams_summary,
)
from .strings import (
    render_strings_summary,
)
from .summary import (
    _format_linktype,
    _protocol_rows,
    render_summary,
)
from .sv import (
    render_sv_summary,
)
from .synchrophasor import (
    render_synchrophasor_summary,
)
from .syslog import (
    render_syslog_summary,
)
from .tcp import (
    render_tcp_summary,
)
from .teamviewer import (
    render_teamviewer_summary,
)
from .telnet import (
    render_telnet_summary,
)
from .threats import (
    render_threats_summary,
)
from .timeline import (
    render_timeline_summary,
)
from .tls import (
    _render_tls_summary_impl,
    render_tls_summary,
)
from .udp import (
    _approx_hist_stats,
    _udp_bucket_ranges,
    render_udp_rollup,
    render_udp_summary,
)
from .vlan import (
    render_vlan_rollup,
    render_vlan_summary,
)
from .vnc import (
    render_vnc_summary,
)
from .vpn import (
    render_vpn_summary,
)
from .webrequests import (
    render_webrequests_summary,
)
from .winrm import (
    render_winrm_summary,
)
from .wlan import (
    render_wlan_summary,
)
from .wmic import (
    render_wmic_summary,
)
from .yokogawa import (
    render_yokogawa_summary,
)

# Names the single-module reporting.py re-exported incidentally, by importing
# them at module level. Nothing in pcapper relies on that, but the module is
# public API and `from pcapper.reporting import DnsSummary` used to work, so
# the surface is preserved rather than quietly narrowed by the split.
from ..aim import AimSummary
from ..arp import ArpSummary
from ..beacon import BeaconSummary
from ..certificates import CertificateSummary
from ..coloring import danger, danger_bg, header, highlight, label, muted, ok, orange, severity_color, severity_label, suspicious_bg, warn
from ..compromised import CompromiseSummary
from ..creds import CredentialSummary
from ..ctf import CtfSummary
from ..decode import DecodeSummary
from ..dhcp import DhcpSummary
from ..dns import DnsSummary, PUBLIC_DNS_RESOLVERS
from ..email import EmailSummary
from ..encrypted_dns import EncryptedDnsSummary
from ..exfil import ExfilSummary
from ..files import FileTransferSummary
from ..ftp import FtpSummary
from ..goose import GooseSummary
from ..health import HealthSummary
from ..hostdetails import HostDetailsSummary
from ..hostname import HostnameSummary
from ..hosts import HostSummary
from ..http import HttpSummary
from ..http2 import Http2Summary
from ..icmp import IcmpSummary
from ..iec101_103 import Iec101103Summary
from ..ioc import IocSummary
from ..ipmac import IpLookupSummary, MacLookupSummary, mac_manufacturer
from ..ips import IpSummary
from ..lldp_dcp import LldpDcpSummary
from ..malware import MalwareSummary
from ..mitre import MitreSummary
from ..models import PcapSummary
from ..nfs import NfsSummary
from ..ntp import NtpSummary
from ..opc_classic import OpcClassicSummary
from ..ot_commands import OtCommandSummary
from ..overview import OverviewSummary
from ..pcapmeta import PcapMetaSummary
from ..powershell import PowershellSummary
from ..protocols import ProtocolSummary
from ..ptp import PtpSummary
from ..qos import QosSummary
from ..quic import QuicSummary
from ..rdp import RdpSummary
from ..reporting_format import format_table
from ..routing import RoutingSummary
from ..rpc import RpcSummary
from ..scan import ScanSummary
from ..search import SearchSummary
from ..secrets import SecretsSummary
from ..services import COMMON_PORTS, ServiceSummary
from ..sizes import SizeSummary, render_size_sparkline
from ..smb import SmbSummary
from ..snmp import SnmpSummary
from ..ssdp import SsdpSummary
from ..ssh import SshSummary
from ..streams import StreamSummary
from ..strings import StringsSummary
from ..sv import SvSummary
from ..synchrophasor import SynchrophasorSummary
from ..syslog import SyslogSummary
from ..tcp import TcpSummary
from ..teamviewer import TeamviewerSummary
from ..telnet import TelnetSummary
from ..threats import ThreatSummary
from ..timeline import TimelineSummary
from ..tls import TlsSummary
from ..udp import UdpConversation, UdpSummary
from ..utils import decode_payload, format_bytes_as_mb, format_duration, format_speed_bps, format_ts, hexdump, sparkline
from ..vlan import VlanStat, VlanSummary
from ..vnc import VncSummary
from ..vpn import VpnSummary
from ..webrequests import WebRequestSummary
from ..winrm import WinrmSummary
from ..wlan import WlanSummary
from ..wmic import WmicSummary
