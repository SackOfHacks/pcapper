"""Rendered output for 802.11 (WLAN) analysis.

Default view: what an attacker could take or already took (WPA handshakes,
WEP, discovered secrets, open-network artifacts), the networks and the
clients. -v adds AP/client links, per-SSID and per-BSSID detail, transfer
channels and the frame mix.
"""

from __future__ import annotations

from ..wlan import WlanSummary
from . import _style as st
from ._kv import counter_line, findings_for


def _signal(avg: object, peak: object) -> str:
    return f"{avg}/{peak} dBm" if avg not in (None, "-") else "-"


def _records(items: list, columns: list[tuple[str, str]], align: str = "", max_rows: int | None = 10) -> list[str]:
    return st.table([c for c, _ in columns],
                    [[(st.ts(i.get(k)) if k in ("first_seen", "last_seen") else i.get(k, "-")) for _, k in columns]
                     for i in items if isinstance(i, dict)], align=align, max_rows=max_rows)


def render_wlan_summary(summary: WlanSummary) -> str:
    rep = st.Report("WLAN", summary.path)
    findings = findings_for(summary, ot=False)
    if not summary.wlan_packets and not st.material(findings):
        return rep.absent("802.11 frames", summary.errors)
    severity, text = st.verdict(findings, high="high-severity wireless activity (attacks, exposed secrets): investigate",
                                medium="wireless activity to review")
    rep.headline(severity, text, st.join([
        f"{st.count(summary.wlan_packets)} 802.11 frames",
        st.plural(summary.unique_networks, "network"), st.plural(summary.unique_clients, "client"),
        f"{st.count(summary.eapol_packets)} EAPOL" if summary.eapol_packets else "",
        st.duration(summary.duration_seconds) if summary.duration_seconds else "",
        st.ts_range(summary.first_seen, summary.last_seen) if summary.first_seen else "",
    ]))
    rep.scope(st.top(summary.security_counts, 6))
    if summary.errors:
        rep.section("Errors", [f"  {st.bad('!')} {e}" for e in summary.errors])
    rep.section("Findings", st.findings_block(findings))

    rep.section("WPA handshakes", [f"  {st.dim('Crackable offline (hashcat -m 22000) when the 4-way exchange is complete.')}"] + st.table(
        ["BSSID", "Station", "EAPOL frames"],
        [[h.get("bssid", "-"), h.get("station", "-"), h.get("eapol_frames", "-")] for h in (summary.wpa_handshakes or [])],
        align="llr", max_rows=None,
    ) if summary.wpa_handshakes else [])
    rep.section("WEP", st.bullets([str(w) for w in (summary.wep_signals or [])], max_items=None))
    rep.section("Discovered secrets", st.bullets([st.bad(str(s)) for s in (summary.discovered_secrets or [])], max_items=None))
    rep.section("Open-network artifacts", st.bullets([str(a) for a in (summary.open_artifacts or [])] +
                                                     [str(a) for a in (summary.recovered_ip_artifacts or [])], max_items=10))

    rep.section("Networks", st.table(
        ["SSID", "BSSID", "Security", "PHY", "Channel", "Clients", "EAPOL", "Signal avg/peak"],
        [[n.ssid or "<hidden>", n.bssid, n.security, n.phy_protocol or "-", n.channel if n.channel is not None else "-",
          st.count(n.associated_clients), st.count(n.eapol_frames), _signal(n.avg_signal_dbm, n.peak_signal_dbm)]
         for n in (summary.networks or [])],
        align="llllrrrr", noun="network",
    ))
    rep.section("Clients", st.table(
        ["Client", "Probes", "Auth", "Assoc", "Deauth", "BSSIDs", "Protection", "IPs", "Signal avg/peak"],
        [[c.mac, c.probe_requests, c.auth_requests, c.assoc_requests,
          st.bad(str(c.deauth_frames)) if c.deauth_frames else "0", c.unique_bssids, c.protection,
          ", ".join(c.ips) or "-", _signal(c.avg_signal_dbm, c.peak_signal_dbm)] for c in (summary.clients or [])],
        align="lrrrrrlll", noun="client",
    ))

    # ---- reference material (-v) ----------------------------------------
    rep.section("Frames", st.kv([
        ("Total packets", str(summary.total_packets)),
        ("Mgmt / data / control", f"{summary.mgmt_packets} / {summary.data_packets} / {summary.control_packets}"),
        ("Protected / open data", f"{summary.protected_data_packets} / {summary.open_data_packets} ({st.size(summary.open_data_bytes)} open)"),
        ("Null / QoS-null", f"{summary.null_data_packets} / {summary.qos_null_packets}"),
        ("EAPOL / WEP", f"{summary.eapol_packets} / {summary.wep_packets}"),
        counter_line("Security", summary.security_counts, None), counter_line("PHY", summary.phy_counts, None),
        counter_line("SSIDs", summary.ssid_counts, None), counter_line("Channels", summary.channel_counts, None),
        counter_line("Management subtypes", summary.mgmt_subtype_counts, None),
    ]), detail=True)
    rep.section("AP/client links", _records(summary.ap_client_links or [], [
        ("AP", "ap_bssid"), ("SSID", "ssid"), ("Client", "client_mac"), ("IPs", "client_ips"), ("PHY", "wireless_protocol"),
        ("Protection", "protection"), ("Auth", "auth_req"), ("Assoc", "assoc_req"), ("EAPOL", "eapol_frames"),
        ("Avg dBm", "avg_signal_dbm"), ("Peak dBm", "peak_signal_dbm")], max_rows=None), detail=True)
    rep.section("SSIDs", _records(summary.ssid_details or [], [
        ("SSID", "ssid"), ("BSSIDs", "bssid_count"), ("Security", "security_modes"), ("Channels", "channels"),
        ("PHY", "phy_protocols"), ("Beacons", "beacons"), ("Clients", "clients")], max_rows=None), detail=True)
    rep.section("BSSIDs", _records(summary.bssid_details or [], [
        ("BSSID", "bssid"), ("SSID", "ssid"), ("Channel", "channel"), ("Security", "security"), ("PHY", "wireless_protocol"),
        ("Clients", "clients"), ("Beacons", "beacons"), ("EAPOL", "eapol"), ("Avg dBm", "avg_signal_dbm"),
        ("Peak dBm", "peak_signal_dbm"), ("First", "first_seen"), ("Last", "last_seen")], max_rows=None), detail=True)
    rep.section("Transfer channels", _records(summary.transfer_channels or [], [
        ("Source", "src"), ("Destination", "dst"), ("Security", "security"), ("Packets", "packets"), ("Bytes", "bytes"),
        ("Subtypes", "subtypes"), ("First pkt", "first_packet"), ("Last pkt", "last_packet")], max_rows=None), detail=True)
    rep.section("Recovered IP artifacts", st.bullets([str(a) for a in (summary.recovered_ip_artifacts or [])], max_items=None),
                detail=True)
    return rep.render()
