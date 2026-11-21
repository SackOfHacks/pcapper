"""Host data in --correlate / baselines: real hosts only."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from pcapper.correlation import correlate
from pcapper.hosts import _normalize_mac


def _hosts(path: str, *ips: str) -> SimpleNamespace:
    return SimpleNamespace(path=Path(path), hosts=[SimpleNamespace(ip=ip) for ip in ips], errors=[])


def test_correlation_counts_unicast_hosts_across_captures() -> None:
    summary = correlate(
        [_hosts("a.pcap", "10.0.0.5", "224.0.0.252", "10.0.0.255", "8.8.8.8"),
         _hosts("b.pcap", "10.0.0.5", "224.0.0.252", "10.0.0.255", "8.8.8.8")],
        [],
    )
    assert summary.host_counts["10.0.0.5"] == 2 and summary.host_counts["8.8.8.8"] == 2
    assert "224.0.0.252" not in summary.host_counts and "10.0.0.255" not in summary.host_counts
    assert any("Public endpoints" in str(d.get("summary")) for d in summary.detections)


def test_group_macs_are_not_host_macs() -> None:
    assert _normalize_mac("FF:FF:FF:FF:FF:FF") is None  # an ARP request's destination
    assert _normalize_mac("01:00:5e:00:00:fb") is None  # IPv4 multicast
    assert _normalize_mac("33:33:00:00:00:16") is None  # IPv6 multicast
    assert _normalize_mac("00:0C:29:B8:CD:E1") == "00:0c:29:b8:cd:e1"


def test_baseline_port_changes_read_as_ports() -> None:
    from pcapper.reporting.baseline_delta import _host_change

    text = re.sub(r"\x1b\[[0-9;]*m", "", _host_change({"ip": "10.0.0.5", "new_ports": [(139, "TCP", "NetBIOS", "")]}))
    assert text == "+port 139/tcp NetBIOS"


def test_gateway_mac_is_not_an_internet_hosts_mac() -> None:
    """Frames to off-link addresses carry the gateway's MAC: it is not
    8.8.8.8's, and two gateways made every public IP a "MAC collision"."""
    from pcapper.hosts import _build_macs

    gw, host, dmz = "00:0c:29:e5:48:cc", "00:0c:29:b8:cd:e1", "00:50:56:01:02:03"
    ips = SimpleNamespace(ip_mac_counts={
        "8.8.8.8": {gw: 10}, "72.21.91.29": {gw: 4}, "192.168.1.1": {gw: 6},
        "192.168.1.10": {host: 20}, "93.184.216.34": {dmz: 3, gw: 1},
    })
    arp = SimpleNamespace(conversations=[SimpleNamespace(src_ip="93.184.216.34", src_mac=dmz, dst_ip="", dst_mac="")])
    macs = _build_macs(ips, arp, None)
    assert not macs.get("8.8.8.8") and not macs.get("72.21.91.29")
    assert list(macs["192.168.1.1"]) == [gw]  # the router's own LAN address keeps it
    assert list(macs["192.168.1.10"]) == [host]
    assert list(macs["93.184.216.34"]) == [dmz]  # an on-link public host, bound by ARP

    from pcapper.hostdetails import _extract_mac_values

    assert _extract_mac_values("8.8.8.8", arp, None, ips) == []  # --hostdetails -ip 8.8.8.8
    assert _extract_mac_values("192.168.1.1", arp, None, ips) == [gw]
    assert _extract_mac_values("93.184.216.34", arp, None, ips) == [dmz]


def test_baseline_banner_change_is_a_port_change() -> None:
    """Same port, new banner: one changed port, not one opened and one closed."""
    from pcapper.baseline import BaselineSnapshot, compare_baseline
    from pcapper.reporting.baseline_delta import _host_change

    def snap(software: str) -> BaselineSnapshot:
        return BaselineSnapshot("t", "3.0.0", [], hosts=[{"ip": "72.21.91.29", "open_ports": [
            {"port": 80, "protocol": "TCP", "service": "HTTP", "software": software}]}])

    change = compare_baseline(snap("ECS (dca/249B)"), snap("ECS (ord/4CD5)")).host_changes[0]
    assert "new_ports" not in change and "missing_ports" not in change
    text = re.sub(r"\x1b\[[0-9;]*m", "", _host_change(change))
    assert text == "80/tcp HTTP ECS (ord/4CD5) -> HTTP ECS (dca/249B)"
