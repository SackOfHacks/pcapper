from __future__ import annotations

from scapy.all import Dot11, Dot11AssoReq, Dot11Beacon, Dot11Elt, RadioTap, wrpcap

from pcapper.wlan import _is_unicast_mac, analyze_wlan


def test_unicast_mac_validation_uses_group_address_bit() -> None:
    assert _is_unicast_mac("02:11:22:33:44:55")
    assert not _is_unicast_mac("03:11:22:33:44:55")
    assert not _is_unicast_mac("01:00:5e:00:00:01")
    assert not _is_unicast_mac("not-a-mac")


def test_association_request_subtype_zero_is_counted(tmp_path) -> None:
    capture = tmp_path / "association_request.pcap"
    packet = (
        RadioTap()
        / Dot11(
            type=0,
            subtype=0,
            addr1="02:00:00:00:00:02",
            addr2="02:00:00:00:00:01",
            addr3="02:00:00:00:00:02",
        )
        / Dot11AssoReq()
    )
    wrpcap(str(capture), [packet])

    result = analyze_wlan(capture, show_status=False)

    assert result.mgmt_subtype_counts["AssocReq"] == 1
    assert result.clients[0].assoc_requests == 1


def test_signal_average_and_peak_use_constant_space_accumulators(tmp_path) -> None:
    capture = tmp_path / "signal_strength.pcap"
    bssid = "02:00:00:00:00:02"
    packets = []
    for signal in (-40, -60):
        packets.append(
            RadioTap(present="dBm_AntSignal", dBm_AntSignal=signal)
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
            / Dot11Beacon(cap="ESS")
            / Dot11Elt(ID="SSID", info=b"test")
        )
    wrpcap(str(capture), packets)

    result = analyze_wlan(capture, show_status=False)

    assert result.networks[0].avg_signal_dbm == -50
    assert result.networks[0].peak_signal_dbm == -40
