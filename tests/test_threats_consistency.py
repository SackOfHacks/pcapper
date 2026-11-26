"""Cross-report consistency: --threats, --mitre, --ot-commands, --compromised
and --tcp reach the same answer about the same traffic.

Each defect here was one report contradicting another on one capture: an
analyzer's own ATT&CK tag dropped on the way to --mitre (an ADS AddRoute
mapped to Brute Force for the word "password"), a cleartext Administrator
logon CRITICAL in --creds and noise in --threats, ADS polling HIGH beaconing
where identical Modbus polling was baseline, ADS symbol lookups and their
replies counted as process writes. Captures are built byte for byte here.
"""

from __future__ import annotations

from collections import Counter
from types import SimpleNamespace

from scapy.all import Dot1Q, Ether, IP, TCP, UDP, Raw, wrpcap  # type: ignore

from pcapper import sharedpass, utils
from pcapper.compromised import analyze_compromised
from pcapper.creds import CredentialHit
from pcapper.industrial_helpers import IndustrialAnomaly, IndustrialCommandEvent
from pcapper.mitre import _analyzer_technique_ids, _rule_from_text, analyze_mitre
from pcapper.ot_commands import (
    ICCP_DEVICE_CONTROL,
    analyze_ot_commands,
    command_is_control,
    control_command_counts,
    worst_command_severity,
)
from pcapper.ot_ports import OT_PORT_PROTOCOLS
from pcapper.reporting.threats import _detection_strength, _is_noisy_low_signal
from pcapper.tcp import analyze_tcp
from pcapper.threats import (
    OT_PORTS,
    _append_anomaly_items,
    _append_ot_anomalies,
    _classify_internal_periodicity,
    _credential_exposure_detection,
    _curate_threat_detections,
    analyze_threats,
)

EWS, PLC = "192.168.21.220", "192.168.21.250"
T0 = 1_700_000_000.0


def _write(path, pkts, step: float | None = 0.5):
    """Write ``pkts`` (stamped ``step`` seconds apart unless None: their own
    times) and start from an empty analysis memo."""
    if step is not None:
        for index, pkt in enumerate(pkts):
            pkt.time = T0 + index * step
    wrpcap(str(path), pkts)
    utils.clear_analysis_memo()
    return path


# --- Beckhoff ADS/AMS ------------------------------------------------------------


def _ads_tag(tag: int, value: bytes) -> bytes:
    return tag.to_bytes(2, "little") + len(value).to_bytes(2, "little") + value


def _ads_udp(service: int, tags: list[bytes], response: bool = False) -> bytes:
    service |= 0x80000000 if response else 0
    return (b"\x03\x66\x14\x71" + b"\x00" * 4 + service.to_bytes(4, "little")
            + bytes([192, 168, 1, 99, 1, 1]) + (10000).to_bytes(2, "little")
            + len(tags).to_bytes(4, "little") + b"".join(tags))


def _ams(command: int, data: bytes, response: bool = False) -> bytes:
    target = bytes([5, 1, 2, 3, 1, 1]) + (851).to_bytes(2, "little")
    source = bytes([192, 168, 1, 99, 1, 1]) + (32905).to_bytes(2, "little")
    if response:
        target, source = source, target
    header = (target + source + command.to_bytes(2, "little") + (5 if response else 4).to_bytes(2, "little")
              + len(data).to_bytes(4, "little") + (0).to_bytes(4, "little") + (7).to_bytes(4, "little"))
    return b"\x00\x00" + (len(header) + len(data)).to_bytes(4, "little") + header + data


SYMBOL_HANDLE = (9, (0xF003).to_bytes(4, "little") + (0).to_bytes(4, "little") + (4).to_bytes(4, "little")
                 + (12).to_bytes(4, "little") + b"MAIN.bValve\x00")
DELETE_NOTIFICATION = (7, (0x2A).to_bytes(4, "little"))
MEMORY_WRITE = (3, (0x4020).to_bytes(4, "little") + (0).to_bytes(4, "little") + (4).to_bytes(4, "little")
                + b"\x01\x00\x00\x00")
PLC_STOP = (5, (6).to_bytes(2, "little") + (0).to_bytes(2, "little") + (0).to_bytes(4, "little"))


def _ads_capture(tmp_path, requests, *, addroute: bool = True, name: str = "ads.pcap"):
    """An engineering station registering an ADS route (its target's Windows
    credentials in clear) and sending AMS requests, each answered."""
    pkts = []
    if addroute:
        route = _ads_udp(6, [_ads_tag(12, b"EWS-PC\x00"), _ads_tag(7, bytes([192, 168, 1, 99, 1, 1])),
                             _ads_tag(13, b"Administrator\x00"), _ads_tag(2, b"Secr3t!\x00")])
        pkts.append(Ether() / IP(src=EWS, dst=PLC) / UDP(sport=50001, dport=48899) / Raw(route))
        pkts.append(Ether() / IP(src=PLC, dst=EWS) / UDP(sport=48899, dport=50001)
                    / Raw(_ads_udp(6, [_ads_tag(5, b"CX-PLC\x00")], response=True)))
    cseq, sseq = 1000, 5000
    for command, data in requests:
        request = _ams(command, data)
        pkts.append(Ether() / IP(src=EWS, dst=PLC) / TCP(sport=50123, dport=48898, flags="PA", seq=cseq, ack=sseq)
                    / Raw(request))
        cseq += len(request)
        reply = _ams(command, b"\x00\x00\x00\x00", response=True)
        pkts.append(Ether() / IP(src=PLC, dst=EWS) / TCP(sport=48898, dport=50123, flags="PA", seq=sseq, ack=cseq)
                    / Raw(reply))
        sseq += len(reply)
    return _write(tmp_path / name, pkts)


# --- A1/A2/A3: --mitre ------------------------------------------------------------


def test_ot_anomaly_attack_tags_reach_the_detection() -> None:
    """The grouping of OT anomalies rebuilt each detection from title and
    description alone; the analyzer's ATT&CK tag was dropped."""
    grouped: list[dict[str, object]] = []
    tag = "T0859 Valid Accounts; T0886 Remote Services"
    _append_ot_anomalies(grouped, "ADS/AMS", [
        IndustrialAnomaly("HIGH", "ADS AddRoute with cleartext Windows credentials", "one", EWS, PLC, 0.0, attack=tag),
        IndustrialAnomaly("HIGH", "ADS AddRoute with cleartext Windows credentials", "two", EWS, "10.0.0.9", 0.0, attack=tag),
    ])
    assert len(grouped) == 1 and grouped[0]["attack"] == tag
    items: list[dict[str, object]] = []
    _append_anomaly_items(items, "X", [
        {"title": "dict finding", "severity": "high", "mitre": "T1110 Brute Force"},
        SimpleNamespace(title="object finding", severity="high", attack="T0855 Unauthorized Command Message"),
    ])
    assert [item.get("attack") for item in items] == ["T1110 Brute Force", "T0855 Unauthorized Command Message"]


def test_mitre_takes_only_technique_ids_it_knows() -> None:
    assert _analyzer_technique_ids({"attack": "T0859 Valid Accounts; T9999 Bogus; T0886"}, "") == ["T0859", "T0886"]
    assert _analyzer_technique_ids({"mitre": "T1021.004 Remote Services: SSH"}, "") == ["T1021.004"]
    # A sub-technique of a known technique is known.
    assert _analyzer_technique_ids({"attack": "T1110.003"}, "") == ["T1110.003"]
    # Ids the analyzer wrote in its own text count when it set no tag ...
    assert _analyzer_technique_ids({}, "ot protocol on a non-standard port (att&ck t1571 non-standard port).") == ["T1571"]
    # ... and a T-number that names no technique is not one.
    assert _analyzer_technique_ids({"attack": "T9999"}, "beacon to t1234.example.com") == []


def test_addroute_maps_to_the_techniques_its_analyzer_tagged(tmp_path) -> None:
    """--mitre mapped an AddRoute carrying Windows credentials to T1110 Brute
    Force (the word "password"), and the ADS replies counted as writes made
    a Program Download out of "engineering command"."""
    capture = _ads_capture(tmp_path, [SYMBOL_HANDLE, DELETE_NOTIFICATION])
    threat_summary = analyze_threats(capture, show_status=False)
    route = next(d for d in threat_summary.detections if d["summary"] == "ADS AddRoute with cleartext Windows credentials")
    assert route["attack"] == "T0859 Valid Accounts; T0886 Remote Services"
    mitre = analyze_mitre(capture, show_status=False, threat_summary=threat_summary)
    mapped = {hit.technique_id: hit for hit in mitre.hits}
    assert {"T0859", "T0886"} <= set(mapped), mitre.hits
    assert not {"T1110", "T0843", "T0855"} & set(mapped), mitre.hits
    assert (mapped["T0859"].tactic, mapped["T0886"].tactic) == ("Persistence", "Lateral Movement")
    assert "analyzer tag" in mapped["T0859"].rationale


def test_engineering_command_wording_is_not_a_program_download() -> None:
    rule, _score = _rule_from_text("ot control/engineering command activity 18 control-like command(s) observed in ads/ams.")
    assert rule is None or rule.technique_id != "T0843"
    rule, _score = _rule_from_text("s7 program download to the plc (block transfer)")
    assert rule is not None and rule.technique_id == "T0843"
    rule, _score = _rule_from_text("firmware update pushed to the plc")
    assert rule is not None and rule.technique_id == "T0857"


def _ftp_root_capture(tmp_path):
    client, server = "10.10.5.20", "10.10.5.5"
    pkts, cseq, sseq = [], 1000, 9000
    for from_client, data in ((False, b"220 ProFTPD Server ready\r\n"), (True, b"USER root\r\n"),
                              (False, b"331 Password required for root\r\n"), (True, b"PASS Toor2024!\r\n"),
                              (False, b"230 User root logged in\r\n"), (True, b"QUIT\r\n")):
        if from_client:
            pkts.append(Ether() / IP(src=client, dst=server) / TCP(sport=51515, dport=21, flags="PA", seq=cseq, ack=sseq)
                        / Raw(data))
            cseq += len(data)
        else:
            pkts.append(Ether() / IP(src=server, dst=client) / TCP(sport=21, dport=51515, flags="PA", seq=sseq, ack=cseq)
                        / Raw(data))
            sseq += len(data)
    return _write(tmp_path / "ftp_root.pcap", pkts, step=0.3)


def test_ftp_root_login_is_valid_accounts_and_a_critical_exposure(tmp_path) -> None:
    """An FTP login as root mapped to no technique, and the credential
    detection was a warning (fewer than 20 hits) while --creds called the
    privileged exposure critical."""
    capture = _ftp_root_capture(tmp_path)
    threat_summary = analyze_threats(capture, show_status=False)
    creds = next(d for d in threat_summary.detections if d["source"] == "Creds")
    assert creds["severity"] == "critical"
    assert "privileged account(s) exposed: root" in str(creds["details"])
    mitre = analyze_mitre(capture, show_status=False, threat_summary=threat_summary)
    assert any(hit.technique_id == "T1078" and hit.source == "FTP" for hit in mitre.hits), mitre.hits


# --- B1: analyzers --threats never ran ---------------------------------------------


def test_vlan_hopping_reaches_threats_without_dissecting_the_capture(tmp_path) -> None:
    """The VLAN analysis never ran under --threats (nor --overview): a HIGH
    double-tagging finding gave zero threat detections. It now runs over the
    tagged frames the threat pass collects, and the pass still reads only
    lightweight records."""
    pkts = [
        Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=1) / Dot1Q(vlan=20)
        / IP(src="10.1.1.66", dst="10.20.0.5") / UDP(sport=40000 + i, dport=161) / Raw(b"\x30\x00")
        for i in range(8)
    ]
    capture = _write(tmp_path / "vlan.pcap", pkts, step=0.2)
    vlan = [d for d in analyze_threats(capture, show_status=False).detections if d["source"] == "VLAN"]
    assert vlan and vlan[0]["severity"] == "high" and "Double-tagged" in str(vlan[0]["summary"])
    reads = sharedpass.discover(capture, [(analyze_threats, (), {})]).reads
    assert reads and "packets" not in reads


def test_protocol_analyses_find_the_same_from_disk_and_memory(tmp_path, monkeypatch) -> None:
    """Read from disk, the VLAN/SSDP/NTP/TeamViewer analyses run over the
    packets the threat pass kept (each a superset of what the analyzer
    accepts); held in memory, over the whole capture. Same report."""
    from pcapper import pcap_cache

    monkeypatch.setenv("PCAPPER_CACHE_ENABLED", "0")
    scanner = "10.0.0.7"
    pkts = [
        Ether() / IP(src=scanner, dst="239.255.255.250") / UDP(sport=50000 + i, dport=1900)
        / Raw(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: ssdp:all\r\n\r\n")
        for i in range(45)
    ]
    pkts += [Ether() / IP(src=scanner, dst="10.0.0.9") / UDP(sport=40123, dport=123) / Raw(bytes([0x17, 0, 3, 0x2A]) + b"\x00" * 4)
             for _ in range(3)]
    pkts += [Ether() / IP(src=scanner, dst="10.0.0.20") / TCP(sport=50555, dport=5938, flags="PA", seq=1) / Raw(b"\x17\x24\x10\x04")]
    pkts += [Ether() / Dot1Q(vlan=1) / Dot1Q(vlan=30) / IP(src=scanner, dst="10.30.0.5") / UDP(sport=40000, dport=161) / Raw(b"\x30\x00")]
    capture = _write(tmp_path / "protocols.pcap", pkts, step=0.1)
    pcap_cache._PACKET_CACHE.clear()
    from_disk = analyze_threats(capture, show_status=False)
    packets, meta = pcap_cache.load_packets(capture, show_status=False)
    utils.clear_analysis_memo()
    in_memory = analyze_threats(capture, show_status=False, packets=packets, meta=meta)
    assert repr(from_disk) == repr(in_memory)
    summaries = {(d["source"], d["summary"]) for d in from_disk.detections}
    assert ("SSDP", "SSDP M-SEARCH flood pattern") in summaries, summaries
    assert ("VLAN", "Double-tagged (802.1Q-in-Q) frames observed: 1") in summaries, summaries


# --- B2: credential grading ---------------------------------------------------------


def _hit(user: str | None, secret: str | None, *, dst: str = "10.0.0.5", kind: str = "FTP PASS", pkt: int = 1):
    return CredentialHit(packet_number=pkt, ts=None, src_ip="10.0.0.9", dst_ip=dst, src_port=50000, dst_port=21,
                         protocol="FTP", kind=kind, username=user, secret=secret, evidence=f"{kind} line")


def _creds(hits, **signals):
    base = {"external_exposures": [], "privileged_exposures": [], "auth_abuse_sequences": [],
            "replay_candidates": [], "token_fanout": []}
    base.update(signals)
    return SimpleNamespace(matches=len(hits), hits=hits, kind_counts=Counter(h.kind for h in hits), **base)


def test_credential_detection_is_graded_by_risk_not_count() -> None:
    cleartext = [_hit("bob", f"pw{i}", pkt=i) for i in range(25)]
    assert _credential_exposure_detection(_creds(cleartext))["severity"] == "warning"
    privileged = _credential_exposure_detection(_creds(
        [_hit("Administrator", "Secr3t!")],
        privileged_exposures=[{"src": "10.0.0.9", "dst": "10.0.0.5", "user": "Administrator", "kind": "FTP PASS", "pkt": 1}],
    ))
    assert privileged["severity"] == "critical"
    assert privileged["evidence"][0] == "privileged account(s) exposed: Administrator"
    external = _credential_exposure_detection(_creds(
        [_hit("bob", "pw", dst="203.0.113.7")],
        external_exposures=[{"src": "10.0.0.9", "dst": "203.0.113.7", "user": "bob", "kind": "FTP PASS", "pkt": 1}],
    ))
    assert external["severity"] == "critical"
    attack = _credential_exposure_detection(_creds(
        [_hit("bob", f"guess{i}", pkt=i) for i in range(8)],
        auth_abuse_sequences=[{"src": "10.0.0.9", "patterns": ["password brute-force"], "events": 8}],
    ))
    assert attack["severity"] == "high"
    hashes = _credential_exposure_detection(_creds([_hit("bob", "aa:bb", kind="NetNTLMv2 Hash")]))
    assert hashes["severity"] == "warning" and "1 offline-crackable hash(es)" in hashes["evidence"]


def test_a_critical_credential_exposure_is_never_noise() -> None:
    detection = _credential_exposure_detection(_creds(
        [_hit("root", None, kind="FTP USER")],
        privileged_exposures=[{"src": "10.0.0.9", "dst": "10.0.0.5", "user": "root", "kind": "FTP USER", "pkt": 1}],
    ))
    kept = _curate_threat_detections([detection])
    assert [d["severity"] for d in kept] == ["critical"]
    assert not _is_noisy_low_signal(kept[0], _detection_strength(kept[0]))


# --- B3/B4: OT polling ----------------------------------------------------------------


def test_ot_ports_follow_the_shared_registry() -> None:
    assert set(OT_PORT_PROTOCOLS) <= set(OT_PORTS)
    for port in (1153, 1628, 1629, 2004, 2005, 3671, 3819, 4000, 4059, 48898, 48899):
        assert port in OT_PORTS, port
    # Ports the registry lacks stay, and the labels the strict public-flow
    # check keys on are kept.
    assert (OT_PORTS[1883], OT_PORTS[8883]) == ("MQTT", "MQTT-TLS")
    assert (OT_PORTS[44818], OT_PORTS[2222], OT_PORTS[102]) == ("EtherNet/IP", "CIP/ENIP-IO", "S7/MMS/ICCP")


def _modbus(response: bool, tid: int) -> bytes:
    pdu = bytes([3, 4, 0, 1, 0, 2]) if response else bytes([3, 0, 0, 0, 2])
    return tid.to_bytes(2, "big") + b"\x00\x00" + (len(pdu) + 1).to_bytes(2, "big") + b"\x01" + pdu


def _polling_capture(tmp_path):
    """Two HMIs polling a PLC every 5 s: one over ADS (ReadState), one over
    Modbus (Read Holding Registers). Identical cadence, identical role."""
    pkts = []

    def session(client, server, sport, dport, maker, offset):
        cseq, sseq = 1000, 7000
        for i in range(40):
            request, reply = maker(False, i + 1), maker(True, i + 1)
            req = Ether() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(request)
            req.time = T0 + offset + i * 5.0
            rsp = Ether() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq + len(request)) / Raw(reply)
            rsp.time = req.time + 0.004
            cseq += len(request)
            sseq += len(reply)
            pkts.extend([req, rsp])

    session("10.20.0.10", "10.20.0.50", 50200, 48898,
            lambda reply, _i: _ams(4, b"\x00\x00\x00\x00\x05\x00\x00\x00" if reply else b"", response=reply), 1.0)
    session("10.20.0.11", "10.20.0.51", 50300, 502, _modbus, 1.5)
    pkts.sort(key=lambda p: float(p.time))
    return _write(tmp_path / "polling.pcap", pkts, step=None)


def test_ads_polling_is_baseline_like_modbus_polling(tmp_path) -> None:
    """ADS polling every 5 s was HIGH beaconing in --compromised and --tcp
    (its port missing from the OT table) while identical Modbus polling was
    baseline; --tcp also called the Modbus polling HIGH "possible beaconing"
    while the beacon verdict on the same flows was OT baseline."""
    capture = _polling_capture(tmp_path)
    tcp = analyze_tcp(capture, show_status=False)
    assert not [d for d in tcp.detections if d["summary"] == "Possible TCP beaconing"], tcp.detections
    polling = [d for d in tcp.detections if d.get("internal_periodicity") == "ot_baseline"]
    assert polling and polling[0]["severity"] == "info"
    assert "48898" in str(polling[0]["details"]) and ":502" in str(polling[0]["details"])
    threat_summary = analyze_threats(capture, show_status=False)
    assert not [d for d in threat_summary.detections if d["severity"] in ("high", "critical")], threat_summary.detections
    assert analyze_mitre(capture, show_status=False, threat_summary=threat_summary).mapped_detections == 0
    compromised = analyze_compromised(capture, show_status=False)
    assert compromised.compromised_hosts == [], compromised.detections


def test_tcp_beaconing_is_judged_like_the_beacon_analysis() -> None:
    internal = {"source": "TCP", "summary": "Possible TCP beaconing", "details": "10.0.0.5:50200 -> 10.0.0.9:48898 (5.00s avg)"}
    assert _classify_internal_periodicity(internal) == "ot_baseline"
    external = dict(internal, details="10.0.0.5:50200 -> 93.184.216.34:443 (5.00s avg)")
    assert _classify_internal_periodicity(external) is None


# --- C1/C2/C3: one classification and one grade for OT commands -------------------


def test_ads_commands_are_classified_as_ads_does() -> None:
    expected = {
        "ReadWrite [symbol handle by name]": False,
        "ReadWrite [sum read]": False,
        "ReadWrite [sum write]": True,
        "ReadWrite [sum read/write]": True,
        "ReadWrite response": False,
        "DeleteDeviceNotification": False,
        "AddDeviceNotification": False,
        "ReadState": False,
        "Write [PLC memory (%M)]": True,
        "WriteControl -> STOP": True,
        "UDP AddRoute": True,
        "UDP AddRoute response": False,
    }
    assert {name: command_is_control("ADS/AMS", name) for name in expected} == expected


def test_ads_lookups_and_replies_are_not_writes_in_either_report(tmp_path) -> None:
    """--ot-commands counted ReadWrite symbol lookups and a notification
    unsubscribe as T0836 writes; --threats counted their replies too. An
    AddRoute -- a route registration carrying credentials -- counted in
    neither, so --overview's OT command volume missed it."""
    capture = _ads_capture(tmp_path, [SYMBOL_HANDLE, DELETE_NOTIFICATION])
    ot = analyze_ot_commands(capture, show_status=False)
    assert ot.command_counts == Counter({"ADS/AMS:UDP AddRoute": 1}), ot.command_counts
    assert ot.sources == Counter({EWS: 1})
    threat_summary = analyze_threats(capture, show_status=False)
    ads_commands = [d for d in threat_summary.detections
                    if d["source"] == "ADS/AMS" and d["summary"] == "OT control/engineering command activity"]
    for detection in ads_commands:  # a single AddRoute may be curated away as weak, never miscounted
        assert detection["evidence"] == ["UDP AddRoute(1)"]


def test_the_same_commands_get_the_same_grade(tmp_path) -> None:
    """--ot-commands graded every state-changing command MEDIUM, --threats by
    keyword and by count (five lookups and their replies made it HIGH)."""
    capture = _ads_capture(tmp_path, [MEMORY_WRITE, PLC_STOP], addroute=False, name="ads_stop.pcap")
    ot = analyze_ot_commands(capture, show_status=False)
    ot_grade = next(d["severity"] for d in ot.detections if d["summary"] == "OT control/write command activity observed")
    threat_grade = next(
        d["severity"] for d in analyze_threats(capture, show_status=False).detections
        if d["source"] == "ADS/AMS" and d["summary"] == "OT control/engineering command activity"
    )
    assert ot_grade == threat_grade == "high"
    # By the kind of command, never by how many.
    assert worst_command_severity(Counter({"Modbus:Write Single Register": 500})) == "warning"
    assert worst_command_severity(["S7:PLC Stop", "Modbus:Write Single Register"]) == "high"


# --- C4/C5: protocols --ot-commands left out ------------------------------------------


def _c37_command(cmd: int) -> bytes:
    body = b"\xaa\x41" + (18).to_bytes(2, "big") + (7).to_bytes(2, "big") + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
    return body + cmd.to_bytes(2, "big") + b"\x00\x00"


def test_synchrophasor_commands_count_as_ot_commands(tmp_path) -> None:
    """--overview showed "data-transmission disabled" (HIGH) beside "OT
    command volume=0": C37.118 command frames were never counted."""
    pdc, pmu = "10.40.0.2", "10.40.0.9"
    pkts = [
        Ether() / IP(src=pdc, dst=pmu) / TCP(sport=40001, dport=4712, flags="PA", seq=1) / Raw(_c37_command(5)),
        Ether() / IP(src=pdc, dst=pmu) / TCP(sport=40001, dport=4712, flags="PA", seq=19) / Raw(_c37_command(1)),
    ]
    ot = analyze_ot_commands(_write(tmp_path / "c37.pcap", pkts), show_status=False)
    assert ot.command_counts == Counter({"C37.118:Turn OFF data transmission": 1}), ot.command_counts
    assert "C37.118:Send CFG-2 frame" in ot.all_command_counts
    assert "C37.118" not in ot.unnormalized_streams
    assert ot.detections[0]["severity"] == "high"


def _ft12(type_id: int, cot: int) -> bytes:
    user = bytes([0x73, 0x01, type_id, 0x01, cot, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01])
    return b"\x68" + bytes([len(user), len(user)]) + b"\x68" + user + bytes([sum(user) & 0xFF]) + b"\x16"


def test_csp_and_iec101_commands_are_counted(tmp_path) -> None:
    """--ot-commands left CSP and IEC 60870-5-101/103 out entirely."""
    master, outstation = "10.50.0.2", "10.50.0.9"
    pccc_write = b"\x01\x07\x00\x00" + b"\x00" * 20 + b"\x0f\x00\x01\x00\x67" + b"\x00" * 8
    pkts = [
        Ether() / IP(src=master, dst=outstation) / TCP(sport=41000, dport=2222, flags="PA", seq=1) / Raw(pccc_write),
        Ether() / IP(src=master, dst=outstation) / TCP(sport=42000, dport=30000, flags="PA", seq=1) / Raw(_ft12(45, 6)),
        # The outstation confirming the activation is not a command.
        Ether() / IP(src=outstation, dst=master) / TCP(sport=30000, dport=42000, flags="PA", seq=1) / Raw(_ft12(45, 7)),
    ]
    ot = analyze_ot_commands(_write(tmp_path / "csp_iec101.pcap", pkts), show_status=False)
    assert ot.command_counts["CSP:PCCC Write (FNC 0x67)"] == 1, ot.command_counts
    assert ot.command_counts["IEC-101/103:C_SC_NA (Single Command)"] == 1, ot.command_counts
    assert ot.control_targets["IEC-101/103"] == Counter({f"{outstation} :: C_SC_NA (Single Command)": 1})


def test_iccp_device_control_is_one_operation() -> None:
    """A TASE.2 Operate is an MMS Write naming a control object in the same
    message; a read naming one is not an operation."""
    a, b = "10.60.0.1", "10.60.0.2"
    events = [
        IndustrialCommandEvent(1.0, a, b, "ICCP/TASE.2"),
        IndustrialCommandEvent(1.0, a, b, "MMS Write"),
        IndustrialCommandEvent(1.0, a, b, "TASE.2 Control Object"),
        IndustrialCommandEvent(2.0, a, b, "ICCP/TASE.2"),
        IndustrialCommandEvent(2.0, a, b, "TASE.2 Control Object"),
    ]
    summary = SimpleNamespace(commands=Counter(e.command for e in events), command_events=events, errors=[])
    assert control_command_counts("ICCP", summary) == Counter({ICCP_DEVICE_CONTROL: 1})
