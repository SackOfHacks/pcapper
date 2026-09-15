"""Regression tests from the third pass of the 2026-09 production-readiness
review: beacon flow keying and the compromise assessment. Each test names the
failure it pins.
"""

from __future__ import annotations

from pathlib import Path

from pcapper import utils
from test_review_batches import T0, _tcp, _write


def _at(pkt, ts: float):
    pkt.time = ts
    return pkt


def _connection(client: str, server: str, sport: int, dport: int, request: bytes, response: bytes, t: float) -> list:
    """One complete TCP connection (handshake, one exchange, FIN) starting at ``t``."""
    cs, ss = 1000, 5000
    pkts = [
        _at(_tcp(client, server, sport, dport, seq=cs, flags="S"), t),
        _at(_tcp(server, client, dport, sport, seq=ss, flags="SA"), t + 0.001),
        _at(_tcp(client, server, sport, dport, request, seq=cs + 1), t + 0.002),
        _at(_tcp(server, client, dport, sport, response, seq=ss + 1), t + 0.003),
        _at(_tcp(client, server, sport, dport, seq=cs + 1 + len(request), flags="FA"), t + 0.004),
        _at(_tcp(server, client, dport, sport, seq=ss + 1 + len(response), flags="FA"), t + 0.005),
    ]
    return pkts


def _reconnecting_c2(tmp_path: Path, name: str = "c2.pcap", checkins: int = 12, gap: float = 300.0) -> Path:
    """HTTP C2 that opens a fresh connection per check-in (Ursnif, Cobalt Strike HTTP)."""
    client, server = "192.168.10.50", "93.184.216.34"
    request = b"POST /gate.php HTTP/1.1\r\nHost: c2.example\r\nContent-Length: 20\r\n\r\n" + b"A" * 20
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    pkts = []
    for i in range(checkins):
        pkts += _connection(client, server, 50000 + i, 80, request, response, T0 + i * gap)
    return _write(tmp_path, name, pkts)


def _hmi_polling(tmp_path: Path, plcs: int = 7, polls: int = 40, gap: float = 90.0) -> Path:
    """An HMI polling several PLCs over Modbus/TCP, one connection per poll."""
    hmi = "192.168.20.10"
    request = bytes.fromhex("000100000006") + bytes([1, 3, 0, 0, 0, 10])
    response = bytes.fromhex("000100000017") + bytes([1, 3, 20]) + bytes(20)
    pkts = []
    for pi in range(plcs):
        plc = f"192.168.20.{101 + pi}"
        for poll in range(polls):
            pkts += _connection(hmi, plc, 40000 + pi * 100 + poll, 502, request, response, T0 + poll * gap + pi * 0.01)
    pkts.sort(key=lambda p: p.time)
    return _write(tmp_path, "hmi.pcap", pkts)


# --- Beacon flow keying ------------------------------------------------------


class TestBeaconReconnect:
    def test_reconnecting_tcp_checkins_form_one_periodic_flow(self, tmp_path) -> None:
        """The flow key dropped the client port before the per-connection key
        was built, so every connection between the same pair shared one key:
        a reconnect-per-check-in C2 collapsed into a single event and was
        never scored, which is exactly the shape the key was meant to catch."""
        from pcapper.beacon import analyze_beacons

        utils.clear_analysis_memo()
        summary = analyze_beacons(_reconnecting_c2(tmp_path), show_status=False)
        flows = [c for c in summary.candidates if c.src_ip == "192.168.10.50" and c.dst_ip == "93.184.216.34"]
        assert len(flows) == 1, [(c.src_ip, c.dst_ip, c.count) for c in summary.candidates]
        assert flows[0].count == 12
        assert flows[0].score >= 0.8
        assert (flows[0].src_port or flows[0].dst_port) == 80


    def test_heartbeats_inside_one_persistent_connection_are_scored(self, tmp_path) -> None:
        """The detector only ever saw connection start times, so a beacon
        that keeps one socket open and heartbeats over it (reverse shells,
        websocket C2, Meterpreter keep-alives) was invisible. With too few
        connections to score, the client's request segments inside them are
        the event stream, held to the same cadence bar as datagrams."""
        from pcapper.beacon import analyze_beacons

        client, server = "192.168.10.50", "93.184.216.34"
        cs, ss = 1000, 5000
        pkts = [
            _at(_tcp(client, server, 51000, 8443, seq=cs, flags="S"), T0),
            _at(_tcp(server, client, 8443, 51000, seq=ss, flags="SA"), T0 + 0.01),
        ]
        cs += 1
        ss += 1
        for i in range(25):
            t = T0 + 1 + i * 60.0
            pkts.append(_at(_tcp(client, server, 51000, 8443, b"\x17\x03\x03\x00\x20" + b"h" * 32, seq=cs), t))
            cs += 37
            pkts.append(_at(_tcp(server, client, 8443, 51000, b"\x17\x03\x03\x00\x10" + b"a" * 16, seq=ss), t + 0.05))
            ss += 21
        utils.clear_analysis_memo()
        summary = analyze_beacons(_write(tmp_path, "persistent.pcap", pkts), show_status=False)
        flows = [c for c in summary.candidates if c.dst_ip == server]
        assert len(flows) == 1, [(c.src_ip, c.dst_ip, c.count) for c in summary.candidates]
        assert flows[0].event_basis == "request"
        assert flows[0].count == 25
        assert flows[0].score >= 0.8
        assert any("basis=requests-in-one-connection" in str(e) for d in summary.detections for e in d.get("evidence", []) or [])

    def test_irregular_requests_in_a_persistent_connection_are_not_a_beacon(self, tmp_path) -> None:
        """An interactive session over one socket (SSH keystrokes, keep-alive
        HTTP) carries many irregular requests; count alone must not admit it."""
        import random

        from pcapper.beacon import analyze_beacons

        rng = random.Random(3)
        client, server = "192.168.10.50", "93.184.216.34"
        cs, ss = 1000, 5000
        pkts = [
            _at(_tcp(client, server, 51001, 22, seq=cs, flags="S"), T0),
            _at(_tcp(server, client, 22, 51001, seq=ss, flags="SA"), T0 + 0.01),
        ]
        cs += 1
        ss += 1
        t = T0 + 1
        for _ in range(60):
            size = rng.randint(1, 400)
            pkts.append(_at(_tcp(client, server, 51001, 22, b"k" * size, seq=cs), t))
            cs += size
            pkts.append(_at(_tcp(server, client, 22, 51001, b"r" * rng.randint(1, 900), seq=ss), t + 0.02))
            ss += 1
            t += rng.choice([0.2, 0.5, 1.0, 3.0, 8.0, 45.0, 200.0])
        utils.clear_analysis_memo()
        summary = analyze_beacons(_write(tmp_path, "ssh.pcap", pkts), show_status=False)
        assert [c for c in summary.candidates if c.dst_ip == server] == []

    def test_connection_tracking_cap_is_reported(self, tmp_path, monkeypatch) -> None:
        """Per-connection tables grew without bound; beyond the cap further
        connections are counted, not tracked, and the report says so."""
        from pcapper import beacon

        monkeypatch.setattr(beacon, "MAX_TRACKED_CONNECTIONS", 5)
        utils.clear_analysis_memo()
        summary = beacon.analyze_beacons(_reconnecting_c2(tmp_path), show_status=False)
        assert any("packet(s) from TCP connections beyond the 5-connection tracking cap" in e for e in summary.errors), summary.errors
        assert all(c.count <= 5 for c in summary.candidates)

    def test_irregular_browsing_is_not_a_burst_sleep_beacon(self, tmp_path) -> None:
        """With reconnects scored again, forty connections to one CDN with
        random gaps and random sizes admitted a 0.35-score candidate, and the
        burst-then-sleep profile (bursty, idle) fired on it as a WARNING; the
        profile now also needs a moderately stable (>=0.5) candidate."""
        import random

        from pcapper.beacon import analyze_beacons

        rng = random.Random(7)
        client, server = "192.168.10.50", "93.184.216.34"
        pkts, t = [], T0
        for i in range(40):
            request = b"GET /a HTTP/1.1\r\nHost: cdn.example\r\n\r\n" + b"x" * rng.randint(0, 600)
            response = b"HTTP/1.1 200 OK\r\n\r\n" + b"y" * rng.randint(200, 1400)
            pkts += _connection(client, server, 50000 + i, 443, request, response, t)
            t += rng.choice([0.5, 1.0, 2.0, 5.0, 30.0, 120.0, 400.0])
        utils.clear_analysis_memo()
        summary = analyze_beacons(_write(tmp_path, "browsing.pcap", pkts), show_status=False)
        assert not [d for d in summary.detections if d.get("summary") == "Burst-then-sleep beacon profile"]
        assert {str(d.get("severity")) for d in summary.detections} == {"info"}, summary.detections


# --- Compromise assessment -----------------------------------------------------


class TestCompromisedOtBaseline:
    def test_hmi_polling_its_plcs_is_not_a_compromised_host(self, tmp_path) -> None:
        """Three defects stacked up on an HMI polling seven PLCs: the beacon
        step read the service port from ``dst_port`` (None for every TCP
        candidate) so the OT-baseline branch never fired and each poll was a
        HIGH beacon; info-level entries weighed 1 each, so five of them alone
        crossed the listing threshold; and the threat engine's own
        "baseline cyclic polling" downgrade was re-scored as warning evidence."""
        from pcapper.compromised import analyze_compromised

        utils.clear_analysis_memo()
        summary = analyze_compromised(_hmi_polling(tmp_path), show_status=False)
        assert summary.compromised_hosts == []
        beacon_rows = [d for d in summary.detections if d.get("source") == "Beacon"]
        assert beacon_rows, "the polling must still be visible as context"
        assert {str(d.get("severity")) for d in beacon_rows} == {"info"}
        ot_rows = [d for d in beacon_rows if str(d.get("summary", "")).startswith("Periodic OT control-channel")]
        assert len(ot_rows) == 7
        assert all(str(d.get("details", "")).endswith("TCP/502") for d in ot_rows)
        assert summary.incidents == [], "info-only clusters are not incidents"

    def test_hmi_polling_maps_to_no_attack_technique(self, tmp_path) -> None:
        """The same polling reached --mitre as three Command and Control
        TTPs ("beacon" in the text), and the executive assessment credited an
        objective-stage tactic to a controller being polled."""
        from pcapper.mitre import analyze_mitre

        utils.clear_analysis_memo()
        summary = analyze_mitre(_hmi_polling(tmp_path), show_status=False)
        assert summary.mapped_detections == 0, summary.hits
        assert not any("Command and Control" in r for r in summary.executive_reasons)
        assert summary.total_detections > 0
        assert any("internal periodic baseline" in line for line in summary.checks.get("sequence_plausibility", []))

    def test_reconnecting_external_c2_is_still_listed(self, tmp_path) -> None:
        """The other side of the change: a private->public reconnecting beacon
        keeps its HIGH severity and lists the client as compromised."""
        from pcapper.compromised import analyze_compromised

        utils.clear_analysis_memo()
        summary = analyze_compromised(_reconnecting_c2(tmp_path), show_status=False)
        ips = [h.ip for h in summary.compromised_hosts]
        assert "192.168.10.50" in ips, summary.detections
        host = next(h for h in summary.compromised_hosts if h.ip == "192.168.10.50")
        assert host.severity in {"high", "critical"}


class TestCompromisedIocs:
    def test_numbers_in_detection_prose_are_not_domain_iocs(self) -> None:
        """"score 0.98", "interval 90.00s" and "duration 58.50m" matched the
        domain pattern, were listed as the host's IOCs, and — identical for
        every host with a similar cadence — grouped unrelated hosts into
        phantom campaigns."""
        from pcapper.compromised import _extract_iocs

        text = "192.168.20.10->192.168.20.101 count=40 interval=90.00s size=41 score=0.98 duration 58.50m mean 90.0s"
        assert _extract_iocs(text) == set()
        assert _extract_iocs("beacon to evil-c2.example.com every 300s") == {"evil-c2.example.com"}
        assert "update.exe" in _extract_iocs("dropped update.exe from cdn.example.net")

    def test_campaign_iocs_need_a_real_tld(self) -> None:
        from pcapper.compromised import IOC_DOMAIN_RE

        assert IOC_DOMAIN_RE.fullmatch("0.98") is None
        assert IOC_DOMAIN_RE.fullmatch("58.50m") is None
        assert IOC_DOMAIN_RE.fullmatch("c2.example.com") is not None


class TestCompromisedStages:
    def test_stage_tokens_match_at_word_starts_only(self) -> None:
        """Bare substring matching made "Unauthorized command message" a
        credential-stage event (via "auth") and an "ec2-….amazonaws.com" peer
        a C2-stage one (via "c2"); stages feed the multi-stage verdict bonus."""
        from pcapper.compromised import _classify_stage

        assert _classify_stage("Unauthorized OT command message", "Modbus write to 192.168.20.101", "Modbus") == "other"
        assert _classify_stage("Large upload", "to ec2-1-2-3-4.compute.amazonaws.com", "Files") == "other"
        assert _classify_stage("Potential brute-force authentication attempts", "", "Threats") == "credential"
        assert _classify_stage("Beaconing behavior detected", "", "Beacon") == "c2"
        assert _classify_stage("Possible C2 channel", "", "Threats") == "c2"
        assert _classify_stage("Vertical port scan", "", "Scan") == "recon"
        assert _classify_stage("SMB lateral movement indicators", "", "SMB") == "lateral"


class TestCompromisedMerge:
    def test_merge_carries_roles_and_orders_hosts_totally(self) -> None:
        """The roll-up rebuilt each host without its browser-announced roles
        and crown-jewel flag, and sorted on (severity, score) alone, so two
        tied hosts came out in input order."""
        from pcapper.compromised import CompromisedHost, CompromiseSummary, merge_compromised_summaries

        def host(ip: str, score: int, roles: list[str] | None = None, infra: bool = False) -> CompromisedHost:
            return CompromisedHost(hostname="", ip=ip, detection_time=T0, explanation="x", evidence=[], iocs=[], severity="high", score=score, roles=roles or [], is_infra=infra)

        a = CompromiseSummary(path=Path("a.pcap"), total_hosts=2, compromised_hosts=[host("10.0.0.2", 10), host("10.0.0.1", 10, ["Domain Controller"], True)])
        b = CompromiseSummary(path=Path("b.pcap"), total_hosts=1, compromised_hosts=[host("10.0.0.1", 8, ["SQL Server"])])
        merged = merge_compromised_summaries([a, b])
        assert [h.ip for h in merged.compromised_hosts] == ["10.0.0.1", "10.0.0.2"]
        dc = merged.compromised_hosts[0]
        assert dc.roles == ["Domain Controller", "SQL Server"]
        assert dc.is_infra is True
        assert dc.score == 10
        # Input order must not change the result.
        again = merge_compromised_summaries([b, a])
        assert [h.ip for h in again.compromised_hosts] == ["10.0.0.1", "10.0.0.2"]
