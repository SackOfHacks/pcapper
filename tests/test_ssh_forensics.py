from __future__ import annotations

from scapy.all import Ether, IP, Raw, TCP, wrpcap

import pcapper.ssh as ssh


def test_ssh_session_state_is_bounded_and_limit_is_reported(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr(ssh, "MAX_SSH_SESSIONS", 1)
    capture = tmp_path / "ssh_session_limit.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820, dport=22)
            / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n"),
            Ether()
            / IP(src="10.0.0.3", dst="10.0.0.2")
            / TCP(sport=51821, dport=22)
            / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n"),
        ],
    )

    result = ssh.analyze_ssh(capture, show_status=False)

    assert result.total_sessions == 1
    assert result.ssh_packets == 2
    assert any("session tracking limit" in error for error in result.errors)


def test_ssh_auth_inference_keeps_services_on_distinct_ports_separate(
    tmp_path,
) -> None:
    capture = tmp_path / "ssh_multiple_services.pcap"
    wrpcap(
        str(capture),
        [
            Ether()
            / IP(src="10.0.0.1", dst="10.0.0.2")
            / TCP(sport=51820 + index, dport=port)
            / Raw(load=b"SSH-2.0-OpenSSH_9.6\r\n")
            for index, port in enumerate((22, 2222, 2200))
        ],
    )

    result = ssh.analyze_ssh(capture, show_status=False)

    assert result.total_sessions == 3
    assert result.auth_inference == []
