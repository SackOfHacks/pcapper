from __future__ import annotations

from types import SimpleNamespace

import pcapper.ldap as ldap
from pcapper.pcap_cache import PcapMeta


def test_nested_analyses_reuse_packet_view_and_surface_errors(
    tmp_path, monkeypatch
) -> None:
    packets = []
    path = tmp_path / "ldap_nested_errors.pcap"
    meta = PcapMeta(path, "pcap", 0, None, None, None)
    calls = {}

    def fake_dns(path, **kwargs):
        calls["dns"] = kwargs
        return SimpleNamespace(qname_counts={}, errors=["DNS parse warning"])

    def fake_files(path, **kwargs):
        calls["files"] = kwargs
        return SimpleNamespace(artifacts=[], errors=["File scan warning"])

    monkeypatch.setattr(ldap, "analyze_dns", fake_dns)
    monkeypatch.setattr(ldap, "analyze_files", fake_files)

    result = ldap.analyze_ldap(
        path,
        show_status=False,
        packets=packets,
        meta=meta,
    )

    assert calls["dns"]["packets"] is packets
    assert calls["dns"]["meta"] is meta
    assert calls["files"]["packets"] is packets
    assert calls["files"]["meta"] is meta
    assert result.errors == ["DNS parse warning", "File scan warning"]
