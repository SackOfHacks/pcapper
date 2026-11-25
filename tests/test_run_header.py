"""The header a run starts with (name and version), and the quote of the
day, which only the full ASCII-art banner shows."""

from __future__ import annotations

import re

from pcapper import cli


def test_quote_of_the_day_is_on_the_full_banner_only(monkeypatch) -> None:
    monkeypatch.setenv("PCAPPER_QUOTE", "Trust the physics, verify the traffic.")
    lines = re.sub(r"\x1b\[[0-9;]*m", "", cli._build_run_header()).splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("PCAPPER v") and "PCAP forensics and threat hunting" in lines[0]
    assert "Trust the physics" not in cli._build_run_header()
    assert 'Quote of the Day: "Trust the physics, verify the traffic."' in cli._build_banner()
    monkeypatch.delenv("PCAPPER_QUOTE")
    monkeypatch.setenv("PCAPPER_QUOTE_SEED", "3")
    assert cli._quote_of_the_day() == cli._OT_ICS_QUOTES[3]
    assert f'"{cli._OT_ICS_QUOTES[3]}"' in cli._build_banner()  # the full banner picks the same quote
