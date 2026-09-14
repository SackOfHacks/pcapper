"""Config-file loading: where pcapper looks, and what it refuses to do silently.

The lookup used to include ``./pcapper.toml``. pcapper is run from inside
evidence directories, and a config there can set ``vt = true`` (send the
investigation's domains and URLs to VirusTotal), ``ip_geo = true`` (send every
public IP to ip-api.com) or redirect the JSON/CSV/carve/decrypt output paths —
applied with nothing on the command line to show it happened. These tests pin
the behaviour that closed that: no CWD lookup, a visible ``Config:`` line, a
loud parse failure, and a notice for any egress-enabling key.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from pcapper import cli
from pcapper.config import find_config, load_config

REPO = Path(__file__).parent.parent


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An empty home directory so no real ~/.pcapper.toml leaks in."""
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setenv("USERPROFILE", str(fake_home))
    monkeypatch.setattr(
        "pcapper.config.DEFAULT_CONFIG_PATHS",
        [fake_home / ".pcapper.toml", fake_home / ".config" / "pcapper" / "config.toml"],
    )
    return fake_home


class TestLookup:
    def test_cwd_config_is_not_loaded(self, home, tmp_path, monkeypatch) -> None:
        evidence = tmp_path / "evidence"
        evidence.mkdir()
        (evidence / "pcapper.toml").write_text("[defaults]\nvt = true\n", encoding="utf-8")
        monkeypatch.chdir(evidence)
        assert find_config(None) is None

    def test_home_config_is_found(self, home) -> None:
        cfg = home / ".pcapper.toml"
        cfg.write_text("[defaults]\nno_color = true\n", encoding="utf-8")
        assert find_config(None) == cfg

    def test_explicit_path_wins(self, home, tmp_path) -> None:
        (home / ".pcapper.toml").write_text("[defaults]\n", encoding="utf-8")
        explicit = tmp_path / "mine.toml"
        explicit.write_text("[defaults]\n", encoding="utf-8")
        assert find_config(explicit) == explicit


class TestLoad:
    def test_parse_error_is_reported_not_swallowed(self, tmp_path) -> None:
        bad = tmp_path / "bad.toml"
        bad.write_text("[defaults\nno_color = true\n", encoding="utf-8")
        result = load_config(bad)
        assert result.data == {}
        assert result.error and "parse error" in result.error

    def test_missing_explicit_file_is_an_error(self, tmp_path) -> None:
        result = load_config(tmp_path / "absent.toml")
        assert result.error and "not found" in result.error

    def test_valid_file_loads(self, tmp_path) -> None:
        cfg = tmp_path / "ok.toml"
        cfg.write_text("[defaults]\ntimeline_bins = 48\n", encoding="utf-8")
        result = load_config(cfg)
        assert result.error is None
        assert result.data == {"defaults": {"timeline_bins": 48}}


class TestApply:
    def _apply(self, config: dict, argv: list[str]):
        parser = cli.build_parser([])
        args = parser.parse_args(argv)
        return args, cli._apply_config_defaults(parser, args, config, argv)

    def test_known_keys_apply_and_cli_wins(self) -> None:
        args, applied = self._apply(
            {"defaults": {"timeline_bins": 48, "no_color": True}},
            ["x.pcap", "--timeline-bins", "12"],
        )
        assert args.timeline_bins == 12  # explicit flag beats config
        assert args.no_color is True
        assert applied.applied == ("no_color",)

    def test_unknown_keys_are_reported(self) -> None:
        _, applied = self._apply({"defaults": {"timeline_binz": 48}}, ["x.pcap"])
        assert applied.unknown == ("timeline_binz",)
        assert applied.applied == ()

    def test_egress_keys_are_flagged(self) -> None:
        args, applied = self._apply({"defaults": {"vt": True, "ip_geo": True}}, ["x.pcap"])
        assert args.vt is True
        assert applied.egress == ("ip_geo", "vt")

    def test_egress_key_set_false_is_not_flagged(self) -> None:
        _, applied = self._apply({"defaults": {"vt": False}}, ["x.pcap"])
        assert applied.egress == ()


@pytest.mark.slow
class TestEndToEnd:
    """The CLI announces the config it used, and refuses one it cannot parse."""

    def _run(self, argv: list[str], env_extra: dict[str, str]) -> subprocess.CompletedProcess:
        import os

        env = dict(os.environ, NO_COLOR="1", PYTHONIOENCODING="utf-8", **env_extra)
        return subprocess.run(
            [sys.executable, "-m", "pcapper", *argv],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            env=env, cwd=REPO, timeout=300,
        )

    def test_applied_config_is_announced_on_stderr(self, tmp_path, pcap) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text("[defaults]\nno_status = true\nbogus_key = 1\n", encoding="utf-8")
        proc = self._run([str(pcap("dns.pcap")), "--dns", "--quiet", "--config", str(cfg)], {})
        assert proc.returncode == 0, proc.stderr
        assert f"Config: {cfg}" in proc.stderr
        assert "ignored unknown key(s): bogus_key" in proc.stderr

    def test_unparseable_config_exits_2(self, tmp_path, pcap) -> None:
        cfg = tmp_path / "c.toml"
        cfg.write_text("[defaults\n", encoding="utf-8")
        proc = self._run([str(pcap("dns.pcap")), "--dns", "--config", str(cfg)], {})
        assert proc.returncode == 2
        assert "Config: config parse error" in proc.stderr
