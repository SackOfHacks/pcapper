"""Regression tests for the SMB client-inventory preview.

``render_smb_summary`` defined two of its nested helpers twice, 58 lines apart.
Python bound the later copy, and the two copies were not identical: the live one
omitted the space character from its allowed set, so every share, account and
group name containing a space was dropped from the preview and counted as
"filtered". On a Windows network that removes precisely the values an analyst is
looking for.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from pcapper.reporting import render_smb_summary
from pcapper.smb import SmbClient, SmbSummary


def _summary(clients: list[SmbClient]) -> SmbSummary:
    """A minimal SmbSummary carrying nothing but the client inventory."""
    return SmbSummary(
        path=Path("fixture.pcap"),
        total_packets=10,
        smb_packets=10,
        smb_ports=Counter({445: 10}),
        versions=Counter({"SMB2": 10}),
        commands=Counter(),
        requests=Counter(),
        responses=Counter(),
        error_codes=Counter(),
        signed_packets=10,
        unsigned_packets=0,
        encrypted_packets=0,
        sessions=[],
        conversations=[],
        servers=[],
        clients=clients,
        shares=[],
        files=[],
        artifacts=[],
        observed_users=Counter(),
        observed_domains=Counter(),
        anomalies=[],
        top_clients=Counter(),
        top_servers=Counter(),
        lateral_movement=[],
        analysis_notes=[],
        deterministic_checks={},
        threat_hypotheses=[],
        benign_context=[],
        errors=[],
    )


SPACED_ACCOUNTS = {"Domain Admins", "Backup Operators"}

# The preview falls back to the *unfiltered* list when the predicate rejects
# everything, which masks the defect entirely if every token contains a space.
# It only surfaces on a mixed set: one token passes, so the filtered list is
# non-empty and becomes the list actually shown — silently dropping the rest.
MIXED_ACCOUNTS = {"svc_sql", "Domain Admins", "Backup Operators"}


class TestTokensContainingSpaces:
    def test_spaced_accounts_survive_alongside_an_unspaced_one(self) -> None:
        client = SmbClient(ip="192.168.10.50", usernames=set(MIXED_ACCOUNTS))
        out = render_smb_summary(_summary([client]))
        for account in sorted(MIXED_ACCOUNTS):
            assert account in out, f"{account!r} was filtered out of the preview"

    def test_domain_names_with_spaces_survive_the_preview(self) -> None:
        client = SmbClient(ip="192.168.10.50", domains={"CONTOSO", "Contoso Corp"})
        out = render_smb_summary(_summary([client]))
        assert "Contoso Corp" in out
        assert "CONTOSO" in out

    def test_spaced_tokens_are_not_counted_as_filtered(self) -> None:
        """The 'filtered' suffix is how a dropped token announced itself."""
        client = SmbClient(ip="192.168.10.50", usernames=set(MIXED_ACCOUNTS))
        assert "filtered" not in render_smb_summary(_summary([client]))

    def test_all_spaced_tokens_also_survive(self) -> None:
        """The masked case: worth pinning too, so a future change to the
        fallback cannot quietly reintroduce the drop."""
        client = SmbClient(ip="192.168.10.50", usernames=set(SPACED_ACCOUNTS))
        out = render_smb_summary(_summary([client]))
        for account in sorted(SPACED_ACCOUNTS):
            assert account in out

    def test_genuinely_junk_tokens_are_still_filtered(self) -> None:
        """The filter still has to do its job — the fix restores the space, it
        does not disable the predicate."""
        client = SmbClient(
            ip="192.168.10.50",
            usernames={"svc_sql", "\x01\x02binary\x03", "a" * 200, "***"},
        )
        out = render_smb_summary(_summary([client]))
        assert "svc_sql" in out
        assert "\x01" not in out


class TestHelpersAreDefinedOnce:
    def test_no_duplicate_nested_definitions(self) -> None:
        """Pinned structurally as well as behaviourally: a reintroduced copy
        would re-break this silently, since Python binds the later one."""
        import ast
        import inspect

        source = inspect.getsource(render_smb_summary)
        tree = ast.parse(source.lstrip())
        names = [
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name != "render_smb_summary"
        ]
        duplicates = {name for name in names if names.count(name) > 1}
        assert not duplicates, f"nested helpers defined more than once: {duplicates}"


class TestRendersWithoutClients:
    def test_empty_inventory_does_not_raise(self) -> None:
        out = render_smb_summary(_summary([]))
        assert "No SMB clients identified." in out

    @pytest.mark.parametrize("verbose", [False, True])
    def test_both_verbosity_modes_render(self, verbose: bool) -> None:
        client = SmbClient(ip="192.168.10.50", usernames=set(MIXED_ACCOUNTS))
        out = render_smb_summary(_summary([client]), verbose=verbose)
        assert "192.168.10.50" in out
        for account in sorted(MIXED_ACCOUNTS):
            assert account in out
