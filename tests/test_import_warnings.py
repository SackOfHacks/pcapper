"""Importing pcapper must not print scapy's cryptography deprecation noise.

scapy's TLS layer imports FFDH primitives, which cryptography >= 46 flags with a
CryptographyDeprecationWarning at import time. It printed on every run, before
the banner, and says nothing about the capture. Run in a subprocess because the
warning fires once per interpreter and pytest has already imported scapy here.
"""

from __future__ import annotations

import subprocess
import sys


def test_cli_import_emits_no_cryptography_deprecation_warning() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "default", "-c", "import pcapper.cli"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "CryptographyDeprecationWarning" not in result.stderr, result.stderr
