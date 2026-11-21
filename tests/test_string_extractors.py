"""The C-speed string extractors return exactly what the byte loops they
replaced returned (copied below as the reference), for every buffer shape."""

from __future__ import annotations

import random

from pcapper.utils import extract_ascii_strings, extract_utf16le_strings


def _ascii_ref(data: bytes, min_len: int, max_len: int) -> list[str]:
    results, current = [], bytearray()
    for b in data:
        if 32 <= b <= 126:
            current.append(b)
        else:
            if len(current) >= min_len:
                results.append(current.decode("latin-1", errors="ignore")[:max_len])
            current = bytearray()
    if len(current) >= min_len:
        results.append(current.decode("latin-1", errors="ignore")[:max_len])
    return results


def _utf16_ref(data: bytes, min_len: int, max_len: int, step_on_miss: int) -> list[str]:
    """step_on_miss 2: the aligned copies (utils, PowerShell, LDAP); 1: the
    resynchronising ones (WMI, RPC)."""
    results, current, i = [], bytearray(), 0
    while i + 1 < len(data):
        ch = data[i]
        if 32 <= ch <= 126 and data[i + 1] == 0x00:
            current.append(ch)
            i += 2
            continue
        if len(current) >= min_len:
            results.append(current.decode("latin-1", errors="ignore")[:max_len])
        current = bytearray()
        i += step_on_miss
    if len(current) >= min_len:
        results.append(current.decode("latin-1", errors="ignore")[:max_len])
    return results


def _buffers(seed: int = 1337, count: int = 3000):
    rng = random.Random(seed)
    for n in range(count):
        parts = []
        for _ in range(rng.randint(0, 12)):
            kind = rng.random()
            text = bytes(rng.choice(b"abcXYZ019 .:/\\-_~") for _ in range(rng.randint(0, 9)))
            if kind < 0.3:
                parts.append(b"".join(bytes([c, 0]) for c in text))  # a wide string
            elif kind < 0.45:
                parts.append(b"\x00" + b"".join(bytes([c, 0]) for c in text))  # shifted by one
            elif kind < 0.7:
                parts.append(text)
            else:
                parts.append(bytes(rng.randrange(256) for _ in range(rng.randint(0, 7))))
        data = b"".join(parts)
        yield (bytearray(data) if n % 7 == 0 else data), rng.choice((1, 2, 3, 4, 5)), rng.choice((3, 4, 200))


def test_ascii_runs_match_the_byte_loop() -> None:
    for data, min_len, max_len in _buffers():
        assert extract_ascii_strings(data, min_len, max_len) == _ascii_ref(bytes(data), min_len, max_len), data


def test_wide_strings_match_both_byte_loops() -> None:
    for data, min_len, max_len in _buffers(seed=99):
        raw = bytes(data)
        assert extract_utf16le_strings(data, min_len, max_len) == _utf16_ref(raw, min_len, max_len, 2), raw
        assert extract_utf16le_strings(data, min_len, max_len, aligned=False) == _utf16_ref(raw, min_len, max_len, 1), raw


def test_edges() -> None:
    assert extract_ascii_strings(b"", 4, 200) == [] and extract_utf16le_strings(b"", 4, 200) == []
    assert extract_utf16le_strings(b"a\x00b\x00c\x00d\x00e", 4, 200) == ["abcd"]  # odd tail byte ignored
    assert extract_utf16le_strings(b"\x00a\x00b\x00c\x00d\x00", 4, 200) == []  # odd offset: not aligned
    assert extract_utf16le_strings(b"\x00a\x00b\x00c\x00d\x00", 4, 200, aligned=False) == ["abcd"]


def test_combined_screens_match_exactly_when_a_pattern_does() -> None:
    """The one-search screens in malware.py / powershell.py must say "match"
    exactly when one of the patterns they combine matches."""
    import re as _re

    from pcapper.malware import _TOOLING_ANY, SUSPICIOUS_TOOLING
    from pcapper.powershell import _SUSPICIOUS_ANY, SUSPICIOUS_PATTERNS

    words = ["powershell", "pwsh", "-enc", "-EncodedCommand", "FromBase64String", "mimikatz", "sekurlsa",
             "certutil", "bitsadmin", "mshta", "rundll32", "regsvr32", "psexec", "wmic", "winrs", "schtasks",
             "Invoke-WebRequest", "DownloadString", "WebClient", "IEX", "Invoke-Expression", "AmsiUtils",
             "-ExecutionPolicy Bypass", "Invoke-Command", "Get-Credential", "Compress-Archive", "JAB", "aGVsbG8=",
             "x", "-", "(", ")", " ", "\\", "/", "=", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA="]
    rng = random.Random(7)
    texts = [" ".join(rng.choice(words) for _ in range(rng.randint(0, 6))) for _ in range(4000)]
    texts += ["".join(chr(rng.randrange(32, 127)) for _ in range(rng.randint(0, 40))) for _ in range(2000)]
    for combined, patterns in ((_TOOLING_ANY, SUSPICIOUS_TOOLING), (_SUSPICIOUS_ANY, SUSPICIOUS_PATTERNS)):
        assert all(isinstance(p, _re.Pattern) for p, _label in patterns)
        for text in texts:
            assert bool(combined.search(text)) == any(p.search(text) for p, _label in patterns), text
