from __future__ import annotations

import pytest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except Exception:  # pragma: no cover
    pytest.skip("hypothesis not installed", allow_module_level=True)

from pcapper.files import _decode_chunked
from pcapper.http import _parse_chunked_length


@given(st.binary(max_size=2048))
@settings(max_examples=200)
def test_decode_chunked_fuzz(data: bytes):
    _decode_chunked(data)


@given(st.binary(max_size=2048), st.integers(min_value=0, max_value=2048))
@settings(max_examples=200)
def test_parse_chunked_length_fuzz(data: bytes, idx: int):
    if idx >= len(data):
        return
    _parse_chunked_length(data, idx)
