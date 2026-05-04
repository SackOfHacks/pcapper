from __future__ import annotations

import base64
import bz2
import gzip
import html
import json
import lzma
import quopri
import re
import zlib
from dataclasses import dataclass
from typing import Callable
from urllib.parse import unquote, unquote_plus

try:
    from cryptography.hazmat.primitives import hashes, padding as sym_padding
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        load_pem_private_key,
    )
except Exception:  # pragma: no cover
    hashes = sym_padding = asym_padding = Cipher = algorithms = modes = None  # type: ignore[assignment]
    load_der_private_key = load_pem_private_key = None  # type: ignore[assignment]


@dataclass(frozen=True)
class DecodeResult:
    format_name: str
    value: str
    success: bool


@dataclass(frozen=True)
class DecodeSummary:
    source: str
    results: list[DecodeResult]


def _normalize_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except Exception:
            text = value.decode("latin-1", errors="replace")
    else:
        text = str(value)
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _looks_printable(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return (printable / max(len(text), 1)) >= 0.85


def _render_text(value: bytes | str, max_chars: int = 400) -> str:
    if isinstance(value, bytes):
        if not value:
            return ""
        text = _normalize_text(value)
        if _looks_printable(text):
            return text[:max_chars]
        return value[: max_chars // 2].hex()
    text = _normalize_text(value)
    return text[:max_chars]


def _maybe_b64decode(token: str, *, urlsafe: bool = False) -> bytes:
    raw = token.strip()
    if not raw:
        raise ValueError("empty input")
    if re.search(r"\s", raw):
        raw = "".join(raw.split())
    padding = "=" * ((4 - (len(raw) % 4)) % 4)
    data = (raw + padding).encode("ascii")
    if urlsafe:
        return base64.urlsafe_b64decode(data)
    return base64.b64decode(data, validate=False)


def _decode_hex(token: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", token)
    if not cleaned:
        raise ValueError("no hex chars")
    if len(cleaned) % 2:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def _decode_ascii_numbers(token: str, *, base: int) -> str:
    parts = [item for item in re.split(r"[\s,;:|]+", token.strip()) if item]
    if not parts:
        raise ValueError("no numeric tokens")
    chars: list[str] = []
    for part in parts:
        value = int(part, base)
        if value < 0 or value > 0x10FFFF:
            raise ValueError("invalid codepoint")
        chars.append(chr(value))
    return "".join(chars)


def _decode_binary(token: str) -> str:
    parts = [item for item in re.split(r"[\s,;:|]+", token.strip()) if item]
    if not parts:
        raise ValueError("no binary tokens")
    chars: list[str] = []
    for part in parts:
        if not re.fullmatch(r"[01]{7,8}", part):
            raise ValueError("invalid binary token")
        chars.append(chr(int(part, 2)))
    return "".join(chars)


def _rot(text: str, shift: int) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - ord("a") + shift) % 26 + ord("a")))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - ord("A") + shift) % 26 + ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def _atbash(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out)


def _decode_jwt_payload(token: str) -> str:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("not jwt-like")
    payload = _maybe_b64decode(parts[1], urlsafe=True)
    data = json.loads(payload.decode("utf-8", errors="strict"))
    return json.dumps(data, indent=2, sort_keys=True)


def _gzip_decompress_raw(text: str) -> bytes:
    return gzip.decompress(text.encode("latin-1", errors="ignore"))


def _zlib_decompress_raw(text: str) -> bytes:
    return zlib.decompress(text.encode("latin-1", errors="ignore"))


def _gzip_decompress_b64(text: str) -> bytes:
    payload = _maybe_b64decode(text, urlsafe=False)
    return gzip.decompress(payload)


def _zlib_decompress_b64(text: str) -> bytes:
    payload = _maybe_b64decode(text, urlsafe=False)
    return zlib.decompress(payload)


def _gzip_decompress_hex(text: str) -> bytes:
    return gzip.decompress(_decode_hex(text))


def _zlib_decompress_hex(text: str) -> bytes:
    return zlib.decompress(_decode_hex(text))


def _bz2_decompress_raw(text: str) -> bytes:
    return bz2.decompress(text.encode("latin-1", errors="ignore"))


def _bz2_decompress_b64(text: str) -> bytes:
    return bz2.decompress(_maybe_b64decode(text))


def _bz2_decompress_hex(text: str) -> bytes:
    return bz2.decompress(_decode_hex(text))


def _lzma_decompress_raw(text: str) -> bytes:
    return lzma.decompress(text.encode("latin-1", errors="ignore"))


def _lzma_decompress_b64(text: str) -> bytes:
    return lzma.decompress(_maybe_b64decode(text))


def _lzma_decompress_hex(text: str) -> bytes:
    return lzma.decompress(_decode_hex(text))


def _decode_base58(text: str) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    raw = text.strip()
    if not raw:
        raise ValueError("empty base58")
    num = 0
    for ch in raw:
        idx = alphabet.find(ch)
        if idx < 0:
            raise ValueError("invalid base58")
        num = num * 58 + idx
    out = b"" if num == 0 else num.to_bytes((num.bit_length() + 7) // 8, "big")
    leading_zeros = len(raw) - len(raw.lstrip("1"))
    return (b"\x00" * leading_zeros) + out


def _rot47(text: str) -> str:
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if 33 <= code <= 126:
            out.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            out.append(ch)
    return "".join(out)


def _decode_hex_text(text: str, encoding: str) -> str:
    return _decode_hex(text).decode(encoding, errors="replace")


def _decode_b64_text(text: str, encoding: str) -> str:
    return _maybe_b64decode(text).decode(encoding, errors="replace")


def _decode_punycode(text: str) -> str:
    raw = text.strip()
    if not raw:
        raise ValueError("empty input")
    return raw.encode("ascii").decode("punycode")


def _aes_key_candidates(key_text: str) -> list[bytes]:
    candidates: list[bytes] = []
    if key_text:
        candidates.append(key_text.encode("latin-1", errors="ignore"))
    try:
        candidates.append(_decode_hex(key_text))
    except Exception:
        pass
    try:
        candidates.append(_maybe_b64decode(key_text))
    except Exception:
        pass
    unique: list[bytes] = []
    seen: set[bytes] = set()
    for item in candidates:
        if not item or item in seen:
            continue
        if len(item) in {16, 24, 32}:
            seen.add(item)
            unique.append(item)
    return unique


def _ciphertext_candidates(source: str) -> list[bytes]:
    candidates: list[bytes] = [source.encode("latin-1", errors="ignore")]
    for decoder in (_decode_hex, _maybe_b64decode):
        try:
            value = decoder(source)  # type: ignore[misc]
            if value:
                candidates.append(value)
        except Exception:
            pass
    unique: list[bytes] = []
    seen: set[bytes] = set()
    for value in candidates:
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(value)
    return unique


def _score_bytes(data: bytes) -> float:
    if not data:
        return -1.0
    text = _normalize_text(data)
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return printable / max(len(text), 1)


def _aes_decrypt_auto(source: str, key_text: str) -> bytes:
    if Cipher is None or algorithms is None or modes is None:
        raise RuntimeError("cryptography backend unavailable")
    keys = _aes_key_candidates(key_text)
    if not keys:
        raise ValueError("unable to derive AES key bytes (need 16/24/32-byte key)")
    ctexts = _ciphertext_candidates(source)
    best: bytes | None = None
    best_score = -1.0
    for key in keys:
        for ctext in ctexts:
            if len(ctext) < 16 or len(ctext) % 16 != 0:
                continue
            mode_options = [("ECB", modes.ECB()), ("CBC-zero-iv", modes.CBC(b"\x00" * 16))]
            for _mode_name, mode in mode_options:
                try:
                    cipher = Cipher(algorithms.AES(key), mode)
                    decryptor = cipher.decryptor()
                    plain = decryptor.update(ctext) + decryptor.finalize()
                except Exception:
                    continue
                for candidate in (plain, _pkcs7_unpad(plain, block_bits=128)):
                    score = _score_bytes(candidate)
                    if score > best_score:
                        best_score = score
                        best = candidate
    if best is None:
        raise ValueError("no AES candidate produced output")
    return best


def _pkcs7_unpad(data: bytes, block_bits: int) -> bytes:
    if sym_padding is None:
        return data
    try:
        unpadder = sym_padding.PKCS7(block_bits).unpadder()
        return unpadder.update(data) + unpadder.finalize()
    except Exception:
        return data


def _read_key_text(key_text: str) -> str:
    token = str(key_text or "").strip()
    if token.startswith("@"):
        path = token[1:]
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.read()
    return token


def _rsa_private_key_candidates(key_text: str) -> list[object]:
    if load_pem_private_key is None or load_der_private_key is None:
        raise RuntimeError("cryptography backend unavailable")
    raw = _read_key_text(key_text)
    out: list[object] = []
    key_bytes_candidates: list[bytes] = [raw.encode("utf-8", errors="ignore")]
    for fn in (_decode_hex, _maybe_b64decode):
        try:
            value = fn(raw)  # type: ignore[misc]
            if value:
                key_bytes_candidates.append(value)
        except Exception:
            pass
    seen: set[bytes] = set()
    for blob in key_bytes_candidates:
        if not blob or blob in seen:
            continue
        seen.add(blob)
        for loader in (load_pem_private_key, load_der_private_key):
            try:
                key_obj = loader(blob, password=None)  # type: ignore[misc]
                out.append(key_obj)
                break
            except Exception:
                continue
    if not out:
        raise ValueError("failed loading RSA private key")
    return out


def _rsa_decrypt_auto(source: str, key_text: str) -> bytes:
    if asym_padding is None or hashes is None:
        raise RuntimeError("cryptography backend unavailable")
    keys = _rsa_private_key_candidates(key_text)
    ctexts = _ciphertext_candidates(source)
    best: bytes | None = None
    best_score = -1.0
    for key in keys:
        for ctext in ctexts:
            padding_options = [
                asym_padding.PKCS1v15(),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None,
                ),
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            ]
            for pad in padding_options:
                try:
                    plain = key.decrypt(ctext, pad)
                except Exception:
                    continue
                score = _score_bytes(plain)
                if score > best_score:
                    best_score = score
                    best = plain
    if best is None:
        raise ValueError("no RSA decrypt candidate succeeded")
    return best


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty xor key")
    out = bytearray()
    key_len = len(key)
    for idx, value in enumerate(data):
        out.append(value ^ key[idx % key_len])
    return bytes(out)


def _xor_decode_text(source: str, key: str) -> bytes:
    data = source.encode("latin-1", errors="ignore")
    key_bytes = key.encode("latin-1", errors="ignore")
    return _xor_bytes(data, key_bytes)


def _xor_decode_hex(source: str, key: str) -> bytes:
    data = _decode_hex(source)
    key_bytes = key.encode("latin-1", errors="ignore")
    return _xor_bytes(data, key_bytes)


def analyze_decode(
    source: str,
    xor_key: str | None = None,
    aes_key: str | None = None,
    rsa_key: str | None = None,
) -> DecodeSummary:
    text = _normalize_text(source)

    formats: list[tuple[str, Callable[[str], bytes | str]]] = [
        ("URL Percent Decode", lambda s: unquote(s)),
        ("URL Percent Decode (+ as space)", lambda s: unquote_plus(s)),
        ("URL Percent Decode (double pass)", lambda s: unquote(unquote(s))),
        ("URL Percent Decode + (double pass)", lambda s: unquote_plus(unquote_plus(s))),
        ("HTML Entity Decode", lambda s: html.unescape(s)),
        ("Base64 Decode", lambda s: _maybe_b64decode(s)),
        ("Base64 URL-safe Decode", lambda s: _maybe_b64decode(s, urlsafe=True)),
        ("Base32 Decode", lambda s: base64.b32decode(s.strip().upper(), casefold=True)),
        ("Base16 Decode", lambda s: base64.b16decode(s.strip().upper(), casefold=True)),
        ("Base85 Decode", lambda s: base64.b85decode(s.strip().encode("ascii"))),
        ("ASCII85 Decode", lambda s: base64.a85decode(s.strip().encode("ascii"))),
        ("Base58 Decode", lambda s: _decode_base58(s)),
        ("Hex Decode", lambda s: _decode_hex(s)),
        ("Quoted-Printable Decode", lambda s: quopri.decodestring(s.encode("latin-1", errors="ignore"))),
        ("Binary ASCII Decode", lambda s: _decode_binary(s)),
        ("Decimal ASCII Decode", lambda s: _decode_ascii_numbers(s, base=10)),
        ("Octal ASCII Decode", lambda s: _decode_ascii_numbers(s, base=8)),
        ("UTF-8 Decode (hex input)", lambda s: _decode_hex_text(s, "utf-8")),
        ("UTF-16LE Decode (hex input)", lambda s: _decode_hex_text(s, "utf-16-le")),
        ("UTF-16BE Decode (hex input)", lambda s: _decode_hex_text(s, "utf-16-be")),
        ("UTF-8 Decode (Base64 input)", lambda s: _decode_b64_text(s, "utf-8")),
        ("ROT13 Decode", lambda s: _rot(s, 13)),
        ("ROT47 Decode", lambda s: _rot47(s)),
        ("Caesar -3 Decode", lambda s: _rot(s, -3)),
        ("Caesar +3 Decode", lambda s: _rot(s, 3)),
        ("Atbash Decode", lambda s: _atbash(s)),
        ("Reverse String", lambda s: s[::-1]),
        ("Punycode Decode", lambda s: _decode_punycode(s)),
        ("Unicode Escape Decode", lambda s: s.encode("utf-8").decode("unicode_escape")),
        ("JWT Payload Decode", lambda s: _decode_jwt_payload(s)),
        ("GZIP Decompress (raw text bytes)", lambda s: _gzip_decompress_raw(s)),
        ("ZLIB Decompress (raw text bytes)", lambda s: _zlib_decompress_raw(s)),
        ("GZIP Decompress (Base64 input)", lambda s: _gzip_decompress_b64(s)),
        ("ZLIB Decompress (Base64 input)", lambda s: _zlib_decompress_b64(s)),
        ("GZIP Decompress (hex input)", lambda s: _gzip_decompress_hex(s)),
        ("ZLIB Decompress (hex input)", lambda s: _zlib_decompress_hex(s)),
        ("BZ2 Decompress (raw text bytes)", lambda s: _bz2_decompress_raw(s)),
        ("BZ2 Decompress (Base64 input)", lambda s: _bz2_decompress_b64(s)),
        ("BZ2 Decompress (hex input)", lambda s: _bz2_decompress_hex(s)),
        ("LZMA Decompress (raw text bytes)", lambda s: _lzma_decompress_raw(s)),
        ("LZMA Decompress (Base64 input)", lambda s: _lzma_decompress_b64(s)),
        ("LZMA Decompress (hex input)", lambda s: _lzma_decompress_hex(s)),
    ]
    if xor_key is not None and str(xor_key):
        key = str(xor_key)
        formats.append(("XOR Decode (raw input, repeating key)", lambda s: _xor_decode_text(s, key)))
        formats.append(("XOR Decode (hex input, repeating key)", lambda s: _xor_decode_hex(s, key)))
    if aes_key is not None and str(aes_key):
        key = str(aes_key)
        formats.append(("AES Decrypt (auto mode/padding)", lambda s: _aes_decrypt_auto(s, key)))
    if rsa_key is not None and str(rsa_key):
        key = str(rsa_key)
        formats.append(("RSA Decrypt (auto padding; private key)", lambda s: _rsa_decrypt_auto(s, key)))

    results: list[DecodeResult] = []
    for name, decoder in formats:
        try:
            value = decoder(text)
            rendered = _render_text(value)
            if not rendered:
                rendered = "<decoded empty output>"
            results.append(DecodeResult(name, rendered, True))
        except Exception:
            results.append(DecodeResult(name, "-", False))
    return DecodeSummary(source=text, results=results)
