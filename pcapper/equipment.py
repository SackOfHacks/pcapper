from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Iterable

from .utils import safe_read_text, decode_payload
from .device_detection import device_fingerprints_from_text

@lru_cache(maxsize=4)
def _load_json(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    try:
        import json

        raw_text = safe_read_text(path, encoding="utf-8", errors="ignore")
        if not raw_text:
            return {}
        raw = json.loads(raw_text)
        return raw if isinstance(raw, dict) else {}
    except Exception:
        return {}


def _add_token(
    index: dict[str, tuple[str, str]],
    token: str,
    vendor: str,
    label: str,
) -> None:
    token = token.strip()
    if len(token) < 4:
        return
    index.setdefault(token.lower(), (vendor, label))


def _collect_rockwell() -> dict[str, tuple[str, str]]:
    index: dict[str, tuple[str, str]] = {}
    data = _load_json(Path(__file__).with_name("enip_mappings.json"))
    vendors = data.get("vendors") if isinstance(data.get("vendors"), dict) else {}
    vendor = str(vendors.get("1") or "Rockwell Automation / Allen-Bradley")

    product_codes = data.get("product_codes")
    if isinstance(product_codes, dict):
        for vendor_bucket in product_codes.values():
            if not isinstance(vendor_bucket, dict):
                continue
            for name in vendor_bucket.values():
                if isinstance(name, str) and name.strip():
                    _add_token(index, name, vendor, name)

    return index


def _collect_siemens() -> dict[str, tuple[str, str]]:
    index: dict[str, tuple[str, str]] = {}
    data = _load_json(Path(__file__).with_name("siemens_mappings.json"))
    vendor = str(data.get("vendor") or "Siemens")

    products = data.get("products")
    if isinstance(products, list):
        for product in products:
            if not isinstance(product, dict):
                continue
            code = product.get("product_code")
            name = product.get("device_name") or product.get("product_family")
            if isinstance(code, str) and code.strip():
                label = f"{name} ({code})" if name else code
                _add_token(index, code, vendor, label)
            if isinstance(name, str) and name.strip():
                _add_token(index, name, vendor, name)

    return index


@lru_cache
def _equipment_index() -> dict[str, tuple[str, str]]:
    index: dict[str, tuple[str, str]] = {}
    index.update(_collect_rockwell())
    index.update(_collect_siemens())
    return index


def equipment_artifacts(payload: bytes, limit: int = 512) -> list[tuple[str, str]]:
    if not payload:
        return []
    text = decode_payload(payload, encoding="utf-8", limit=limit)
    if not text:
        return []
    lowered = text.lower()
    if not any(ch.isalnum() for ch in lowered):
        return []

    matches: list[tuple[str, str]] = []
    seen: set[str] = set()
    for token, (vendor, label) in _equipment_index().items():
        if token in lowered:
            detail = f"{vendor}: {label}"
            if detail in seen:
                continue
            seen.add(detail)
            matches.append(("equipment", detail))

    for detail in device_fingerprints_from_text(text, source="payload"):
        if detail in seen:
            continue
        seen.add(detail)
        matches.append(("device", detail))

    return matches
