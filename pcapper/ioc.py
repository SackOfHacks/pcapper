from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Iterable, Any
import hashlib
import json
import uuid

from .dns import DnsSummary
from .http import HttpSummary
from .strings import StringsSummary
from .files import FileTransferSummary
from .ips import IpSummary


@dataclass(frozen=True)
class IocItem:
    ioc_type: str
    value: str
    source: str
    details: dict[str, object] | None = None


def _now_zulu() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _normalize_value(value: str) -> str:
    return value.strip()


def _hash_payload(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _add_ioc(bucket: dict[tuple[str, str], IocItem], item: IocItem) -> None:
    key = (item.ioc_type, item.value)
    if key in bucket:
        return
    bucket[key] = item


def collect_iocs(
    dns_summary: DnsSummary | None = None,
    http_summary: HttpSummary | None = None,
    strings_summary: StringsSummary | None = None,
    files_summary: FileTransferSummary | None = None,
    ips_summary: IpSummary | None = None,
) -> list[IocItem]:
    items: dict[tuple[str, str], IocItem] = {}

    if ips_summary:
        for endpoint in ips_summary.endpoints:
            value = _normalize_value(endpoint.ip)
            if value:
                _add_ioc(items, IocItem("ip", value, "ips"))
        for finding in ips_summary.intel_findings:
            ip = finding.get("ip")
            if isinstance(ip, str) and ip:
                details = {k: v for k, v in finding.items() if k != "ip"}
                _add_ioc(items, IocItem("ip", ip, str(finding.get("source", "intel")), details))
        for sni, count in ips_summary.sni_counts.items():
            value = _normalize_value(sni)
            if value:
                _add_ioc(items, IocItem("domain", value, "tls", {"count": count}))
        for ja3, count in ips_summary.ja3_counts.items():
            value = _normalize_value(ja3)
            if value:
                _add_ioc(items, IocItem("ja3", value, "tls", {"count": count}))
        for ja4, count in ips_summary.ja4_counts.items():
            value = _normalize_value(ja4)
            if value:
                _add_ioc(items, IocItem("ja4", value, "tls", {"count": count}))
        for ja4s, count in ips_summary.ja4s_counts.items():
            value = _normalize_value(ja4s)
            if value:
                _add_ioc(items, IocItem("ja4s", value, "tls", {"count": count}))

    if dns_summary:
        for name, count in dns_summary.qname_counts.items():
            value = _normalize_value(name)
            if value:
                _add_ioc(items, IocItem("domain", value, "dns", {"count": count}))

    if http_summary:
        for host, count in http_summary.host_counts.items():
            value = _normalize_value(host)
            if value:
                _add_ioc(items, IocItem("domain", value, "http", {"count": count}))
        for url, count in http_summary.url_counts.items():
            value = _normalize_value(url)
            if value:
                _add_ioc(items, IocItem("url", value, "http", {"count": count}))

    if strings_summary:
        for item in strings_summary.urls:
            value = _normalize_value(item.value)
            if value:
                _add_ioc(items, IocItem("url", value, "strings", {"count": item.count}))
        for item in strings_summary.domains:
            value = _normalize_value(item.value)
            if value:
                _add_ioc(items, IocItem("domain", value, "strings", {"count": item.count}))
        for item in strings_summary.emails:
            value = _normalize_value(item.value)
            if value:
                _add_ioc(items, IocItem("email", value, "strings", {"count": item.count}))

    if files_summary:
        for artifact in files_summary.artifacts:
            sha256 = getattr(artifact, "sha256", None)
            md5 = getattr(artifact, "md5", None)
            if not sha256 and artifact.payload:
                sha256 = _hash_payload(artifact.payload)
            if sha256:
                _add_ioc(items, IocItem("sha256", sha256, "files", {"filename": artifact.filename, "file_type": artifact.file_type}))
            if md5:
                _add_ioc(items, IocItem("md5", md5, "files", {"filename": artifact.filename, "file_type": artifact.file_type}))

    return list(items.values())


def export_iocs_json(iocs: Iterable[IocItem]) -> str:
    payload = [
        {
            "type": item.ioc_type,
            "value": item.value,
            "source": item.source,
            "details": item.details or {},
        }
        for item in iocs
    ]
    return json.dumps(payload, indent=2, sort_keys=True)


def export_iocs_csv(iocs: Iterable[IocItem]) -> str:
    rows = ["type,value,source,details"]
    for item in iocs:
        details = json.dumps(item.details or {}, sort_keys=True)
        value = item.value.replace('"', '""')
        rows.append(f"{item.ioc_type},\"{value}\",{item.source},\"{details}\"")
    return "\n".join(rows)


def _stix_pattern(item: IocItem) -> Optional[str]:
    value = item.value.replace("'", "\\'")
    if item.ioc_type == "ip":
        if ":" in value:
            return f"[ipv6-addr:value = '{value}']"
        return f"[ipv4-addr:value = '{value}']"
    if item.ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if item.ioc_type == "url":
        return f"[url:value = '{value}']"
    if item.ioc_type == "email":
        return f"[email-addr:value = '{value}']"
    if item.ioc_type == "sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if item.ioc_type == "md5":
        return f"[file:hashes.MD5 = '{value}']"
    if item.ioc_type in {"ja3", "ja4", "ja4s"}:
        return "[x-{}:value = '{}']".format(item.ioc_type, value)
    return None


def export_iocs_stix(iocs: Iterable[IocItem]) -> str:
    created = _now_zulu()
    objects: list[dict[str, Any]] = []
    for item in iocs:
        pattern = _stix_pattern(item)
        if not pattern:
            continue
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": created,
            "modified": created,
            "name": f"{item.ioc_type} indicator",
            "pattern": pattern,
            "pattern_type": "stix",
            "labels": ["pcapper", item.source],
        })
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
    return json.dumps(bundle, indent=2, sort_keys=True)


def write_iocs(output: str, out_path: str | None) -> None:
    if out_path:
        Path(out_path).write_text(output, encoding="utf-8")
    else:
        print(output)
