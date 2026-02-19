from __future__ import annotations

import re
from typing import Iterable


_DEVICE_HINT_RE = re.compile(
    r"(?i)\b("
    r"firmware|fw|software|sw|version|ver|revision|rev|build|"
    r"model|product|device|order\s*code|catalog|"
    r"plc|pac|rtu|hmi|scada|dcs|ied|relay|vfd|drive|"
    r"router|switch|firewall|gateway|camera|sensor|"
    r"windows|linux|ubuntu|debian|centos|red hat|"
    r"vxworks|qnx|freertos|threadx|integrity|ecos|"
    r"siemens|rockwell|allen-bradley|schneider|omron|mitsubishi|"
    r"yokogawa|honeywell|emerson|abb|ge|beckhoff|phoenix|wago|"
    r"advantech|moxa|hirschmann|cisco|juniper|fortinet|palo alto|microsoft|msft"
    r")\b"
)

_VENDOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\ballen[- ]?bradley\b|\brockwell\b", re.IGNORECASE), "Rockwell Automation / Allen-Bradley"),
    (re.compile(r"\bsiemens\b", re.IGNORECASE), "Siemens"),
    (re.compile(r"\bschneider\b|\bmodicon\b|\btelemechanique\b", re.IGNORECASE), "Schneider Electric"),
    (re.compile(r"\bomron\b", re.IGNORECASE), "Omron"),
    (re.compile(r"\bmitsubishi\b", re.IGNORECASE), "Mitsubishi Electric"),
    (re.compile(r"\byokogawa\b", re.IGNORECASE), "Yokogawa"),
    (re.compile(r"\bhoneywell\b", re.IGNORECASE), "Honeywell"),
    (re.compile(r"\bemerson\b|\bovation\b|\bdelta[v]?\b", re.IGNORECASE), "Emerson"),
    (re.compile(r"\babb\b", re.IGNORECASE), "ABB"),
    (re.compile(r"\bge\b|general electric", re.IGNORECASE), "GE"),
    (re.compile(r"\bbeckhoff\b", re.IGNORECASE), "Beckhoff"),
    (re.compile(r"\bphoenix contact\b", re.IGNORECASE), "Phoenix Contact"),
    (re.compile(r"\bwago\b", re.IGNORECASE), "WAGO"),
    (re.compile(r"\badvantech\b", re.IGNORECASE), "Advantech"),
    (re.compile(r"\bmoxa\b", re.IGNORECASE), "Moxa"),
    (re.compile(r"\bhirschmann\b", re.IGNORECASE), "Hirschmann"),
    (re.compile(r"\bcisco\b", re.IGNORECASE), "Cisco"),
    (re.compile(r"\bjuniper\b", re.IGNORECASE), "Juniper"),
    (re.compile(r"\bfortinet\b", re.IGNORECASE), "Fortinet"),
    (re.compile(r"\bpalo alto\b", re.IGNORECASE), "Palo Alto Networks"),
    (re.compile(r"\bmikrotik\b", re.IGNORECASE), "MikroTik"),
    (re.compile(r"\bdell\b", re.IGNORECASE), "Dell"),
    (re.compile(r"\bmicrosoft\b|\bmsft\b", re.IGNORECASE), "Microsoft"),
    (re.compile(r"\bhewlett[- ]?packard\b|\bhp\b", re.IGNORECASE), "HP"),
    (re.compile(r"\blenovo\b", re.IGNORECASE), "Lenovo"),
    (re.compile(r"\bapple\b", re.IGNORECASE), "Apple"),
]

_DEVICE_TYPE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bplc\b|programmable logic controller", re.IGNORECASE), "PLC"),
    (re.compile(r"\bpac\b|programmable automation controller", re.IGNORECASE), "PAC"),
    (re.compile(r"\brtu\b", re.IGNORECASE), "RTU"),
    (re.compile(r"\bhmi\b", re.IGNORECASE), "HMI"),
    (re.compile(r"\bscada\b", re.IGNORECASE), "SCADA"),
    (re.compile(r"\bdcs\b", re.IGNORECASE), "DCS"),
    (re.compile(r"\bied\b|intelligent electronic device", re.IGNORECASE), "IED"),
    (re.compile(r"\brelay\b|protection relay", re.IGNORECASE), "Protection Relay"),
    (re.compile(r"\bvfd\b|variable frequency drive|drive\b", re.IGNORECASE), "Drive/VFD"),
    (re.compile(r"\brouter\b", re.IGNORECASE), "Router"),
    (re.compile(r"\bswitch\b", re.IGNORECASE), "Switch"),
    (re.compile(r"\bfirewall\b", re.IGNORECASE), "Firewall"),
    (re.compile(r"\bgateway\b", re.IGNORECASE), "Gateway"),
    (re.compile(r"\bcamera\b", re.IGNORECASE), "Camera"),
    (re.compile(r"\bsensor\b", re.IGNORECASE), "Sensor"),
    (re.compile(r"\bups\b", re.IGNORECASE), "UPS"),
    (re.compile(r"\bserver\b", re.IGNORECASE), "Server"),
    (re.compile(r"\bworkstation\b|\bdesktop\b", re.IGNORECASE), "Workstation"),
    (re.compile(r"\bprinter\b", re.IGNORECASE), "Printer"),
]

_OS_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bWindows(?: NT)?\s*([0-9.]+)?", re.IGNORECASE), "Windows"),
    (re.compile(r"\bUbuntu\s*([0-9.]+)?", re.IGNORECASE), "Ubuntu"),
    (re.compile(r"\bDebian\s*([0-9.]+)?", re.IGNORECASE), "Debian"),
    (re.compile(r"\bCentOS\s*([0-9.]+)?", re.IGNORECASE), "CentOS"),
    (re.compile(r"\bRed Hat(?: Enterprise Linux)?\s*([0-9.]+)?", re.IGNORECASE), "Red Hat"),
    (re.compile(r"\bLinux\b(?:[^0-9]*([0-9.]+))?", re.IGNORECASE), "Linux"),
    (re.compile(r"\bmacOS\s*([0-9.]+)?", re.IGNORECASE), "macOS"),
    (re.compile(r"\bDarwin\s*([0-9.]+)?", re.IGNORECASE), "macOS"),
    (re.compile(r"\bAndroid\s*([0-9.]+)?", re.IGNORECASE), "Android"),
    (re.compile(r"\biOS\s*([0-9.]+)?", re.IGNORECASE), "iOS"),
    (re.compile(r"\bVxWorks\b\s*([0-9.]+)?", re.IGNORECASE), "VxWorks"),
    (re.compile(r"\bQNX\b\s*([0-9.]+)?", re.IGNORECASE), "QNX"),
    (re.compile(r"\bFreeRTOS\b\s*([0-9.]+)?", re.IGNORECASE), "FreeRTOS"),
    (re.compile(r"\bThreadX\b\s*([0-9.]+)?", re.IGNORECASE), "ThreadX"),
    (re.compile(r"\bINTEGRITY\b\s*([0-9.]+)?", re.IGNORECASE), "INTEGRITY"),
    (re.compile(r"\beCos\b\s*([0-9.]+)?", re.IGNORECASE), "eCos"),
]

_VERSION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(?:firmware|fw)\b[:= ]+v?([A-Za-z0-9._-]{1,32})"), "firmware"),
    (re.compile(r"(?i)\b(?:software|sw)\b[:= ]+v?([A-Za-z0-9._-]{1,32})"), "software"),
    (re.compile(r"(?i)\b(?:os|operating system)\b[:= ]+v?([A-Za-z0-9._-]{1,32})"), "os"),
    (re.compile(r"(?i)\b(?:version|ver|rev|revision|build)\b[:= ]+v?([A-Za-z0-9._-]{1,32})"), "version"),
]

_MODEL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bmodel(?:\s*no\.|number)?\s*[:= ]+([A-Za-z0-9][A-Za-z0-9 _./\\-]{1,48})"), "model"),
    (re.compile(r"(?i)\bproduct(?:\s*name|code)?\s*[:= ]+([A-Za-z0-9][A-Za-z0-9 _./\\-]{1,48})"), "product"),
    (re.compile(r"(?i)\bdevice\s*[:= ]+([A-Za-z0-9][A-Za-z0-9 _./\\-]{1,48})"), "model"),
    (re.compile(r"(?i)\border\s*code\s*[:= ]+([A-Za-z0-9][A-Za-z0-9 _./\\-]{1,48})"), "order_code"),
    (re.compile(r"(?i)\bcatalog(?:\s*no\.|#)?\s*[:= ]+([A-Za-z0-9][A-Za-z0-9 _./\\-]{1,48})"), "catalog"),
]

_SOFTWARE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bOpenSSH[_/-]?([0-9A-Za-z.p]+)", re.IGNORECASE), "OpenSSH"),
    (re.compile(r"\bDropbear[_/-]?([0-9A-Za-z.p]+)", re.IGNORECASE), "Dropbear"),
    (re.compile(r"\bApache/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "Apache"),
    (re.compile(r"\bnginx/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "nginx"),
    (re.compile(r"Microsoft-IIS/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "Microsoft IIS"),
    (re.compile(r"\bLighttpd/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "Lighttpd"),
    (re.compile(r"\bBoa/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "Boa"),
    (re.compile(r"\bGoAhead/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "GoAhead"),
    (re.compile(r"\bMongoose/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "Mongoose"),
    (re.compile(r"\bBusyBox/?([0-9A-Za-z.p]+)?", re.IGNORECASE), "BusyBox"),
    (re.compile(r"\bCODESYS\b(?:\s*V?([0-9A-Za-z.p]+))?", re.IGNORECASE), "CODESYS"),
    (re.compile(r"\bNiagara\b", re.IGNORECASE), "Niagara"),
    (re.compile(r"\bIgnition\b(?:\s*([0-9A-Za-z.p]+))?", re.IGNORECASE), "Ignition"),
    (re.compile(r"\bWinCC\b", re.IGNORECASE), "Siemens WinCC"),
    (re.compile(r"\bFactoryTalk\b", re.IGNORECASE), "FactoryTalk"),
    (re.compile(r"\bSIMATIC\b", re.IGNORECASE), "SIMATIC"),
]


def _clean_value(value: str) -> str:
    return " ".join(str(value).strip().split())


def _truncate(value: str, limit: int = 80) -> str:
    value = _clean_value(value)
    if len(value) <= limit:
        return value
    return value[:limit].rstrip() + "..."


def extract_device_fields(text: str) -> dict[str, str]:
    if not text:
        return {}
    cleaned = _clean_value(text)
    if len(cleaned) < 4:
        return {}
    if not _DEVICE_HINT_RE.search(cleaned):
        return {}

    fields: dict[str, str] = {}

    for pattern, vendor in _VENDOR_PATTERNS:
        if pattern.search(cleaned):
            fields["vendor"] = vendor
            break

    for pattern, dtype in _DEVICE_TYPE_PATTERNS:
        if pattern.search(cleaned):
            fields["device_type"] = dtype
            break

    for pattern, os_name in _OS_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            version = match.group(1) if match.lastindex else None
            os_value = f"{os_name} {version}".strip() if version else os_name
            fields["os"] = os_value
            break

    if "os" not in fields and "vendor" in fields:
        vendor = fields["vendor"].lower()
        if vendor == "microsoft":
            fields["os"] = "Windows"
        elif vendor == "apple":
            fields["os"] = "macOS"

    for pattern, key in _VERSION_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            value = match.group(1)
            if value and value.lower().startswith(("http/", "ssh-")):
                continue
            fields.setdefault(key, value)

    for pattern, key in _MODEL_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            value = match.group(1).strip()
            if value and len(value) > 1:
                fields.setdefault(key, value)
                break

    for pattern, software in _SOFTWARE_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            version = match.group(1) if match.lastindex else None
            sw_value = f"{software} {version}".strip() if version else software
            fields.setdefault("software", sw_value)
            break

    return fields


def format_device_detail(fields: dict[str, object], source: str | None = None) -> str | None:
    if not fields:
        return None

    ordered_keys = [
        ("vendor", "vendor"),
        ("model", "model"),
        ("product", "product"),
        ("device_type", "type"),
        ("os", "os"),
        ("firmware", "firmware"),
        ("software", "software"),
        ("version", "version"),
        ("revision", "revision"),
        ("serial", "serial"),
        ("id", "id"),
    ]
    parts: list[str] = []
    if source:
        parts.append(f"source={_truncate(source, 48)}")
    seen_values: set[str] = set()
    for key, label in ordered_keys:
        value = fields.get(key)
        if value is None:
            continue
        value_text = _truncate(str(value))
        if not value_text:
            continue
        if value_text in seen_values:
            continue
        seen_values.add(value_text)
        parts.append(f"{label}={value_text}")
    if not parts:
        return None
    return " ".join(parts)


def device_fingerprints_from_text(text: str, source: str | None = None) -> list[str]:
    fields = extract_device_fields(text)
    detail = format_device_detail(fields, source=source)
    return [detail] if detail else []


def device_fingerprint_from_fields(fields: dict[str, object], source: str | None = None) -> str | None:
    return format_device_detail(fields, source=source)


def append_device_fingerprints(counter, fingerprints: Iterable[str]) -> None:
    for detail in fingerprints:
        if not detail:
            continue
        counter[detail] += 1
