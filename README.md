# Pcapper

Modular, analyst-first PCAP triage and reporting. Pcapper turns raw captures into concise, readable intelligence with opt‑in deep dives when you need them.

<p align="left">
	<img alt="Python" src="https://img.shields.io/badge/Python-3.9%2B-blue" />
	<img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
	<img alt="Version" src="https://img.shields.io/badge/Version-0.6.5-orange" />
</p>

> ⚡ Fast triage. 🔍 Focused analysis. 🧠 Actionable reporting.

---

## Why Pcapper
- **Triage in seconds**: protocol presence, timelines, and key stats at a glance.
- **Deep‑dive modules**: DNS, HTTP, SMB, NTLM, TLS, files, beacons, exfil, and more.
- **Readable reports**: clean output optimized for IR workflows and handoffs.
- **Extensible architecture**: add new analyzers without touching the core.

---

## Highlights
- Accepts single PCAP/PCAPNG files or folders of captures (recursive).
- Summarizes packets, timestamps, duration, size, interface details.
- Detects beaconing/exfil patterns and surfaces suspicious strings.
- Extracts file artifacts and flags type/extension mismatches.
- TLS summaries with certificate and handshake insights.

---

## Quick Start

### Install

```bash
pip install -r requirements.txt
```

For local development:

```bash
pip install -e .
```

### Run

```bash
python -m pcapper /path/to/capture.pcap
python -m pcapper /path/to/folder --recursive
pcapper /path/to/capture.pcapng --limit-protocols 20
```

---

## Modules (opt‑in)

Enable analysis modules with flags to keep output focused.

```bash
pcapper /path/to/capture.pcap --dns --http --tls --files
pcapper /path/to/capture.pcap --smb --ntlm --ips --beacon
pcapper /path/to/capture.pcap --timeline --strings --services
```

Common flags:
- `--dns`, `--http`, `--icmp`, `--tls`, `--smb`, `--ntlm`, `--ldap`
- `--files`, `--strings`, `--services`, `--protocols`
- `--ips`, `--beacon`, `--exfil`, `--timeline`

---

## Visuals

### Example Summary (trimmed)

```
PCAPPER v0.6.5  ::  Compile Date 2026-02-04

Capture Summary
	Packets: 182,419
	Duration: 00:18:42
	Interfaces: 1
	Size: 214.3 MB

Top Protocols
	TCP: 64.2%  UDP: 30.4%  ICMP: 0.8%

Threat Signals
	• Beaconing candidates: 3
	• Possible exfil bursts: 2
	• Cleartext credentials: 1
```

### Analyst‑Friendly Flow

```
[Capture] -> [Summary] -> [Signals] -> [Modules] -> [Artifacts] -> [Report]
```

---

## Configuration

### GeoIP Enrichment (optional)
Provide MaxMind databases via environment variables:

```bash
export PCAPPER_GEOIP_CITY_DB=/path/to/GeoLite2-City.mmdb
export PCAPPER_GEOIP_ASN_DB=/path/to/GeoLite2-ASN.mmdb
```

---

## Output Philosophy
Pcapper reports are designed to be:
- **Concise**: minimal noise, maximal signal.
- **Actionable**: highlights first, details later.
- **Shareable**: readable by analysts, not just developers.

---

## Contributing
Issues and pull requests are welcome. Please keep modules focused, outputs consistent, and performance top‑of‑mind.

---

## License
MIT
