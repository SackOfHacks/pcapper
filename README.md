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

## Full CLI Help (-h)

Below is the full help output and a plain‑English explanation of each option.

```
usage: pcapper [-h] [-r] [-l LIMIT_PROTOCOLS] [--vlan] [-v] [--icmp] [--dns]
							 [--http] [--tls] [--tcp] [--udp] [--exfil] [--sizes] [--ips]
							 [--beacon] [--threats] [--files] [--protocols] [--services]
							 [--smb] [--nfs] [--strings] [--certificates] [--timeline]
							 [--domain] [--ldap] [--kerberos] [-ip TIMELINE_IP] [--health]
							 [--ntlm] [--netbios] [--modbus] [--dnp3]
							 [--extract FILENAME] [--view FILENAME] [--no-status]
							 [--no-color] [-summarize]
							 target

positional arguments:
	target                Path to a pcap/pcapng file or directory of captures.

options:
	-h, --help            show this help message and exit
	-r, --recursive       Recursively search for pcaps when target is a directory.
	-l, --limit-protocols Number of protocols to show in the summary.
	--vlan                Include VLAN analysis in the output.
	-v, --verbose         Show verbose details in analysis output.
	--icmp                Include ICMP analysis in the output.
	--dns                 Include DNS analysis in the output.
	--http                Include HTTP analysis in the output.
	--tls                 Include TLS/HTTPS analysis in the output.
	--tcp                 Include TCP analysis in the output.
	--udp                 Include UDP analysis in the output.
	--exfil               Include exfiltration heuristics and anomaly analysis.
	--sizes               Include packet size distribution analysis.
	--ips                 Include IP address intelligence and conversation analysis.
	--beacon              Include beaconing analysis in the output.
	--threats             Include consolidated threat detections in the output.
	--files               Include file transfer discovery in the output.
	--protocols           Include detailed protocol hierarchy and anomaly analysis.
	--services            Include service discovery and cybersecurity risk analysis.
	--smb                 Include SMB protocol analysis (Versioning, Shares, Anomalies).
	--nfs                 Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies).
	--strings             Include cleartext strings extraction and anomaly analysis.
	--certificates        Include TLS certificate extraction and analysis.
	--timeline            Include a threat-hunting timeline for a specific IP (use with -ip).
	--domain              Include MS AD and domain analysis (services, users, DCs, artifacts).
	--ldap                Include LDAP analysis (queries, users, servers, anomalies, secrets).
	--kerberos            Include Kerberos analysis (requests, errors, principals, attacks).
	-ip TIMELINE_IP       Target IP for timeline analysis (use with --timeline).
	--health              Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs).
	--ntlm                Include NTLM authentication analysis (Users, Domains, Versions).
	--netbios             Include NetBIOS name service analysis (Names, Groups, Roles).
	--modbus              Include Modbus/TCP status and security analysis (Functions, Units, Anomalies).
	--dnp3                Include DNP3 protocol analysis (Functions, Restarts, File Ops).
	--extract FILENAME    Extract a discovered file by name into ./files (use with --files).
	--view FILENAME       View extracted file content in ASCII/HEX (use with --files).
	--no-status           Disable the processing status bar.
	--no-color            Disable ANSI color output.
	-summarize, --summarize
												Summarize supported analysis across all pcaps (e.g., --modbus, --dnp3).
```

### Option explanations
- `target`: The capture file or directory to analyze. Directories can be scanned recursively with `--recursive`.
- `--recursive`: Find pcaps beneath a folder tree.
- `--limit-protocols`: Limits the number of protocols shown in the high‑level summary.
- `--vlan`: Adds VLAN breakdowns and rollups.
- `--verbose`: Expands module output with additional detail.
- `--icmp`: ICMP message and anomaly analysis.
- `--dns`: DNS queries, responses, and suspicious patterns.
- `--http`: HTTP request/response summaries and anomalies.
- `--tls`: TLS/HTTPS handshake and metadata summaries.
- `--tcp`: TCP session insights, retransmissions, and flow summaries.
- `--udp`: UDP flow summaries and statistics.
- `--exfil`: Detects potential data exfiltration bursts or suspicious transfers.
- `--sizes`: Packet size distribution and outlier patterns.
- `--ips`: IP intelligence, conversations, and endpoint profiles (GeoIP optional).
- `--beacon`: Beaconing heuristics for periodic traffic.
- `--threats`: Consolidated high‑signal threat detections from multiple modules.
- `--files`: File transfer discovery across common protocols.
- `--protocols`: Protocol hierarchy, anomalies, and unusual mixes.
- `--services`: Service discovery and risk context based on ports and behavior.
- `--smb`: SMB versioning, shares, and anomalies.
- `--nfs`: NFS/RPC activity, clients, servers, and anomalies.
- `--strings`: Cleartext strings and credential‑like artifact detection.
- `--certificates`: TLS certificate extraction and analysis.
- `--timeline`: Per‑IP timeline for threat hunting (use with `-ip`).
- `--domain`: MS AD domain insights and service/user artifacts.
- `--ldap`: LDAP operations, users, servers, and anomalies.
- `--kerberos`: Kerberos requests, errors, principals, and attack hints.
- `-ip`: Target IP for timeline analysis.
- `--health`: Traffic health assessment across retransmissions, TTL/QoS, SNMP, and certs.
- `--ntlm`: NTLM authentication summaries.
- `--netbios`: NetBIOS name service analysis.
- `--modbus`: Modbus/TCP function codes and security anomalies.
- `--dnp3`: DNP3 function usage and control‑plane insights.
- `--extract`: Extract a discovered file by name into ./files (requires `--files`).
- `--view`: View extracted file content in ASCII/HEX (requires `--files`).
- `--no-status`: Disable the progress status bar for scripting or logs.
- `--no-color`: Disable ANSI colors for plain text output.
- `--summarize`: Roll up module summaries across multiple pcaps.

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
