# Pcapper

Modular, analyst-first PCAP triage and reporting. Pcapper turns raw captures into concise, readable intelligence with opt‑in deep dives when you need them.

<p align="left">
	<img alt="Python" src="https://img.shields.io/badge/Python-3.9%2B-blue" />
	<img alt="License" src="https://img.shields.io/badge/License-MIT-green" />
	<img alt="Version" src="https://img.shields.io/badge/Version-1.0.0-orange" />
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
- IOC extraction with JSON/CSV/STIX export support.
- Email protocol analysis for SMTP/POP/IMAP/LMTP/ManageSieve.
- Performance controls: streaming, multiprocessing, index cache.

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
- `--dns`, `--http`, `--icmp`, `--tls`, `--smb`, `--ntlm`, `--ldap`, `--creds`
- `--email`, `--ioc`, `--files`, `--strings`, `--services`, `--protocols`
- `--ips`, `--beacon`, `--exfil`, `--timeline`

---

## Full CLI Help (-h)

Below is the full help output and a plain‑English explanation of each option.

```
usage: pcapper [-h] [-l LIMIT_PROTOCOLS] [-r] [--stream] [--mp]
		   [--mp-workers MP_WORKERS] [--index-cache] [--index-refresh]
		   [-summarize] [--beacon] [--certificates] [--creds] [--dns]
		   [--dnp3] [--domain] [--email] [--exfil] [--files] [--health]
		   [--http] [--icmp] [--ioc] [--ips] [--kerberos] [--ldap]
		   [--modbus] [--netbios] [--nfs] [--ntlm] [--protocols]
		   [--services] [--sizes] [--smb] [--strings] [--tcp] [--threats]
		   [--timeline] [--tls] [--udp] [--vlan] [-ip TIMELINE_IP]
		   [--timeline-filter-ip TIMELINE_FILTER_IP]
		   [--timeline-filter-port TIMELINE_FILTER_PORT]
		   [--timeline-filter-domain TIMELINE_FILTER_DOMAIN]
		   [--timeline-filter-user TIMELINE_FILTER_USER] [--timeline-json]
		   [--timeline-out PATH] [--extract FILENAME] [--view FILENAME]
		   [--output {txt,md,json}] [--profile PATH] [--baseline PATH]
		   [--compare PCAP] [--no-color] [--no-status] [-v]
		   [--ioc-export {json,csv,stix}] [--ioc-out PATH]
		   target

positional arguments:
	target                Path to a pcap/pcapng file or directory of captures.

options:
	-h, --help            show this help message and exit
	--index-cache         Build/use a PCAP index cache for faster repeated runs.
	--index-refresh       Rebuild the PCAP index cache even if one exists.
	-l, --limit-protocols Number of protocols to show in the summary.
	--mp                  Run analysis modules in parallel processes.
	--mp-workers          Number of worker processes for --mp (default: CPU count).
	-r, --recursive       Recursively search for pcaps when target is a directory.
	--stream              Stream modules from disk (disable in-memory packet cache).
	-summarize, --summarize
						Summarize supported analysis across all pcaps (e.g., --modbus, --dnp3).
	--beacon              Include beaconing analysis in the output.
	--certificates        Include TLS certificate extraction and analysis.
	--creds               Include credential hunting across HTTP, SMB, NTLM, and Kerberos.
	--dns                 Include DNS analysis in the output.
	--dnp3                Include DNP3 protocol analysis (Functions, Restarts, File Ops).
	--domain              Include MS AD and domain analysis (services, users, DCs, artifacts).
	--email               Include email protocol analysis (SMTP/POP/IMAP/LMTP/ManageSieve).
	--exfil               Include exfiltration heuristics and anomaly analysis.
	--files               Include file transfer discovery in the output.
	--health              Include overall traffic health assessment (retransmissions, TTL, QoS, SNMP, certs).
	--http                Include HTTP analysis in the output.
	--icmp                Include ICMP analysis in the output.
	--ioc                 Extract and display indicators of compromise (IOCs).
	--ips                 Include IP address intelligence and conversation analysis.
	--kerberos            Include Kerberos analysis (requests, errors, principals, attacks).
	--ldap                Include LDAP analysis (queries, users, servers, anomalies, secrets).
	--modbus              Include Modbus/TCP status and security analysis (Functions, Units, Anomalies).
	--netbios             Include NetBIOS name service analysis (Names, Groups, Roles).
	--nfs                 Include NFS protocol analysis (RPC, Clients, Servers, Files, Anomalies).
	--ntlm                Include NTLM authentication analysis (Users, Domains, Versions).
	--protocols           Include detailed protocol hierarchy and anomaly analysis.
	--services            Include service discovery and cybersecurity risk analysis.
	--sizes               Include packet size distribution analysis.
	--smb                 Include SMB protocol analysis (Versioning, Shares, Anomalies).
	--strings             Include cleartext strings extraction and anomaly analysis.
	--tcp                 Include TCP analysis in the output.
	--threats             Include consolidated threat detections in the output.
	--timeline            Include a threat-hunting timeline for a specific IP (use with -ip).
	--tls                 Include TLS/HTTPS analysis in the output.
	--udp                 Include UDP analysis in the output.
	--vlan                Include VLAN analysis in the output.
	-ip TIMELINE_IP       Target IP for timeline analysis (use with --timeline).
	--timeline-filter-ip  Filter timeline events by IP (src/dst).
	--timeline-filter-port
			Filter timeline events by port.
	--timeline-filter-domain
			Filter timeline events by domain/host.
	--timeline-filter-user
			Filter timeline events by user/principal.
	--timeline-json       Output timeline events as JSON for ingestion.
	--timeline-out PATH   Write timeline JSON to file (defaults to stdout).
	--extract FILENAME    Extract a discovered file by name into ./files (use with --files).
	--view FILENAME       View extracted file content in ASCII/HEX (use with --files).
	--output {txt,md,json}
			Output format for reports (default: txt).
	--profile PATH        Write a JSON profile snapshot for the capture.
	--baseline PATH       Compare current run against a saved profile JSON.
	--compare PCAP        Compare current capture against another PCAP/PCAPNG.
	--no-color            Disable ANSI color output.
	--no-status           Disable the processing status bar.
	-v, --verbose         Show verbose details in analysis output.
	--ioc-export {json,csv,stix}
						Export collected IOCs in the selected format.
	--ioc-out PATH        Write IOC export to a file (defaults to stdout).
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
- `--creds`: Credential hunting across HTTP, SMB, NTLM, and Kerberos.
- `--timeline`: Per‑IP timeline for threat hunting (use with `-ip`).
- `--timeline-filter-ip`: Filter timeline by source/destination IP.
- `--timeline-filter-port`: Filter timeline by port.
- `--timeline-filter-domain`: Filter timeline by domain/host.
- `--timeline-filter-user`: Filter timeline by user/principal.
- `--timeline-json`: Emit timeline as JSON for Splunk/ELK ingestion.
- `--timeline-out`: Write timeline JSON to file (defaults to stdout).
- `--domain`: MS AD domain insights and service/user artifacts.
- `--ldap`: LDAP operations, users, servers, and anomalies.
- `--kerberos`: Kerberos requests, errors, principals, and attack hints.
- `-ip`: Target IP for timeline analysis.
- `--health`: Traffic health assessment across retransmissions, TTL/QoS, SNMP, and certs.
- `--ntlm`: NTLM authentication summaries.
- `--netbios`: NetBIOS name service analysis.
- `--modbus`: Modbus/TCP function codes and security anomalies.
- `--dnp3`: DNP3 function usage and control‑plane insights.
- `--email`: Email protocol analysis (SMTP/POP/IMAP/LMTP/ManageSieve).
- `--ioc`: Extract and display indicators of compromise.
- `--extract`: Extract a discovered file by name into ./files (requires `--files`).
- `--view`: View extracted file content in ASCII/HEX (requires `--files`).
- `--output`: Output format (txt, md, json).
- `--profile`: Write a JSON profile snapshot for the capture.
- `--baseline`: Compare current run against a saved profile JSON.
- `--compare`: Compare current capture against another PCAP/PCAPNG.
- `--stream`: Stream modules from disk (disable in-memory cache).
- `--mp`: Run modules in parallel processes.
- `--mp-workers`: Number of worker processes for `--mp`.
- `--index-cache`: Build/use a PCAP index cache.
- `--index-refresh`: Rebuild the index cache even if one exists.
- `--no-status`: Disable the progress status bar for scripting or logs.
- `--no-color`: Disable ANSI colors for plain text output.
- `--summarize`: Roll up module summaries across multiple pcaps.
- `--ioc-export`: Export IOCs to JSON, CSV, or STIX.
- `--ioc-out`: Write IOC export to a file (defaults to stdout).

---

## Visuals

### Example Summary (trimmed)

```
PCAPPER v1.0.0  ::  Compile Date 2026-02-04

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

### IOC Enrichment (optional)
Enable opt‑in lookups and provide API keys:

```bash
export PCAPPER_INTEL_OPT_IN=1
export PCAPPER_ABUSEIPDB_KEY=your_key
export PCAPPER_OTX_KEY=your_key
export PCAPPER_VT_KEY=your_key
```

Cache and rate‑limit controls:

```bash
export PCAPPER_IP_INTEL_CACHE_TTL=86400
export PCAPPER_IP_INTEL_RATE_LIMIT=1.0
export PCAPPER_INTEL_CACHE=~/.pcapper/ip_intel_cache.json
```

### File Triage (optional)
Enable YARA scanning by pointing to a rule file or directory:

```bash
export PCAPPER_YARA_RULES=/path/to/rules
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
