# Changelog

All notable changes to pcapper will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## 1.3.0 — 2026-02-19
### Added
- Device fingerprinting across IT/OT/IoT traffic (vendor/model/OS/firmware/software) with rollups integrated into host, service, and OT reporting.
- Deeper OT protocol decoding including DNP3 object/variation parsing with expanded size tables and transport reassembly, IEC 61850 GOOSE/SV dataset value decoding with sequence-state tracking, OPC UA ResponseHeader plus common service request/response decoding, BACnet APDU services, CoAP option/URI parsing with Observe tracking, MQTT topic parsing, CIP/ENIP class/attribute/service decoding, and LLDP/PROFINET DCP block parsing.
- OT risk posture scoring and attack-storyline summaries in timeline output.
- New routing protocol analysis (`--routing`) for OSPF/BGP/RIP/EIGRP/VRRP/HSRP with sessions, auth exposure, and routing-health detections.
- OSPF LSA parsing (types, IDs, advertising routers, MaxAge/sequence alerts) for deeper routing forensics.
- BGP UPDATE parsing with NLRI/withdraw decoding, next-hop/origin/AS-path artifacts, and prefix-level rollups.
- IS-IS TLV/LSP parsing with system IDs, areas, hostnames, reachability, and authentication insights.
- PIM parsing (Hello + Join/Prune) with group/source tracking and DR/holdtime insights.

### Changed
- Timeline output now shows all events by default (independent of `-v`), includes TCP SYN/SYN-ACK connection events, and supports category filtering with an on-demand category list.
- Reporting summaries expanded with richer OT command visibility, protocol artifacts, and device fingerprint context.

## 1.2.8 — 2026-02-18
### Added
- New analyzers: QUIC (`--quic`), HTTP/2 (`--http2`), encrypted DNS (`--encrypted-dns`), NTP (`--ntp`), VPN/tunnel detection (`--vpn`), OPC Classic (`--opc-classic`), IEC 61850 GOOSE/SV (`--goose`, `--sv`), LLDP/Profinet DCP (`--lldp`), PTP (`--ptp`), IEC 101/103 heuristic (`--iec101-103`), OT command normalization (`--ot-commands`), IOC matching (`--ioc`), CTF flag finder (`--ctf`), pcap metadata (`--pcapmeta`), and TCP stream analysis (`--streams`).
- Stream tooling: `--follow`, `--follow-id`, `--lookup-stream-id`, and `--streams-full`.
- Export options: `--json`, `--csv`, and `--sqlite` outputs, plus case packaging via `--case-dir`/`--case-name`.
- Packet slicing controls: `--bpf`, `--time-start`, and `--time-end`.

### Changed
- Summarize mode now renders merged summaries per module (no per‑pcap sections).
- Help menu ordering is now enforced alphabetically in IT and OT/ICS groups.
- Section headers now use reversed color styling for main headers.
- Public IP highlighting now applies across all reporting sections.

### Fixed
- Disabled argparse abbreviations so unknown flags error clearly, with “Did you mean …” hints.
- Stream reassembly now uses TCP sequence ordering with gap tracking.

## 1.2.2 — 2026-02-18
### Added
- Wildcard target resolution support for quoted glob patterns and mixed target inputs.
- Multiple positional target support (e.g., shell-expanded wildcards like `Un*` resolving to many files).
- Merged summarize rendering for timeline analysis (`--summarize --timeline -ip ...`).
- Parser regression tests for grouped-help completeness, alphabetical IT/ICS flag ordering, and multi-target parsing.
- New `--dhcp` analyzer with DHCP conversations/sessions, lease/option intelligence, client/server endpoint detail, artifacts, and attack/threat-hunting detections (starvation, rogue DHCP, NAK floods, probing, beaconing, exfil-style option abuse).
- Beaconing enhancements: severity tiers, fan-out detection, low-and-slow cadence detection, high-frequency check-in detection, and candidate evidence payloads.
- Exfiltration enhancements: per-source DNS tunneling heuristics (entropy + max label), uncommon high-volume outbound channel detection, aggregated HTTP POST channel detection, and richer exfil evidence.
- New smoke coverage for beacon fan-out and exfil per-source DNS/uncommon-port detections.
- New remote-access analyzers for `--rdp`, `--telnet`, `--vnc`, `--teamviewer`, and `--winrm` with host details, artifacts, and threat-hunting heuristics.
- Expanded `--ssh` analysis with MAC visibility, auth outcomes, beaconing, and exfil heuristics.

### Changed
- CLI help menu organization now enforces complete alphabetical ordering inside IT and OT/ICS groups.
- README refreshed to reflect current CLI behavior, wildcard/multi-target usage, summarize semantics, and full grouped flag inventory.
- IT grouped help inventory now includes `--dhcp`, with ordering/completeness checks aligned to the live parser definitions.
- Dependency ordering normalized in `requirements.txt` and `pyproject.toml`.
- Threat, beacon, and exfil reporting now render richer evidence lines directly under detections for faster triage.
- README now includes a direct `--help` verification command and explicit IT/ICS function counts.
- `requirements.txt` now explicitly marks runtime dependencies as alphabetically ordered.
- Summarize mode now renders full module sections for `--health`, `--rdp`, `--telnet`, `--vnc`, `--teamviewer`, and `--winrm`.
- CLI help description refreshed for IT + OT/ICS framing.
- README now highlights OT/ICS command-center positioning and includes `--ftp` in the IT flag inventory.
- `requirements.txt` now notes synchronization with `pyproject.toml`.

### Fixed
- `argparse` failure when shell-expanded wildcard input produced multiple targets (`unrecognized arguments ...`).
- Timeline summarize output path now renders full merged timeline report instead of generic rollup-only output.
- OT false positives in `--threats` were reduced by strict protocol signature gating (CIP/EtherNet-IP/DNP3), confidence checks, and anomaly deduping.

## 1.2.0 — 2026-02-13
### Changed
- Version bump and release metadata alignment.

### Fixed
- Reader handling and progress robustness improvements for large streamed captures.

## 0.6.5 — 2026-02-04
### Changed
- Version bump and release prep updates.

### Fixed
- Packaging metadata consistency checks.

## 0.6.0 — 2026-02-04
### Added
- File artifact extraction summaries with type heuristics and mismatch checks.
- Threat-hunting helpers for beaconing, exfiltration, and timeline-focused views.

### Changed
- Reporting layout and section ordering for faster triage.
- Protocol summaries tuned for readability and consistency across modules.

### Fixed
- Edge-case parsing issues in file reconstruction and HTTP body handling.
- Defensive guards for malformed packets and partial streams.

## 0.5.6 — 2026-02-02
### Changed
- Progress and health reporting tweaks for large capture sets.
- Cache usage tuned to reduce repeated parsing work.

### Fixed
- Minor output inconsistencies across protocol modules.
- Stability improvements around optional dependency loading.

## 0.5.0 — 2026-01-30
### Added
- TLS and certificate inspection summaries.
- Beaconing and data exfiltration detection modules.
- Timeline and strings views for fast pivoting.
- File transfer analysis across common protocols.

### Changed
- CLI output polish and richer high-level summaries.
- Analyzer orchestration to improve overall runtime on large PCAPs.

## 0.4.0 — 2026-01-24
### Added
- LDAP analysis module with conversations, queries, users, systems, secrets, and anomalies.
- Enhanced domain analysis with discovered domains, credentials, and service naming.

### Changed
- Reporting improvements across LDAP/Domain summaries for threat-hunting context.

## 0.3.0 — 2026-01-24
### Added
- Clearer public-facing documentation and guidance to help new users get started.
- Expanded reporting and output polish for a smoother CLI experience.

### Changed
- Refined analysis output for readability and consistency.
- Internal cleanup to improve maintainability without altering core behavior.

## 0.2.1 — 2024-11-10
### Fixed
- Minor stability fixes for edge-case PCAPs.
- Small output tweaks for better consistency.

## 0.2.0 — 2024-10-02
### Added
- Modular protocol analyzers for common network services.
- Report generation enhancements for easier sharing.

## 0.1.0 — 2024-08-18
### Added
- Initial public release with core CLI, parsing, and analysis features.
