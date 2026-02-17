# Changelog

All notable changes to pcapper will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

## Unreleased
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
- Added IOC export (JSON/CSV/STIX) and CLI options for output control.
- Documented IOC enrichment configuration and cache/rate-limit controls.
- Added TCP stream reassembly for HTTP parsing and HTTP/2 preface detection.
- Added passive JARM fingerprints in TLS analysis and QUIC detection in UDP.
- Added credential hunting module for HTTP auth, NTLM/Kerberos artifacts, and SMB sessions.
- Added file triage with YARA scanning, MIME/PE/ELF metadata, hash clustering, and expanded carving.
- Added timeline filters (IP/port/domain/user) and JSON export for SIEM ingestion.

### Fixed
- Added caching/rate limiting for IP intel lookups.

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
