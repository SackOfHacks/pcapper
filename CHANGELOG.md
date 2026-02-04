# Changelog

All notable changes to pcapper will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

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
