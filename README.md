# Pcapper

![CI](https://github.com/SackOfHacks/pcapper/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-0B7285)
![License](https://img.shields.io/badge/license-MIT-6C757D)
![OT/ICS](https://img.shields.io/badge/ot%2Fics-ready-3D5A80)

```text
  ____
 |  _ \  ___ __ _ _ __  _ __   ___ _ __
 | |_) |/ __/ _` | '_ \| '_ \ / _ \ '__|
 |  __/| (_| (_| | |_) | |_) |  __/ |
 |_|    \___\__,_| .__/| .__/ \___|_|
                 |_|   |_|
  PCAP triage for IT + OT/ICS, fast enough for the plant floor
```

**Pcapper** is a PCAP/PCAPNG forensics and threat-hunting CLI for enterprise IT and OT/ICS networks. It reads a capture once and runs any of 120+ analyses over it -- from a one-command overview to deep dives into Modbus, DNP3, IEC-104, S7, CIP and dozens of other protocols. Every report leads with a severity headline and its findings, and every finding carries its evidence, its ATT&CK technique and the next command to run.

Built for SOC analysts, incident responders and OT defenders who need fast answers they can defend.

## Why you can put its output in a report

A PCAP tool is only useful if what it prints is *true*. Every analysis holds to these rules, each pinned by a regression test on a synthetic capture:

| Rule | What it means in the report |
| --- | --- |
| **Roles come from the service port, not packet direction** | A server's replies never make it a "client"; a client's ephemeral port is never a "top port". |
| **Windows are per protocol** | A one-minute Kerberos exchange in an eight-hour capture reports a one-minute window, and every rate derived from it is right. |
| **Padding is not payload** | Segment lengths come from the IP/TCP headers, so a padded pure ACK is zero bytes of data. |
| **Same capture, same report** | Every sort has a total order: the same command prints byte-identical output on every run and machine. |
| **Several captures, one story** | `-summarize` lists what the captures share once, counts distinct hosts and flows over all of them, and does not depend on the order they are named in. |

And nothing internal leaves the box: reputation lookups (`-vt`, `--ip-geo`) run only when you ask and configure them, only ever see public hostnames and routable addresses, and a config file planted in the evidence directory is never loaded.

## Install

```bash
git clone https://github.com/SackOfHacks/pcapper.git
cd pcapper
pip install .            # or: pipx install .
pcapper capture.pcap --overview
```

Python 3.9 or newer. Optional external tools: `tshark` for `--decrypt`, `suricata` for `--suricata`, and Npcap (Windows) or libpcap for `--bpf` filtering.

## Quickstart

```bash
pcapper capture.pcap --overview                        # what is in this capture, and what to look at first
pcapper capture.pcap --threats --ips --health          # fast risk triage
pcapper capture.pcap --timeline -ip 10.0.0.5           # one host's story
pcapper capture.pcap --mitre --suricata                # ATT&CK mapping and IDS corroboration
pcapper capture.pcap --modbus --dnp3 --iec104 --s7 --ot-commands --safety   # OT/ICS deep dive
pcapper -summarize day1.pcap day2.pcap day3.pcap --overview                 # several captures as one
pcapper capture.pcap --threats --json out/results.json --sqlite out/results.db --case-dir case-001
```

Add `-v` to any report for every row, exact timestamps and the evidence behind each finding.

## Which flag should I use?

| If you want to... | Start with |
| --- | --- |
| See what is in a capture and what to look at first | `--overview` |
| Get immediate risk triage | `--threats --ips --health` |
| Hunt C2 or beaconing behavior | `--beacon --dns --tls --quic` |
| Hunt proxy/tunnel evasion (VPN, SOCKS) | `--vpn --socks` |
| Map findings to ATT&CK | `--mitre` |
| Corroborate with IDS alerts | `--suricata` |
| Investigate data theft and transferred artifacts | `--exfil --files --ftp --http --aim --email` |
| Investigate identity abuse | `--kerberos --ldap --ntlm --domain --creds` |
| Track lateral movement | `--hostnames --services --protocols --tcp --timeline -ip <host>` |
| Investigate phone calls (VoIP) | `--voip` (add `--voip-out DIR` to recover call audio) |
| Run OT/ICS-specific triage | `--modbus --dnp3 --iec104 --s7 --ot-commands --safety` |
| Find OT protocols on moved ports | `--overview` (auto-detects), or `--decode-as tcp/10203=s7` |
| Compare against a known-good baseline | `--baseline` once, then `--baseline-diff X.baseline.json` (or a known-good `.pcap`) |
| Building automation / metering | `--knx --lontalk --bacnet` / `--dlms --c1222` |
| Analyze several captures together | `-summarize` with any of the above |
| Build IR exports and evidence packs | `--json --csv --sqlite --case-dir` |

## What it covers

- **Triage and hunting:** threat correlation, beaconing, exfiltration, scanning, credential exposure, obfuscated payloads, TLS/JA3/JA4 and SSH fingerprints, DNS/LLMNR/mDNS lookups, SOCKS and VPN tunnels, ATT&CK mapping, Suricata corroboration.
- **OT/ICS:** dedicated analyzers for Modbus, DNP3, IEC-104, IEC 61850 MMS/GOOSE/SV, S7, CIP/EtherNet/IP, PROFINET, BACnet, OPC UA/DA, FINS, MELSEC, HART-IP, C37.118 and more; control-command and write visibility, control-loop validation, safety-system (SIS) analysis, and OT protocols found on non-standard ports.
- **Baselines:** `--baseline` records what an OT/ICS/IoT network normally does -- who talks to whom, at what polling cadence, with which commands, from which MACs -- and `--baseline-diff` reports deviations as incidents, with their span, ATT&CK techniques and next steps.
- **Evidence:** file carving and extraction, TLS decryption with a key log (`--decrypt`), VoIP call audio, case metadata and provenance, JSON/CSV/SQLite exports.
- **Scale:** one read of the capture serves every analysis; `--jobs` spreads the work over your cores and `--split N` reports N windows in parallel.

## Sample report

`pcapper 2017-11-02-Smoke-Loader-traffic.pcap --overview` (a public malware-traffic-analysis.net sample), the first sections:

```text
OVERVIEW · 2017-11-02-Smoke-Loader-traffic.pcap
════════════════════════════════════════════════════════════════════════════════
  HIGH      active threat indicators: prioritize investigation now
            IT/enterprise capture · 1,775 packets · 3m 59s · 13 hosts (2 internal, 11 public) · 2017-11-02T17:20:43Z → 17:24:42Z
            why: 3 critical/high threat detections; 1 high-priority lead

Critical/high detections ───────────────────────────────────────────────────────
  • Malware: Executable payload downloaded
  • Obfuscation: Encoded payload content matches attack tradecraft patterns
  • Obfuscation: IOCs recovered from encoded payloads

Immediate leads ────────────────────────────────────────────────────────────────
  1. HIGH     threat-correlation  Critical/high detections observed (3)
              evidence: Detections: 10 (critical/high: 3).
              next: pcapper <capture> --threats -v   (then --threats --mitre to map ATT&CK)
              check: Triage the underlying detections in --threats; verify before escalating.
```

## Usage

```bash
pcapper <target> [<target> ...] [options]        # or: python -m pcapper ...
```

A target is a capture file, a directory, or a wildcard pattern; several can be given. Each capture gets its own report, unless `-summarize` asks for one report across all of them (directories are searched recursively with `-r`).

- Colored output is used on terminals only; `--no-color` or `NO_COLOR=1` turns it off.
- Large captures (millions of packets) are read from disk in one shared pass; pcapper says up front how long a full read takes. See [Large captures](docs/reference.md#large-captures).
- **Recovered secrets are shown in full** in reports and exports: recovering credentials, tokens and community strings is the job. Outputs are written owner-only; treat a case directory as evidence.

## Documentation

The per-feature reference -- every analysis, its flags and a worked example -- is **[docs/reference.md](docs/reference.md)**, including [-summarize](docs/reference.md#summarize-behavior), [decryption](docs/reference.md#decryption), [carving](docs/reference.md#stream-carving), [baselines](docs/reference.md#baselines), [correlation](docs/reference.md#correlation), [IOC enrichment](docs/reference.md#ioc-enrichment), [configuration](docs/reference.md#configuration), [plugins](docs/reference.md#plugins) and the [CLI flag groups](docs/reference.md#cli-flag-groups).

Release notes are in [CHANGELOG.md](CHANGELOG.md); how to report a vulnerability is in [SECURITY.md](SECURITY.md).

## Development

```bash
pip install -e ".[dev]"
ruff check --select F pcapper tests
pytest -q                     # add -m "not slow" to skip the subprocess tests
```

The tests run on small synthetic captures built by `tests/make_fixtures.py`; no real traffic is committed, and `.gitignore` is an allow-list, so carved files, decrypted streams, key logs and case exports cannot be added by accident. `tests/rollup_check.py` runs the deep `-summarize` checks over every analysis on composite captures built from the ICS-pcaps collection.

### Pull requests from more than one machine

1. **Start from an up-to-date `main`:** `git switch main && git pull --ff-only`, then `git switch -c <topic>`.
2. **Add release notes under `## Unreleased`** in CHANGELOG.md, and leave the version alone. The changelog merges as a union, so two branches that both added entries do not conflict.
3. **Only if GitHub reports a conflict:** `git fetch && git merge origin/main` on the branch, push, and review the merged `## Unreleased` section. A PR that is merely behind `main` merges as it is.
4. **Squash-merge**, or turn on auto-merge to merge once the checks pass. GitHub deletes the branch; then, on each machine: `git switch main && git pull --ff-only && git fetch --prune && git branch -D <topic>`.
5. **Release:** set `__version__` in `pcapper/__init__.py` (the only copy of the version) and add a `## X.Y.Z — date` heading directly below `## Unreleased`, which stays the top heading. After that PR merges: `git switch main && git pull --ff-only && git tag -a vX.Y.Z -m "pcapper X.Y.Z" && git push origin vX.Y.Z && gh release create vX.Y.Z --verify-tag`, with the changelog section as the release notes.

## License

MIT -- see [LICENSE](LICENSE).
