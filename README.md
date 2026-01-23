# Pcapper

Modular CLI for fast, readable PCAP triage and reporting.

## Features
- Accepts a single PCAP/PCAPNG file or a directory of captures
- Summarizes packet count, timestamps, duration, size, interface details
- Produces a protocol presence summary for quick triage
- Modular architecture for easy expansion

## Install

```bash
pip install -r requirements.txt
```

Or install the package locally:

```bash
pip install -e .
```

## Usage

```bash
python -m pcapper /path/to/capture.pcap
python -m pcapper /path/to/folder --recursive
pcapper /path/to/capture.pcapng --limit-protocols 20
```

Optional analysis modules are enabled with flags such as `--dns`, `--http`,
`--icmp`, `--protocols`, `--services`, `--files`, `--smb`, `--ntlm`, and `--ips`.

## Output
Pcapper prints a clean, analyst-friendly report suitable for triage and forensic review.

## License

MIT
