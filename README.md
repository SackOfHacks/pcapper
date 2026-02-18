# Pcapper

Modular PCAP/PCAPNG analysis CLI for fast triage and deep-dive protocol investigations across enterprise IT and ICS/OT traffic.

**OT/ICS READY** — plant-floor triage in minutes, not hours.

## OT/ICS Command Center

Industrial networks are first-class here: deep protocol coverage, safety-conscious detections, and context that reads like an OT incident timeline instead of a raw packet dump.

Signal > noise for substations, plants, and mixed IT/OT environments.

What you get:
- Dedicated OT protocol analyzers (IEC-104, DNP3, S7, Profinet, EtherNet/IP, MMS, and more).
- OT-aware timing/jitter insights for control traffic.
- Analyst-friendly outputs tuned for plant floors, substations, and mixed IT/OT environments.
- Control-command visibility for safety/availability impacts (writes, downloads, starts/stops).
- OT/ICS-centric threat and anomaly rollups with evidence lines for fast triage.

## Install

```bash
pip install -r requirements.txt
```

For development:

```bash
pip install -e .
```

## Usage

```bash
python -m pcapper <target> [options]
```

`target` accepts one or more values:
- a single file (`capture.pcap`)
- a directory (`~/Downloads/pcaps/`)
- wildcard patterns (`~/Downloads/pcaps/Un*`)
- multiple explicit targets (for example shell-expanded wildcards)

Examples:

```bash
python -m pcapper ~/Downloads/pcaps/MIME11.pcap --ips
python -m pcapper ~/Downloads/pcaps/ --arp
python -m pcapper ~/Downloads/pcaps/ --dhcp --no-status
python -m pcapper ~/Downloads/pcaps/Un* --arp
python -m pcapper "~/Downloads/pcaps/Un*" --summarize --ips
python -m pcapper one.pcap two.pcapng ~/Downloads/pcaps/ --summarize --timeline -ip 10.182.207.28
```

Secrets/credentials are redacted by default in reports. Use `--show-secrets` to display them.

## Summarize behavior

Use `--summarize` to aggregate selected analyses across all resolved target pcaps.

- Summarize renders merged rollup output only (no per‑pcap sections).
- Recursive directory traversal is enabled only with `-r/--recursive`.

## CLI Flag Groups

Pcapper help is split into:
- `GENERAL FLAGS`
- `IT/ENTERPRISE FUNCTIONS`
- `OT/ICS/INDUSTRIAL FUNCTIONS`

Both IT and ICS/OT function groups are alphabetically ordered.

You can verify the live menu any time with:

```bash
python -m pcapper --help
```

### General flags

- `--bpf EXPR`
- `--base`
- `--case-dir DIR`
- `--case-name NAME`
- `-case`
- `--csv PATH`
- `--extract FILENAME`
- `--follow FLOW`
- `--follow-id STREAM_ID`
- `-ip TIMELINE_IP`
- `--ioc-file PATH`
- `--json PATH`
- `-l, --limit-protocols`
- `--lookup-stream-id STREAM_ID`
- `--no-color`
- `--no-status`
- `-r, --recursive`
- `--sqlite PATH`
- `--search STRING`
- `--show-secrets`
- `--streams-full`
- `-summarize, --summarize`
- `--time-end TIME`
- `--time-start TIME`
- `-v, --verbose`
- `--view FILENAME`

### IT/Enterprise functions (alphabetical)

- `--arp`
- `--beacon`
- `--certificates`
- `--creds`
- `--ctf`
- `--dhcp`
- `--dns`
- `--domain`
- `--encrypted-dns`
- `--exfil`
- `--files`
- `--ftp`
- `--health`
- `--hostdetails`
- `--hostname`
- `--http`
- `--http2`
- `--icmp`
- `--ioc`
- `--ips`
- `--kerberos`
- `--ldap`
- `--netbios`
- `--nfs`
- `--ntlm`
- `--ntp`
- `--opc-classic`
- `--pcapmeta`
- `--powershell`
- `--protocols`
- `--quic`
- `--rdp`
- `--rpc`
- `--services`
- `--sizes`
- `--smb`
- `--smtp`
- `--snmp`
- `--ssh`
- `--streams`
- `--strings`
- `--syslog`
- `--tcp`
- `--teamviewer`
- `--telnet`
- `--threats`
- `--timeline`
- `--tls`
- `--udp`
- `--vlan`
- `--vnc`
- `--vpn`
- `--winrm`
- `--wmic`

Count: 54 flags

### OT/ICS/Industrial functions (alphabetical)

- `--bacnet`
- `--cip`
- `--coap`
- `--crimson`
- `--csp`
- `--df1`
- `--dnp3`
- `--enip`
- `--ethercat`
- `--fins`
- `--goose`
- `--hart`
- `--honeywell`
- `--iccp`
- `--iec101-103`
- `--iec104`
- `--lldp`
- `--melsec`
- `--mms`
- `--modbus`
- `--modicon`
- `--mqtt`
- `--niagara`
- `--odesys`
- `--opc`
- `--ot-commands`
- `--pccc`
- `--pcworx`
- `--prconos`
- `--profinet`
- `--ptp`
- `--s7`
- `--srtp`
- `--sv`
- `--yokogawa`

Count: 35 flags

## Notes

- For timeline mode, supply `-ip` with `--timeline`.
- If your shell expands wildcards (for example `Un*`), pcapper now accepts the resulting multiple target arguments directly.
- Use `--no-status` for cleaner output in logs/pipelines.

## License

MIT
