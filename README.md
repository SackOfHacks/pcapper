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

## Summarize behavior

Use `--summarize` to aggregate selected analyses across all resolved target pcaps.

- `--ips` summarize renders a merged IPS report.
- `--timeline` summarize renders a merged timeline report.
- `--health`, `--rdp`, `--telnet`, `--vnc`, `--teamviewer`, and `--winrm` summarize render full module sections.
- Other modules summarize via module rollups.
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

- `--base`
- `--extract FILENAME`
- `-ip TIMELINE_IP`
- `-l, --limit-protocols`
- `--no-color`
- `--no-status`
- `--search STRING`
- `-case`
- `-r, --recursive`
- `-summarize, --summarize`
- `-v, --verbose`
- `--view FILENAME`

### IT/Enterprise functions (alphabetical)

- `--arp`
- `--beacon`
- `--certificates`
- `--creds`
- `--dhcp`
- `--dns`
- `--domain`
- `--exfil`
- `--files`
- `--ftp`
- `--health`
- `--hostdetails`
- `--hostname`
- `--http`
- `--icmp`
- `--ips`
- `--kerberos`
- `--ldap`
- `--netbios`
- `--nfs`
- `--ntlm`
- `--protocols`
- `--rdp`
- `--services`
- `--sizes`
- `--smb`
- `--ssh`
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
- `--winrm`

Count: 40 flags

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
- `--hart`
- `--honeywell`
- `--iccp`
- `--iec104`
- `--melsec`
- `--mms`
- `--modbus`
- `--modicon`
- `--mqtt`
- `--niagara`
- `--odesys`
- `--opc`
- `--pccc`
- `--pcworx`
- `--prconos`
- `--profinet`
- `--s7`
- `--srtp`
- `--yokogawa`

Count: 30 flags

## Notes

- For timeline mode, supply `-ip` with `--timeline`.
- If your shell expands wildcards (for example `Un*`), pcapper now accepts the resulting multiple target arguments directly.
- Use `--no-status` for cleaner output in logs/pipelines.

## License

MIT
