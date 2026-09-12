# pcapper reference

Per-feature reference for every analysis mode: what it does, the flags that
drive it, and a worked example. For an overview, installation and a quick start,
see the [README](../README.md).

Split out of the README, which had reached 28 KB. Content is verbatim.

## Summarize behavior

Use `-summarize` (single dash) to aggregate selected analyses across all resolved target pcaps.

- Summarize renders merged rollup output only (no per‑pcap sections).
- Recursive directory traversal is enabled only with `-r/--recursive`.

## Decryption

Pcapper can drive a tshark-based TLS/SSH decryption workflow when key logs are available.

Example:

```bash
python -m pcapper capture.pcap --tls --decrypt --tls-keylog ~/sslkeys.log --decrypt-out decrypted/
```

Notes:
- `tshark` must be installed and on `PATH`.
- TLS uses NSS `SSLKEYLOGFILE` format. SSH decryption depends on tshark keylog support.

## Stream Carving

Reassemble TCP streams and carve common file signatures.

```bash
python -m pcapper capture.pcap --carve --carve-out carved/
```

## Obfuscation Heuristics

Detect high‑entropy or encoded payloads that may indicate tunneling or obfuscation.

```bash
python -m pcapper capture.pcap --obfuscation
```

## Control-Loop Validation

Analyze Modbus/DNP3 value changes for rapid shifts, oscillations, and outliers.

```bash
python -m pcapper capture.pcap --control-loop
```

## Safety PLC Detection

Detect safety PLC/SIS protocol traffic (Triconex/TriStation heuristics).

```bash
python -m pcapper capture.pcap --safety
```

## Kill-Chain Timeline Tags

Timeline output includes attribution tags and causal links between related events.

```bash
python -m pcapper capture.pcap --timeline -ip 10.0.0.5
```

## LOLBAS Recognition

File transfer analysis highlights living-off-the-land binary artifacts when observed.

```bash
python -m pcapper capture.pcap --files
```

## Correlation

Correlate repeated hosts/services across multiple pcaps.

```bash
python -m pcapper captures/*.pcap --correlate -summarize
```

## Case Metadata

When using `--case-dir`, Pcapper writes `case.json` with analyst info, hashes, timestamps, and CLI options.

## Baselines

Snapshot asset and command baselines, then compare for drift.

```bash
python -m pcapper capture.pcap --baseline-save baseline.json
python -m pcapper capture.pcap --baseline-compare baseline.json
```

## Rules

Apply rule packs to detections.

```bash
python -m pcapper capture.pcap --rules rules.json
```

Minimal `rules.json` example:

```json
[
  {
    "id": "OT_CONTROL_WRITE",
    "title": "OT control writes",
    "severity": "high",
    "match": {
      "all": [
        {"field": "source", "op": "in", "value": ["ot_commands", "iec104", "modbus", "dnp3", "s7"]}
      ],
      "any": [
        {"field": "summary", "op": "regex", "value": "control|write"},
        {"field": "details", "op": "regex", "value": "setpoint|operate"}
      ]
    }
  }
]
```

## IOC Enrichment

You can provide enriched IOC metadata via JSON.

```json
{
  "indicators": [
    {
      "value": "1.2.3.4",
      "type": "ip",
      "source": "VendorX",
      "confidence": 80,
      "mitre": ["TA0011"],
      "tags": ["c2"]
    }
  ]
}
```

## Configuration

Pcapper can load default flag values from a TOML config file. Lookup order:
- `./pcapper.toml`
- `~/.pcapper.toml`
- `~/.config/pcapper/config.toml`

You can also supply `--config PATH` or set `PCAPPER_CONFIG` to override the location.

Example:

```toml
[defaults]
no_color = true
timeline_bins = 48
vt = true
log_file = "pcapper.log"
log_json = true
```

Config keys match argparse dest names (use underscores, not dashes).

## Logging

Use `--log-file PATH` to emit structured events and `--log-json` for JSONL output. If no `--log-file` is provided, JSON logs are sent to stderr.

## Plugins

Pcapper supports analyzers via entry points under the `pcapper.plugins` group. A plugin should return one or more `PluginSpec` instances from `pcapper.plugins`.
Only install plugins from sources you trust; plugin code is imported and executed in-process.

Minimal example (in your plugin package):

```python
from pcapper.plugins import PluginSpec

def register():
    return PluginSpec(
        name="my_analyzer",
        flag="--my-analyzer",
        help="Custom analyzer example",
        group="it",
        analyze=analyze_my_analyzer,
        render=render_my_analyzer,
        merge=merge_my_analyzer,
        title="MY ANALYZER",
    )
```

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
- `--baseline-compare PATH`
- `--baseline-fast`
- `--baseline-save PATH`
- `--bpf EXPR`
- `--carve`
- `--carve-limit N`
- `--carve-max-bytes N`
- `--carve-out DIR`
- `--carve-stream-bytes N`
- `--case-analyst NAME`
- `--case-dir DIR`
- `--case-id ID`
- `--case-name NAME`
- `--case-notes TEXT`
- `--config PATH`
- `--correlate`
- `--correlate-min N`
- `--csv PATH`
- `--decode INPUT`
- `--decrypt`
- `--decrypt-limit N`
- `--decrypt-out DIR`
- `--cache-mb MB`
- `--ioc-file PATH`
- `--json PATH`
- `--list-plugins`
- `--log-file PATH`
- `--log-json`
- `--no-color`
- `--no-status`
- `--packet N`
- `--profile`
- `--profile-out PATH`
- `--rules PATH`
- `--search STRING`
- `--self-check`
- `--sqlite PATH`
- `--ssh-keylog PATH`
- `--streams-full`
- `--time-end TIME`
- `--time-start TIME`
- `--timeline-bins N`
- `--timeline-storyline-off`
- `--tls-keylog PATH`
- `-aes KEY`
- `-case`
- `-categories, --timeline-categories LIST`
- `-established`
- `-exe`
- `-extract FILENAME`
- `-hash FILENAME`
- `-high`
- `-host`
- `-id STREAM_ID`
- `-ip TIMELINE_IP`
- `-l, --limit-protocols N`
- `-mac LOOKUP_MAC`
- `-name HOSTNAME`
- `-port STREAM_PORT`
- `-post`
- `-r, --recursive`
- `-raw` (shows `-view`/`--packet` output as raw text, no ASCII/HEX framing)
- `-rsa KEY_OR_@PATH`
- `-search TERM`
- `-summarize`
- `-v, --verbose`
- `-view FILENAME`
- `-vt, --vt`
- `-xor KEY`

### IT/Enterprise functions (alphabetical)

- `--aim`
- `--arp`
- `--beacon`
- `--certificates`
- `--compromised`
- `--creds`
- `--ctf`
- `--dhcp`
- `--dns`
- `--domain`
- `--email`
- `--encrypted-dns`
- `--exfil`
- `--files`
- `--ftp`
- `--health`
- `--hostdetails`
- `--hostnames`
- `--http`
- `--http2`
- `--icmp`
- `--ioc`
- `--ip`
- `--ips`
- `--kerberos`
- `--ldap`
- `--mac`
- `--malware`
- `--mitre`
- `--netbios`
- `--nfs`
- `--ntlm`
- `--ntp`
- `--obfuscation`
- `--overview`
- `--opc-classic`
- `--pcapmeta`
- `--powershell`
- `--protocols`
- `--qos`
- `--quic`
- `--rdp`
- `--routing`
- `--rpc`
- `--scan`
- `--secrets`
- `--services`
- `--sizes`
- `--smb`
- `--snmp`
- `--ssdp`
- `--ssh`
- `--streams`
- `--strings`
- `--suricata`
- `--suricata-config`
- `--suricata-eve-types`
- `--suricata-only-sid`
- `--suricata-rules`
- `--suricata-strict`
- `--suricata-suppress-sid`
- `--syslog`
- `--tcp`
- `--teamviewer`
- `--telnet`
- `--threats`
- `--timeline`
- `--tls`
- `--tlsm`
- `--udp`
- `--vlan`
- `--vnc`
- `--vpn`
- `--webrequests`
- `--winrm`
- `--wlan`
- `--wmic`

Count: 78 flags

### OT/ICS/Industrial functions (alphabetical)

- `--bacnet`
- `--cip`
- `--coap`
- `--control-loop`
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
- `--ot-commands-config`
- `--ot-commands-fast`
- `--ot-commands-sessions`
- `--pccc`
- `--pcworx`
- `--prconos`
- `--profinet`
- `--ptp`
- `--s7`
- `--safety`
- `--srtp`
- `--sv`
- `--yokogawa`

Count: 40 flags

## Phone Over IP (VoIP)

`--voip` (alias `--sip`) analyses the whole call path, not one protocol.

```bash
python -m pcapper capture.pcap --voip
python -m pcapper capture.pcap --voip --voip-out voip/     # also recover audio
python -m pcapper capture.pcap --voip -ip 10.1.2.3         # one endpoint
```

| Layer | Covered |
| --- | --- |
| Signalling | SIP (any port, UDP/TCP/TLS), Cisco SCCP/Skinny, MGCP, MEGACO/H.248, IAX2, H.323 (H.225 call signalling and RAS) |
| Session description | SDP — addresses, ports, codecs, direction, SRTP keying |
| Media | RTP, RTCP, SRTP, T.38 fax over UDPTL |
| NAT traversal | STUN / TURN / ICE |
| Provisioning | TFTP and HTTP phone configuration fetches |
| Numbering | ENUM (`e164.arpa` NAPTR lookups) |

SIP is recognised by its start line rather than its port, so a PBX moved to 5080
— or a service hiding on an arbitrary port — is still analysed, and the
non-standard port is reported.

### What it recovers

- **Calls** — participants, dialled number, disposition (answered, busy,
  cancelled, rejected, register failed …) and duration, from whichever protocol
  carried them.
- **Registrations** — accounts, contact bindings, source addresses, and the
  success/challenge/failure counts behind them.
- **Credentials** — SIP Digest responses as ready `hashcat -m 11400` lines, IAX2
  MD5 challenge/response pairs and plaintext IAX2 passwords, and TURN long-term
  credentials. Not redacted: recovering them is the point.
- **Keypad digits** — RFC 4733 telephone-events in RTP, SIP INFO
  `application/dtmf-relay`, Skinny `KeypadButton` and MGCP observed events.
  These are routinely IVR PINs, calling-card numbers and card data.
- **Media keys** — `a=crypto ... inline:` in SDP. If the signalling was not
  itself encrypted, every "encrypted" call in the capture is decryptable by
  whoever captured it.
- **Media quality** — per stream: SSRC, codec, packet loss, reordering,
  duplicates and interarrival jitter.
- **Phone configuration fetches** — the richest credential source in a VoIP
  capture, since config files carry the SIP password in the clear and TFTP has
  no authentication at all.
- **Audio** — with `--voip-out`, G.711 (PCMU/PCMA) streams are decoded to WAV.
  Other codecs are reported but not decoded; SRTP-negotiated streams are skipped
  rather than decoded into convincing noise.

### What it detects

Scanner and attack tooling by User-Agent (SIPVicious, sipcli, sipsak, SIPp,
smap and friends), extension enumeration by behaviour, registration brute force
and password spraying, unauthenticated call setup, international and
premium-rate dialling, registration hijacking, RTP with no matching SDP offer,
multiple SSRCs on one media path, cleartext SRTP keys, cleartext signalling,
internet exposure, and INVITE floods. Findings carry ATT&CK technique IDs, so
they flow into `--threats` and `--mitre`.

### Output limits

`PCAPPER_VOIP_MAX_CALLS` (5000), `PCAPPER_VOIP_MAX_CREDENTIALS` (2000),
`PCAPPER_VOIP_MAX_RTP_STREAMS` (5000), `PCAPPER_VOIP_MAX_DTMF_DIGITS` (256),
`PCAPPER_VOIP_MAX_AUDIO_BYTES` (16 MB per stream),
`PCAPPER_VOIP_MIN_RTP_PACKETS` (4 — how many packets must agree on one SSRC
before a stream is reported, which is what keeps arbitrary UDP from being
mistaken for media).

> `pcapper.srtp` is **GE SRTP**, an industrial PLC protocol on ports
> 18245/18246. It is unrelated to Secure RTP, which is handled here.

## Notes

- For timeline mode, supply `-ip` with `--timeline`.
- Use `-categories`/`--timeline-categories` with `--timeline` to filter event categories (comma-separated). Use `-categories false` or an empty value to print the supported list.
- Timeline output always shows all events (independent of `-v`) and includes TCP SYN/SYN-ACK connection events with port visibility.
- Use `--timeline-bins` to control OT activity sparkline resolution and `--timeline-storyline-off` to disable the storyline block.
- If your shell expands wildcards (for example `Un*`), pcapper now accepts the resulting multiple target arguments directly.
- Use `--no-status` for cleaner output in logs/pipelines.
- `--ot-commands-config` accepts JSON/YAML with `write_markers` and `protocol_markers` overrides (YAML requires PyYAML).
- Use `--ot-commands-sessions` to change the number of session rows in the OT commands block.
- VirusTotal lookups require `VT_API_KEY` and `-vt`/`--vt`.
- Set `PCAPPER_QUOTE` to override the banner quote, or `PCAPPER_QUOTE_SEED` for deterministic rotation.
- Output ordering is deterministic by default; set `PCAPPER_DETERMINISTIC=0` to restore Python's default Counter tie ordering.
- Use `--self-check` for a quick dependency and environment check, and `--list-plugins` to inspect loaded plugins.
- Chained steps (e.g. `--ssh --tls --dns`) parse the capture once and share the packet list across all analyzers. Captures are held in memory when they fit the cache budget (default 256 MB total / 64 MB per file; chained runs raise the per-file limit to the total budget). For larger captures, raise the budget with `--cache-mb` (e.g. `--cache-mb 1024`) so multi-step runs avoid re-parsing the file per step — parsed packets occupy roughly 5–10x the file size in RAM. Env equivalents: `PCAPPER_CACHE_MAX_BYTES`, `PCAPPER_CACHE_FILE_MAX_BYTES`, `PCAPPER_CACHE_ENABLED=0`.
- Analyzers invoked multiple times in one run (top-level step plus internal fan-out from `--threats`, `--overview`, `--hostdetails`, `--ips`, `--files`) are computed once and replayed from an in-memory result cache. Disable with `PCAPPER_ANALYSIS_MEMO=0`.

