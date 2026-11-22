# pcapper reference

Per-feature reference for every analysis mode: what it does, the flags that
drive it, and a worked example. For an overview, installation and a quick start,
see the [README](../README.md).

Split out of the README, which had reached 28 KB. Content is verbatim.

## Summarize behavior

Use `-summarize` (single dash) to aggregate selected analyses across all resolved target pcaps.

- Summarize renders merged rollup output only (no per‑pcap sections).
- Recursive directory traversal is enabled only with `-r/--recursive`.

## DNS Queries

`--dnsqueries` lists every DNS lookup in a capture with the response observed
for it: the client, the server it asked (for LLMNR, the host that answered), the
name and type, and what came back -- the answers, NXDOMAIN or another error,
`no response`, or `(query not captured)` for a response whose query predates the
capture. LLMNR and mDNS lookups use the DNS wire format and are included,
labelled by protocol.

- The default view lists each distinct lookup once, at its first sighting, with
  how often it repeated (×N); `-v` lists every query in time order with its
  packet number, transaction ID and round-trip time.
- `-ip <IP>` lists only that host's lookups (as client or as server), like every
  other step; `-summarize` merges captures and names each row's capture; `-vt`
  adds a VirusTotal column; `--json` / `--csv` / `--sqlite` carry every record.
- `--timeline` and `--hostdetails` no longer list DNS lookups: they say how many
  there were and point here (a lookup VirusTotal flags stays on the timeline).
- `PCAPPER_MAX_DNS_QUERY_RECORDS` (default 200000) caps the records kept per
  capture; the rest are counted.

```bash
python -m pcapper capture.pcapng --dnsqueries -ip 10.0.0.5
python -m pcapper ./captures/ -r --dnsqueries -summarize -v
```

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

`--safety` reports Triconex/TriStation traffic (TCP/UDP 1500-1502) and decodes TriStation (layout and codes per Nozomi Networks' tricotools dissector): the request/reply/reject mix, the key switch position and program state from CP status replies, the project name, and a timeline of logic and state-changing commands. Findings: TRITON-pattern reprogramming (logic upload, download change/allocate program, run), program download, OVD disable, point writes, run-state changes and a key switch left in PROGRAM/REMOTE.

```bash
python -m pcapper capture.pcap --safety
```

## Capture Input

- A target is a capture when its header says so (pcap, nanosecond pcap, modified pcap, pcapng); the extension is never consulted, so `cap_00001_20210318035345` is accepted. A directory scan names any `*.pcap` file without a capture header instead of dropping it.
- A gzip-compressed capture (`.pcap.gz`, `.pcapng.gz`, or any gzip file holding a capture) is read decompressed, like any other capture; its report names, sizes and hashes the file as given (`Type : pcap (gzip)`). It cannot be cut into `--split` windows, and its packet count (for the memory budget) is estimated from its start.
- Split captures (`X.pcap.part000.pcap`, `X.pcap.part001.pcap` ...) found together are analysed as one capture, streamed part by part: one timeline, one conversation table, titled `X.pcap [N parts joined]`, hashed over the parts in order. Suricata and `--decrypt` run per part. `--no-join-parts` analyses them one by one; a single part named on its own is always analysed alone.

## Large Captures

A capture larger than the in-memory budget is read from disk. Several things keep that fast without changing what any analysis reports:

- **Lightweight records.** Every OT analyzer (the port- and EtherType-based ones, Modbus, DNP3, CIP, ENIP, GOOSE and R-GOOSE, SV, PTP, LLDP/PROFINET-DCP, IEC 101/103, synchrophasor, safety/TriStation, OPC Classic), the `--files` stream pass and auto-decode parse a few header bytes per packet instead of a full scapy dissection, and fall back to scapy for anything the header parser does not reproduce exactly. Ethernet, Linux cooked, raw-IP and BSD-loopback captures are parsed this way. `PCAPPER_RAW_READER=0` disables it.
- **Prefilters.** Those analyzers skip packets they can never claim before parsing them; totals and time spans still count every packet. An analyzer covering several encodings (POWERLINK: EtherType, UDP and v1; PROFINET: PNIO-CM ports and the RT EtherType) analyses them all in one read.
- **One read per run.** A run plans every analysis its steps start -- the steps' own and the ones they nest (the file analysis behind `--http`, QUIC and certificates behind `--tls`, the dozens behind `--threats` or `--overview`) -- with one dry run, and computes them all from one read of the capture: held in memory when it fits (a single step that nests others is kept in memory too), else in one shared pass from disk where they run concurrently. Analyses that combine others read their own packets first and combine afterwards, so they share that pass rather than adding one. The capture's SHA-256/SHA-1 come from the same read, and so do a pcapng's interface and section details (the summary's capture details). A single analysis streams the capture. From disk, the decode-as port detection reads up to the first 50,000 packets before the analyses run; the records are kept (up to `PCAPPER_PRIME_MAX_BYTES`, default 64 MiB) and the read that follows replays them and carries on where the detection stopped, so it adds no read. `PCAPPER_SHARED_PASS=0` disables shared passes, `PCAPPER_SHARED_PASS_DEBUG=1` prints every read and the analyses it fed.
- **`--jobs N`** spreads those analyses over N processes (0 = one per CPU, 1 = a single process); the report is identical. A capture held in memory is shared with forked workers -- each starts once the analyses it needs are done and reads the packets and those results from shared memory, no read and no copy. From disk, workers read no file: the main process's own read copies every byte into a pipe per worker (buffered up to `PCAPPER_TEE_BUFFER_BYTES`, 64 MiB, per worker), and each parses the capture from there -- replaying the head the decode-as check kept, from the memory it inherits -- for the analyses that need no other, while the main process runs the rest at the same time, waiting for a worker's result rather than computing it again. A worker whose copy falls short of the file computes nothing from it. Without `--jobs`: when the run is worth it (packets × analyses 500,000+) one process per usable CPU, at most 8, never more than the plan has analyses; in memory no more than half the available memory allows (~6 KB per packet per worker); from disk only as many workers as keep pace with the main process (`--overview`: 3). A run that queries VirusTotal or geolocation stays in one process unless `--jobs` says otherwise: concurrent queries could meet a rate limit a single process does not.
- **Suricata** (`--suricata`) reads the capture file itself (a compressed one from an inflated copy, a split one part by part); the capture's hash comes from the run's read. `PCAPPER_SURICATA_FEED=1` feeds it a copy of the run's read through a FIFO instead -- one read for pcapper and Suricata together -- but Suricata 6's alerts depend on the pace it is fed at, and a slow run costs it alerts, so it is off by default. With a copy waiting, the run reads the capture before the steps, even for one analysis. Each alert's examples are its five earliest events, whatever order Suricata's threads wrote them in.
- **`--decrypt`** lists the TLS/SSH streams with tshark fed the same way -- down its standard input where there are no FIFOs (`PCAPPER_TSHARK_FEED=0` has it read the file) -- then follows them all -- TLS and SSH together -- in one tshark run of its own (up to 200 streams per run) that stops at the last frame they need: at most two reads of the capture in all, whatever the number of streams.
- **Filtered runs** (`--bpf`, `--time-start`/`--time-end`) read once too: tcpdump filters a copy of pcapper's read down its standard input (macOS: tcpdump reads the file), and every analysis, nested ones included, sees the filtered packets. `--split N` reads the capture twice: once to index the windows (equal packet counts need the total first; the capture's hashes come from that walk), once in the windows.
- **Split and compressed captures** read once too: a split capture's hashes carry on from part to part through the run's read, and `--jobs` workers are copied every part (framed by its size) from it; a gzip-compressed capture is inflated by pcapper's own reader, so what wants it inflated (tshark, a pcapng's details) takes it from the same read.
- **`--split N`** cuts the capture into N contiguous windows (at record boundaries, equal packet counts) and analyses them in parallel, printing one report per window. Each report is exact for its window; conversations and detections spanning windows are seen in parts. Packet filters, exports, `-summarize`, `--correlate`, baselines and `--packet`/`--streams`/`--carve`/`--extract`/`--decrypt`/`--suricata` analyse the capture whole.
- **Memory budget.** A capture is kept in memory when its estimated packet count fits `PCAPPER_CACHE_MAX_PACKETS` (default a quarter of available memory at ~6 KB per dissected packet, 100k–4M packets), in addition to the byte budget below.
- **`--timeline` keeps each record's time** (8 bytes) for its first `PCAPPER_TIMELINE_TIMES_MAX` records (default 16,000,000) to date the file transfers it lists; transfers past them are dated from a scan of the record times.
- **Notice.** Above `PCAPPER_LARGE_CAPTURE_PACKETS` (default 1,000,000) pcapper prints the estimated packet count, how long one full read takes on this machine, whether the capture stays in memory, and the options above.

For one question about a huge capture, the fastest route is still a narrower input: a single protocol flag, or `editcap -A/-B` for a time window and `tcpdump -r IN -w OUT 'tcp port 502'` for one protocol.

## OT Protocols on Non-Standard Ports

Every OT analyzer selects traffic by port. `--decode-as` adds ports (repeatable):

```bash
python -m pcapper plc.pcap --s7 --decode-as tcp/10203=s7
python -m pcapper plc.pcap --s7 --decode-as 'tcp.port==10203,s7comm'   # tshark -d syntax
```

Without it, the busiest server ports in the first 50,000 packets are tested against S7/MMS (TPKT), Modbus, DNP3, EtherNet/IP, IEC-104, OPC UA, BACnet, KNXnet/IP, ADS, XGT, FINS, MELSEC, HART-IP, ROC Plus, C12.22, DLMS and R-GOOSE. A port is assigned only when the protocol's own length fields frame at least 60% of its payload packets exactly and at least 3 carry protocol content; each detection is printed, scoped to its capture, shown in `--overview` and reported by `--threats` (T1571). `--no-auto-decode` turns it off.

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
- `--config PATH` on the command line
- `PCAPPER_CONFIG` in the environment
- `~/.pcapper.toml`
- `~/.config/pcapper/config.toml`

A `pcapper.toml` in the **current directory is not loaded automatically**.
pcapper is often run from inside an evidence directory, and a config planted
there could enable outbound VirusTotal/ip-api lookups or redirect output paths
without any sign on the command line. Pass it explicitly with `--config` if
that is what you want.

Whenever a config is applied, pcapper prints `Config: <path>` to stderr, lists
any keys that match no option, and prints a notice for any key that enables
network egress (`vt`, `ip_geo`). A config that exists but cannot be parsed is
an error (exit 2), not a silent fallback to defaults.

Example:

```toml
[defaults]
no_color = true
timeline_bins = 48
vt = true
log_file = "pcapper.log"
log_json = true
```

Config keys match argparse dest names (use underscores, not dashes). Options
given on the command line always take precedence over the config.

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
- `--decode-as SPEC`
- `--decrypt`
- `--decrypt-limit N`
- `--decrypt-out DIR`
- `--cache-mb MB`
- `--ioc-file PATH`
- `--jobs N` / `-j N`
- `--json PATH`
- `--list-plugins`
- `--log-file PATH`
- `--log-json`
- `--no-auto-decode`
- `--no-color`
- `--no-join-parts`
- `--no-status`
- `--packet N`
- `--profile`
- `--split N`
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
- `--dnsqueries`
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

- `--ads`
- `--bacnet`
- `--c1222`
- `--cip`
- `--coap`
- `--codesys`
- `--control-loop`
- `--crimson`
- `--csp`
- `--df1`
- `--dlms`
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
- `--knx`
- `--lldp`
- `--lontalk`
- `--melsec`
- `--mms`
- `--modbus`
- `--modicon`
- `--mqtt`
- `--niagara`
- `--opc`
- `--ot-commands`
- `--ot-commands-config`
- `--ot-commands-fast`
- `--ot-commands-sessions`
- `--pccc`
- `--pcworx`
- `--powerlink`
- `--prconos`
- `--profinet`
- `--ptp`
- `--rocplus`
- `--s7`
- `--safety`
- `--srtp`
- `--sv`
- `--xgt`
- `--yokogawa`

Count: 48 flags

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
- Timeline output keeps every event and includes TCP SYN/SYN-ACK connection events with port visibility. The default view shows each distinct event once at its first sighting (×N and the last time); `-v` lists every event in time order with exact timestamps and links between related events.
- Every report is concise by default and complete with `-v`: the footer of the default view names the sections `-v` adds, and truncated tables say how many rows `-v` shows. Rankings of artifacts (domains, hosts, URLs, user agents, server names, fingerprints, commands, ports, protocols, conversations ...) show the top 10 and the bottom 10 -- the rarest, where the long tail of an investigation lives -- with a line saying how many sit between them. The scored "Analyst Verdict" of a report is a `-v` "Assessment" section; threat-hunt/forensics/CTF/OT highlights, immediate leads and the auto-run deep dives are part of `--overview` only.
- Use `--timeline-bins` to control OT activity sparkline resolution and `--timeline-storyline-off` to disable the storyline block.
- If your shell expands wildcards (for example `Un*`), pcapper now accepts the resulting multiple target arguments directly.
- While captures are analysed, stderr shows one progress bar per capture (`[2/5] name.pcap ━━━━━━──── 62% 0:41`) and nothing else; it moves with each read pass and each finished analysis, weighted by cost, and disappears when the capture is done. `-v` shows the detail instead: each read pass's percentage, each analysis's spinner and start/finish timing, scapy's and Python's warnings, and the large-capture and auto decode-as notices — each on its own line. Errors are shown either way.
- Use `--no-status` for cleaner output in logs/pipelines (no bar is drawn when stderr is not a terminal either).
- `--ot-commands-config` accepts JSON/YAML with `write_markers` and `protocol_markers` overrides (YAML requires PyYAML).
- Use `--ot-commands-sessions` to change the number of session rows in the OT commands block.
- VirusTotal lookups require `VT_API_KEY` and `-vt`/`--vt`.
- Set `PCAPPER_QUOTE` to override the banner quote, or `PCAPPER_QUOTE_SEED` for deterministic rotation.
- Output ordering is deterministic by default; set `PCAPPER_DETERMINISTIC=0` to restore Python's default Counter tie ordering.
- Use `--self-check` for a quick dependency and environment check, and `--list-plugins` to inspect loaded plugins.
- Chained steps (e.g. `--ssh --tls --dns`), and a single step that runs others (`--http` the file analysis, `--tls` QUIC and certificates, `--ips` host names), parse the capture once and share the packet list across all analyzers. Captures are held in memory when they fit the cache budget (default 256 MB total / 64 MB per file; chained runs raise the per-file limit to the total budget). For larger captures, raise the budget with `--cache-mb` (e.g. `--cache-mb 1024`) so multi-step runs avoid re-parsing the file per step — a dissected packet takes ~6 KB, 30–90x the file size for typical captures, and a capture is also held only when its estimated packets fit `PCAPPER_CACHE_MAX_PACKETS`. Captures that are not held are read in shared passes (see Large Captures). Env equivalents: `PCAPPER_CACHE_MAX_BYTES`, `PCAPPER_CACHE_FILE_MAX_BYTES`, `PCAPPER_CACHE_ENABLED=0`.
- Analyzers invoked multiple times in one run (top-level step plus internal fan-out from `--threats`, `--overview`, `--hostdetails`, `--ips`, `--files`) are computed once and replayed from an in-memory result cache. Disable with `PCAPPER_ANALYSIS_MEMO=0`. The cached object is shared, not copied, on a replay (results are immutable by contract); set `PCAPPER_ANALYSIS_MEMO_COPY=1` to restore deep copies.
- **Roles.** In every per-protocol view the *client* is the end that talks to the service port and the *server* is the end that holds it, regardless of which way a given packet travels. A service port on the source side only identifies the service when the destination is an ephemeral port (>= 1024), so a flow from ephemeral 389 to 443 is not LDAP.
- **Windows.** `First Seen` / `Last Seen` / `Duration` in a per-protocol view span that protocol's packets, not the whole capture; the capture-wide window is in the base summary and `--health`. Per-second rates in a protocol view are computed over the protocol window.
- **Segment lengths** come from the IP/TCP headers, so the padding of a 60-byte minimum Ethernet frame is never read as payload (a padded pure ACK is 0 bytes of data, not 6).
- `--decode` bounds every decompressor (gzip, zlib, bzip2, xz) at 32 MiB of output.
- `--decrypt` bounds every tshark call at 120 s; override with `PCAPPER_TSHARK_TIMEOUT`.
- A target whose extension says capture but whose magic does not (a gzip-compressed or renamed file) is rejected with exit code 2 rather than read as an empty capture.
