# Security Policy

## Why this file exists

pcapper parses attacker-controlled input as its entire purpose. It reads capture
files from compromised networks, reassembles streams an adversary put on the
wire, carves artifacts out of them, and reconstructs files it was never meant to
see. A parser bug in pcapper is a security bug, and a researcher who finds one
needs somewhere to send it that is not a public issue.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes |
| Latest tagged release | Yes |
| Earlier releases | No — please reproduce against `main` first |

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting**:
**Security → Report a vulnerability** on
<https://github.com/SackOfHacks/pcapper/security/advisories/new>.

Do not open a public issue for a suspected vulnerability.

Please include, as far as you have it:

- what pcapper does that it should not, and what you expected instead;
- the command line you ran;
- a **minimal, synthetic** capture that reproduces it — see the note below;
- the pcapper version (`pip show pcapper`, or the commit), Python version and OS.

Expect an acknowledgement within 7 days and an assessment within 30. If the
report is confirmed, the fix and the advisory are published together, and you
are credited unless you would rather not be.

### Do not send real captures

A capture from a live network is someone else's data: credentials, internal
hostnames, personal information, possibly regulated material. Reduce a
reproducer to synthetic traffic before sending it. `tests/make_fixtures.py` in
this repository shows how the project builds small deterministic captures with
scapy, and is a reasonable starting point.

## Scope

In scope — pcapper handling a malicious or malformed capture:

- crashes, hangs, unbounded memory or disk growth while parsing;
- decompression bombs, and any bound that can be made not to hold;
- path traversal or any write outside the chosen output directory during file
  extraction, carving or decryption;
- command injection through a filename, a field off the wire, or a config value;
- deserialisation of untrusted data, or code execution of any kind;
- an artifact being attributed to the wrong conversation, or evidence
  (a hash, an offset, a timestamp) being reported as sound when it is not.

That last item is deliberate. pcapper's output is used as forensic evidence, so
a confidently-wrong artifact is a security-relevant defect here, not just a
correctness bug.

Out of scope:

- **Recovered secrets appearing in output.** pcapper does not redact what it
  recovers — `reporting._redact_secret` is a documented no-op — because
  recovering credentials, tokens and community strings is the job. Outputs are
  written owner-only (`0600`, directories `0700`) for that reason; treat a case
  directory as evidence and handle it accordingly.
- Findings that require an attacker to already control the machine pcapper runs
  on, or to supply the command line.
- Results from automated scanners with no demonstrated impact on pcapper.
- Vulnerabilities in dependencies — please report those upstream. Tell us anyway
  if pcapper's usage makes one exploitable when it otherwise would not be.

## Running pcapper on hostile input

pcapper is an analysis tool, not a sandbox. When triaging a capture from an
untrusted source, run it in a disposable VM or container, with no credentials
mounted and no network path back into the environment under investigation.
`--carve` and `--files` write reconstructed attacker-supplied files to disk;
those are malware samples, and nothing in pcapper detonates or defangs them.
