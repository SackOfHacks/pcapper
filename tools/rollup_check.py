"""Deep checks of ``-summarize`` across every analysis -- a developer tool,
not shipped with pcapper.

    py -3 tools/rollup_check.py build DIR --ics ICS_PCAPS [--common DIR] [--pair A B ...]
    py -3 tools/rollup_check.py {order,identity,self,seed,all} DIR [--step STEP ...] [--workers N]

``build`` writes two composite captures into DIR, X.pcap and Y.pcap, each
holding a different small capture of every protocol family it finds (the
ICS-pcaps collection's folders, the test captures, any ``--pair``), plus
empty.pcap and iocs.txt: every analysis then has data on both sides of a
merge. The checks, over every analysis flag:

  order     -summarize X Y prints what -summarize Y X prints
  identity  X prints what -summarize X empty prints (Y likewise): a capture
            without the traffic changes nothing
  self      -summarize X X-copy -- the same traffic twice over -- lists every
            row once with its counts doubled, and leaves counts of distinct
            things (hosts, flows, unique strings, findings) and durations as
            they were
  seed      a report is the same under two hash seeds, X alone and X+Y

A rollup says "Captures: 2" where a report gives its path, and some rows keep
the capture they came from (located by a packet number, or named on purpose):
those differences are listed in KNOWN per check. Anything else fails the run
(exit status 1) and is printed.
"""

from __future__ import annotations

import argparse
import difflib
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "tests" / "data"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
SKIP_STEPS = {"decode", "packet", "pcapmeta"}  # per packet / per file by design
HOST = "192.168.10.50"  # a host of tests/data/mixed.pcap, which build puts in X

# Steps whose rollup differs from the capture on purpose, per check.
KNOWN = {
    # base: SHA "multiple", capture count; carve: files written per capture;
    # health: no rates across the gaps between captures; the rest name the
    # capture a row came from.
    "identity": {"base", "carve", "certificates", "ctf", "dnsqueries", "health", "malware", "obfuscation", "search"},
    # Rows located by a packet number (or a per-capture flow id) keep their
    # capture, so a capture and its copy hold two of each.
    "self": {"carve", "dnsqueries", "http", "malware", "obfuscation", "search"},
    "order": set(),
    "seed": set(),
}

COSMETIC = [
    (re.compile(r"all captures \(\d+\)|all captures|ALL_PCAPS_\d+|ALL_PCAPS"), "<CAP>"),
    (re.compile(r"in these captures"), "in this capture"),
    (re.compile(r"across \d+ captures?"), "across <N> capture"),
    (re.compile(r"^(\s*)(?:Path:\s+\S*<CAP>|Captures:\s+\d+)$"), r"\1<CAPTURES>"),
]

# What the self check counts: addresses, MACs and timestamps identify a row
# (kept); any other number is a count, masked with its unit (652 B doubles to
# 1.27 KB); column padding collapsed.
ROW_TOKENS = re.compile(
    r"(?P<keep>\d{4}-\d\d-\d\dT[\d:.]+Z?"
    r"|(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?![\w.])"
    r"|(?<![\w:])[0-9a-f]{2}(?::[0-9a-f]{2}){5}(?![\w:])"
    r"|(?<![\w:])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![\w:]))"
    r"|(?P<num>\d[\d,.]*\s?(?:[KMGT]i?B|B|ms|us|s|m|h|d|%|pps|bps|/min|/s|/h)?)",
    re.I,
)
DISTINCT_NOUNS = (r"hosts?|clients?|servers?|conversations?|flows?|incidents?|indicators?|devices?|endpoints?|"
                  r"peers?|assets?|findings?|detections?|IPs?|MACs?|domains?|issues?|sessions?")
COUNTED = [re.compile(rf"(\d[\d,]*)\s+(?:{DISTINCT_NOUNS})(?![\w-])", re.I),
           re.compile(r"(\d[\d,]*)\s+unique\b", re.I),
           re.compile(r"\bunique\s+(?:[a-z]+\s+)?(\d[\d,]*)", re.I),
           re.compile(r"\b(\d+)h \d+m")]


# --- running pcapper ----------------------------------------------------------------


def steps(selected: list[str] | None) -> dict[str, list[str]]:
    sys.path.insert(0, str(REPO))
    from pcapper.cli import _builtin_flag_map

    found: dict[str, list[str]] = {"base": []}
    for flag, step in _builtin_flag_map().items():
        if flag.startswith("--") and step not in found and step not in SKIP_STEPS:
            found[step] = [flag]
    if selected:
        missing = sorted(set(selected) - set(found))
        if missing:
            raise SystemExit(f"unknown step(s): {', '.join(missing)}")
        found = {k: v for k, v in found.items() if k in selected}
    return dict(sorted(found.items()))


def extra_args(step: str, folder: Path) -> list[str]:
    return {
        "hostdetails": ["-ip", HOST],
        "timeline": ["-ip", HOST],
        "ioc": ["--ioc-file", str(folder / "iocs.txt")],
        "search": ["example"],
    }.get(step, [])


def run(folder: Path, args: list[str], seed: str | None = None) -> tuple[int, list[str], str]:
    env = dict(os.environ, NO_COLOR="1", PCAPPER_NO_COLOR="1", PYTHONIOENCODING="utf-8", PCAPPER_QUOTE="q",
               PYTHONPATH=str(REPO) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    if seed is not None:
        env["PYTHONHASHSEED"] = seed
    proc = subprocess.run([sys.executable, "-m", "pcapper", *args, "-v", "--no-auto-decode", "--no-status"],
                          cwd=str(folder), env=env, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=3600)
    return proc.returncode, ANSI.sub("", proc.stdout).splitlines(), ANSI.sub("", proc.stderr)[-800:]


def normalise(lines: list[str], names: tuple[str, ...]) -> list[str]:
    out = []
    for line in lines:
        if line.startswith("PCAPPER v") or "empty.pcap" in line:
            continue
        for name in names:
            line = line.replace(name, "<CAP>")
        for pattern, repl in COSMETIC:
            line = pattern.sub(repl, line)
        out.append(line.rstrip())
    return out


def diff(a: list[str], b: list[str]) -> list[str]:
    return [d for d in difflib.unified_diff(a, b, n=0, lineterm="") if not d.startswith(("---", "+++", "@@"))]


def failed_run(*results: tuple[int, list[str], str]) -> list[str]:
    return [f"exit {rc}: {err.strip().splitlines()[-1] if err.strip() else '(no stderr)'}"
            for rc, _out, err in results if rc != 0 or "Traceback" in err]


# --- the checks ---------------------------------------------------------------------


def check_order(folder: Path, step: str, flags: list[str]) -> list[str]:
    extra = flags + extra_args(step, folder)
    xy = run(folder, ["-summarize", "X.pcap", "Y.pcap", *extra])
    yx = run(folder, ["-summarize", "Y.pcap", "X.pcap", *extra])
    names = ("X.pcap", "Y.pcap")
    return failed_run(xy, yx) or diff(normalise(xy[1], names), normalise(yx[1], names))


def check_identity(folder: Path, step: str, flags: list[str]) -> list[str]:
    extra = flags + extra_args(step, folder)
    problems: list[str] = []
    for name in ("X.pcap", "Y.pcap"):
        alone = run(folder, [name, *extra])
        merged = run(folder, ["-summarize", name, "empty.pcap", *extra])
        problems += failed_run(alone, merged) or [
            f"[{name}] {d}" for d in diff(normalise(alone[1], (name,)), normalise(merged[1], (name,)))
        ]
    return problems


def _shape(line: str) -> str:
    text = ROW_TOKENS.sub(lambda m: m.group("keep") or "#", line.replace("≈", ""))
    return re.sub(r"\s+", " ", text).strip()


def _counted(line: str) -> list[int]:
    return [int(m.group(1).replace(",", "")) for pattern in COUNTED for m in pattern.finditer(line)]


def check_self(folder: Path, step: str, flags: list[str]) -> list[str]:
    extra = flags + extra_args(step, folder)
    names = ("X-copy.pcap", "X.pcap")
    alone = run(folder, ["X.pcap", *extra])
    twice = run(folder, ["-summarize", "X.pcap", "X-copy.pcap", *extra])
    if failed_run(alone, twice):
        return failed_run(alone, twice)
    a, b = normalise(alone[1], names), normalise(twice[1], names)

    def shapes(lines: list[str]) -> Counter:
        return Counter(_shape(line) for line in lines
                       if len(line.strip()) > 3 and not set(line.strip()) <= set("─═-=│|·•. "))

    single, double = shapes(a), shapes(b)
    problems = [f"listed {count}x (alone {single.get(shape, 0)}x): {shape[:150]}"
                for shape, count in double.items() if count > max(1, single.get(shape, 0))]
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "replace" and (i2 - i1) == (j2 - j1):
            for old, new in zip(a[i1:i2], b[j1:j2]):
                ca, cb = _counted(old), _counted(new)
                if len(ca) == len(cb) and any(x > 1 and y == 2 * x for x, y in zip(ca, cb)):
                    problems.append(f"doubled: {old.strip()[:90]}  ->  {new.strip()[:90]}")
    return problems


def check_seed(folder: Path, step: str, flags: list[str]) -> list[str]:
    extra = flags + extra_args(step, folder)
    problems: list[str] = []
    for captures in (["X.pcap"], ["-summarize", "X.pcap", "Y.pcap"]):
        one, two = run(folder, [*captures, *extra], "1"), run(folder, [*captures, *extra], "2")
        problems += failed_run(one, two) or [f"[{' '.join(captures)}] {d}" for d in diff(one[1], two[1])]
    return problems


CHECKS = {"order": check_order, "identity": check_identity, "self": check_self, "seed": check_seed}


def run_checks(folder: Path, names: list[str], selected: list[str] | None, workers: int) -> int:
    for needed in ("X.pcap", "Y.pcap", "empty.pcap", "iocs.txt"):
        if not (folder / needed).is_file():
            raise SystemExit(f"{folder / needed} is missing: run `rollup_check.py build {folder} --ics ...` first")
    if "self" in names and not (folder / "X-copy.pcap").is_file():
        shutil.copyfile(folder / "X.pcap", folder / "X-copy.pcap")
    todo = steps(selected)
    unexpected = 0
    for name in names:
        check = CHECKS[name]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = dict(zip(todo, pool.map(lambda item: check(folder, *item), todo.items())))
        bad = {step: problems for step, problems in results.items() if problems}
        known = {step for step in bad if step in KNOWN[name]}
        print(f"\n{name}: {len(todo) - len(bad)} of {len(todo)} steps clean"
              + (f"; {len(known)} differ on purpose ({', '.join(sorted(known))})" if known else ""))
        for step, problems in sorted(bad.items()):
            if step in known:
                continue
            unexpected += 1
            print(f"  FAIL {step}: {len(problems)} difference(s)")
            for line in problems[:8]:
                print(f"       {line[:200]}")
    print(f"\n{'all checks passed' if not unexpected else f'{unexpected} unexpected difference(s)'}")
    return 1 if unexpected else 0


# --- building the composite captures ---------------------------------------------


ICS_FOLDERS = ["BACnet", "CIP", "EthernetIP", "IEC60870-5-104", "MELSEC", "ModbusTCP", "OPC", "beckoff", "dnp3",
               "fox", "hart", "modicon", "omron", "profinet", "quickdraw", "s7", "DLMS-COSEM", "ICS-Samples"]
ICS_PAIRS = {  # folders that mix protocols: explicit files
    "GOOSE": ("IEC61850/GOOSE/GOOSE.pcap", "IEC61850/GOOSE/Sample_File_GOOSE.pcap"),
    "MMS": ("IEC61850/MMS - Specific Commands/iec61850_write.pcap", "IEC61850/MMS - Specific Commands/mms-stopRequest.pcap"),
    "MMS+GOOSE": ("IEC61850/Sample_File_MMS_and_GOOSE.pcap", "IEC61850/m-send-req.mms.pcap"),
    "C37.118": ("C37.118/C37.118_1PMU_UDP.pcap", "C37.118/C37.118_1PMU_TCP.pcap"),
}
TEST_PAIRS = {
    "IT-1": ("mixed.pcap", "http.pcap"),
    "IT-2": ("dns.pcap", "tls.pcap"),
    "VoIP": ("voip.pcap", "voip_attack.pcap"),
}


def build(folder: Path, ics: Path, common: Path | None, pairs: list[list[str]]) -> int:
    from scapy.all import rdpcap, wrpcap  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.utils import PcapWriter  # type: ignore

    def ether(path: Path) -> list:
        try:
            return [p for p in rdpcap(str(path)) if isinstance(p, Ether)]  # one link type per pcap
        except Exception as exc:  # noqa: BLE001
            print(f"  ! unreadable {path}: {exc}")
            return []

    def smallest_two(sub: Path) -> list[Path]:
        found = sorted((p for p in sub.rglob("*")
                        if p.suffix.lower() in (".pcap", ".pcapng") and 1_000 < p.stat().st_size < 1_500_000),
                       key=lambda p: (p.stat().st_size, str(p)))
        picked: list[Path] = []
        for path in found:
            if ether(path):
                picked.append(path)
            if len(picked) == 2:
                break
        return picked

    x: list = []
    y: list = []

    def add(label: str, a: Path, b: Path) -> None:
        pa, pb = ether(a), ether(b)
        print(f"{label:14s} X={a.name} ({len(pa)})  Y={b.name} ({len(pb)})")
        x.extend(pa)
        y.extend(pb)

    for label, (a, b) in TEST_PAIRS.items():
        add(label, DATA / a, DATA / b)
    for label, (a, b) in ICS_PAIRS.items():
        if (ics / a).is_file() and (ics / b).is_file():
            add(label, ics / a, ics / b)
    if common is not None:
        if (common / "modbus/modbusSmall.pcap").is_file():
            add("Modbus-test", DATA / "modbus.pcap", common / "modbus/modbusSmall.pcap")
        if (common / "lldp.pcap").is_file() and (common / "mqtt.pcap").is_file():
            add("LLDP/MQTT", common / "lldp.pcap", common / "mqtt.pcap")
    for index, (a, b) in enumerate(pairs, 1):
        add(f"pair-{index}", Path(a), Path(b))
    for name in ICS_FOLDERS:
        if not (ics / name).is_dir():
            continue
        picked = smallest_two(ics / name)
        if len(picked) == 2:
            add(name, *picked)
        elif picked:  # one capture: half to each side, so the protocol is on both
            packets = ether(picked[0])
            half = len(packets) // 2
            x.extend(packets[:half])
            y.extend(packets[half:])
            print(f"{name:14s} split {picked[0].name}: X={half}  Y={len(packets) - half}")

    folder.mkdir(parents=True, exist_ok=True)
    for label, packets in (("X.pcap", x), ("Y.pcap", y)):
        packets.sort(key=lambda p: float(p.time))
        wrpcap(str(folder / label), packets, linktype=1)
        print(f"{label}: {len(packets)} packets, {(folder / label).stat().st_size} bytes")
    writer = PcapWriter(str(folder / "empty.pcap"), linktype=1)
    writer._write_header(None)
    writer.close()
    (folder / "iocs.txt").write_text("93.184.216.34\nexample.com\n", encoding="utf-8")
    (folder / "X-copy.pcap").unlink(missing_ok=True)
    return 0


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)  # progress shows when piped
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build", help="write X.pcap, Y.pcap, empty.pcap and iocs.txt into DIR")
    b.add_argument("dir", type=Path)
    b.add_argument("--ics", type=Path, required=True, help="the ICS-pcaps collection")
    b.add_argument("--common", type=Path, help="a folder with lldp.pcap, mqtt.pcap and modbus/modbusSmall.pcap")
    b.add_argument("--pair", nargs=2, action="append", default=[], metavar=("X_PART", "Y_PART"),
                   help="two more captures of one protocol, one for each side")
    helps = {
        "order": "-summarize X Y prints what -summarize Y X prints",
        "identity": "a capture merged with an empty one prints what it prints alone",
        "self": "a capture merged with its own copy lists every row once",
        "seed": "reports are the same under two hash seeds",
        "all": "all four checks",
    }
    for name in (*CHECKS, "all"):
        c = sub.add_parser(name, help=helps[name])
        c.add_argument("dir", type=Path)
        c.add_argument("--step", action="append", help="only these steps (repeatable)")
        c.add_argument("--workers", type=int, default=max(2, (os.cpu_count() or 4) // 2))
    args = parser.parse_args()
    if args.command == "build":
        return build(args.dir, args.ics, args.common, args.pair)
    names = list(CHECKS) if args.command == "all" else [args.command]
    return run_checks(args.dir.resolve(), names, args.step, args.workers)


if __name__ == "__main__":
    raise SystemExit(main())
