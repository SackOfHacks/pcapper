from __future__ import annotations

import re
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .capture_parts import capture_parts
from .fifo_feed import FeedRegistry, FifoFeed, can_feed, start_part_feeds
from .pcap_cache import forget_part_hooks
from .utils import env_int, executable_path_warnings, open_private, restrict_dir_permissions


@dataclass(frozen=True)
class DecryptConfig:
    enabled: bool
    tls_keylog: Path | None
    ssh_keylog: Path | None
    output_dir: Path
    limit: int


@dataclass(frozen=True)
class DecryptSummary:
    path: Path
    protocol: str
    keylog_path: Path | None
    output_dir: Path
    stream_count: int
    outputs: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _sanitize_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return cleaned.strip("_") or "stream"


def _tshark_path() -> str | None:
    configured_raw = os.environ.get("PCAPPER_TSHARK_BIN", "")
    configured = str(Path(configured_raw).expanduser()) if configured_raw else ""
    if configured:
        return configured if Path(configured).is_file() else None
    return shutil.which("tshark")


def _tshark_available() -> bool:
    return _tshark_path() is not None


TSHARK_TIMEOUT = float(env_int("PCAPPER_TSHARK_TIMEOUT", 120, minimum=1))

# Fields requested, in order, by the single stream-enumeration pass. Every one is
# emitted as a column whether or not it matched, so the row width is fixed and a
# field can be read by position — see _label_from_row.
_STREAM_FIELDS = (
    "tcp.stream",
    "ip.src",
    "tcp.srcport",
    "ip.dst",
    "tcp.dstport",
    "ipv6.src",
    "ipv6.dst",
    "frame.number",  # a stream's last one bounds the follow run (tshark -c)
)


def _run_tshark(
    cmd: list[str], timeout: float = TSHARK_TIMEOUT
) -> subprocess.CompletedProcess[str] | None:
    """Run tshark, returning ``None`` if it exceeded ``timeout``.

    A malformed or very large capture can stall tshark indefinitely. ``--decrypt``
    invokes it once per stream, so an unbounded call means one pathological
    stream can take the whole run with it, with no output and no way for the
    operator to tell a hang from slow progress. Callers record the expiry in
    ``DecryptSummary.errors`` and move to the next stream, matching how
    ``threats.py`` already handles its own subprocess calls.
    """
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None


def _split_fields(line: str, count: int) -> list[str]:
    """Split one ``-T fields`` row into exactly ``count`` columns.

    Deliberately does not strip the row first. tshark pads every requested
    ``-e`` field, so a field that did not match is emitted as an empty column
    rather than omitted — and for an IPv6 packet the empty columns (``ip.src``,
    ``ip.dst``) come *first*. Stripping the leading tab before splitting is
    indistinguishable from stripping data: it shifts every index down by one and
    silently mislabels the stream. The IPv4 case only appeared to work because
    its empty columns are trailing.
    """
    parts = line.split("\t")
    if len(parts) < count:
        parts.extend([""] * (count - len(parts)))
    return parts[:count]


def _label_from_row(parts: list[str]) -> str:
    """Build ``src-sport_to_dst-dport`` from a padded ``_STREAM_FIELDS`` row."""
    src_ip = parts[1] or parts[5]
    src_port = parts[2]
    dst_ip = parts[3] or parts[6]
    dst_port = parts[4]
    if src_ip and dst_ip:
        return f"{src_ip}-{src_port}_to_{dst_ip}-{dst_port}"
    return ""


# (tshark preference, display filter) of each protocol --decrypt follows.
_TLS = ("tls.keylog_file", "tls")
_SSH = ("ssh.keylog_file", "ssh")

# Stream listings started on a copy of the run's read (pcapper.fifo_feed), by
# (capture, display filter, preference), until the decryption step takes its.
_LISTING_FEEDS = FeedRegistry()


def _listing_command(source: str, display_filter: str, pref: str | None) -> list[str]:
    cmd = [_tshark_path() or "tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(["-r", source, "-Y", display_filter, "-T", "fields"])
    # occurrence=f: take the first occurrence of a field rather than joining all
    # of them with commas, so a tunnelled packet cannot produce a "0,1" that
    # fails int() and silently drops the stream from the listing.
    cmd.extend(["-E", "occurrence=f"])
    for name in _STREAM_FIELDS:
        cmd.extend(["-e", name])
    return cmd


def _capture_key(path: Path) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(path)


def start_decrypt_feeds(config: DecryptConfig | None, path: Path) -> int:
    """Start tshark's stream listings for ``--decrypt`` on a copy of the read
    the run makes of ``path`` -- per part of a split capture, as tshark reads
    them, each started when the read nears its part (PCAPPER_TSHARK_FEED=0
    turns it off) -- so they read no file of their own. The number of
    listings per file."""
    if config is None or not config.enabled or os.environ.get("PCAPPER_TSHARK_FEED", "1") == "0":
        return 0
    if not _tshark_available():
        return 0
    listings = [
        (display_filter, f"{pref_key}:{keylog}")
        for keylog, (pref_key, display_filter) in ((config.tls_keylog, _TLS), (config.ssh_keylog, _SSH))
        if keylog
    ]

    def _start(file: Path) -> None:
        if not can_feed(file, stdin_ok=True):  # tshark reads ``-r -`` where there are no FIFOs
            return
        for display_filter, pref in listings:
            key = (_capture_key(file), display_filter, pref)
            if key in _LISTING_FEEDS:
                continue
            try:
                feed = FifoFeed(
                    file,
                    lambda source, _workdir, flt=display_filter, prf=pref: _listing_command(source, flt, prf),
                    timeout=TSHARK_TIMEOUT,
                    name="tshark",
                    stdin_ok=True,
                )
            except Exception:  # noqa: BLE001 - the listing then reads the file itself
                continue
            _LISTING_FEEDS.add(key, feed)

    if listings:
        start_part_feeds(path, _start)
    return len(listings)


def discard_decrypt_feeds(path: Path | None = None) -> None:
    """Stop the listings no decryption step took up (one capture's, or all)."""
    if path is None:
        _LISTING_FEEDS.discard()
        return
    for part in capture_parts(path):
        _LISTING_FEEDS.discard(_capture_key(part))
    forget_part_hooks(path)


def _fed_listing(
    path: Path, display_filter: str, pref: str | None
) -> tuple[bool, subprocess.CompletedProcess[str] | None]:
    """``(True, process)`` for the listing tshark made from a copy of the
    run's read (process None: it timed out); ``(False, None)`` when there is
    none -- no feed, or a copy that fell short -- and the file must be read."""
    feed = _LISTING_FEEDS.take((_capture_key(path), display_filter, pref))
    if feed is None:
        return False, None
    try:
        fed = feed.result()
    except subprocess.TimeoutExpired:
        return True, None
    finally:
        feed.close()
    if fed is None:
        return False, None
    return True, subprocess.CompletedProcess(feed.argv, fed[0], fed[1], fed[2])


def _collect_streams(
    path: Path, display_filter: str, pref: str | None
) -> tuple[list[int], dict[int, str], list[str], dict[int, int]]:
    """Enumerate matching TCP streams and label each by its endpoints.

    One pass over the capture yields both. The labels used to come from a
    separate ``tshark`` invocation per stream, which re-read the whole file each
    time — 2N+1 reads for N streams, the dominant cost of ``--decrypt`` on a
    multi-GB capture — and bounded that read with ``-c 1``. ``-c`` caps packets
    *read*, not packets *matched*, so tshark read packet #1, applied the display
    filter, and stopped: every stream except the one containing the capture's
    first packet fell through to the ``stream_<N>`` fallback, leaving the
    labelling feature effectively inert.
    """
    errors: list[str] = []
    fed, proc = _fed_listing(path, display_filter, pref)
    if not fed:
        proc = _run_tshark(_listing_command(str(path), display_filter, pref))
    if proc is None:
        errors.append(
            f"tshark stream listing timed out after {TSHARK_TIMEOUT:.0f}s: {path.name}"
        )
        return [], {}, errors, {}
    if proc.returncode != 0:
        errors.append(proc.stderr.strip() or "tshark stream listing failed.")
        return [], {}, errors, {}

    labels: dict[int, str] = {}
    last_frames: dict[int, int] = {}
    unbounded: set[int] = set()
    for line in proc.stdout.splitlines():
        parts = _split_fields(line, len(_STREAM_FIELDS))
        if not any(parts):
            continue
        try:
            stream_id = int(parts[0])
        except ValueError:
            continue
        if not labels.get(stream_id):
            labels[stream_id] = _label_from_row(parts)
        try:
            frame = int(parts[7])
        except ValueError:
            unbounded.add(stream_id)
            continue
        last_frames[stream_id] = max(frame, last_frames.get(stream_id, 0))
    for stream_id in unbounded:
        last_frames.pop(stream_id, None)
    return sorted(labels), labels, errors, last_frames


def _stream_label(stream_id: int, labels: dict[int, str]) -> str:
    return _sanitize_filename(labels.get(stream_id) or f"stream_{stream_id}")


# Streams followed per tshark run (each -z adds a few dozen bytes to its
# command line).
_FOLLOW_BATCH = 200
_FOLLOW_START = "\n" + "=" * 67 + "\nFollow: "


def _split_follow_output(output: str, wanted: list[tuple[str, int]]) -> dict[tuple[str, int], str]:
    """The per-stream blocks of one tshark run with a ``-z follow`` tap for
    each ``(protocol, stream)`` of ``wanted`` -- tshark prints them one after
    another (last tap first), each exactly what a run following that stream
    alone prints -- by ``(protocol, stream)``. Empty unless the output splits
    into exactly one block per tap: a payload that looks like a block header
    must not cut a stream short."""
    blocks: dict[tuple[str, int], str] = {}
    starts = []
    index = output.find(_FOLLOW_START)
    while index >= 0:
        starts.append(index)
        index = output.find(_FOLLOW_START, index + 1)
    if len(starts) != len(wanted) or (starts and starts[0] != 0):
        return {}
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(output)
        block = output[start:end]
        match = re.match(r"\n=+\nFollow: ([^,\n]+),[^\n]*\nFilter: [^\n]*?(\d+)\n", block)
        if match is None:
            return {}
        blocks[(match.group(1), int(match.group(2)))] = block
    if sorted(blocks) != sorted(wanted):
        return {}
    return blocks


def _follow_streams(
    path: Path, wanted: list[tuple[str, int]], prefs: list[str], last_frame: int | None = None
) -> dict[tuple[str, int], tuple[str, str]] | None:
    """Follow several streams -- ``(protocol, stream)``, of every protocol
    asked for -- in one tshark run: one read of the capture for all of them,
    not one each, and only up to ``last_frame`` (the last frame of any of
    them; the frames after it add nothing to their text). Each gets the text
    a run of its own prints; the run's stderr goes with the first. None when
    tshark timed out (the caller follows them one by one, so one stalled
    stream does not cost the others)."""
    if not wanted:
        return {}
    cmd = [_tshark_path() or "tshark"]
    for pref in prefs:
        cmd.extend(["-o", pref])
    cmd.extend(["-r", str(path), "-q"])
    if last_frame:
        cmd.extend(["-c", str(last_frame)])
    for follow_proto, stream_id in wanted:
        cmd.extend(["-z", f"follow,{follow_proto},ascii,{stream_id}"])
    proc = _run_tshark(cmd)
    if proc is None:
        return None
    blocks = _split_follow_output(proc.stdout or "", wanted)
    if not blocks:
        return {}  # nothing to trust (an error, an old tshark): each on its own
    results: dict[tuple[str, int], tuple[str, str]] = {}
    stderr = proc.stderr or ""
    for item in wanted:
        results[item] = (blocks[item], stderr)
        stderr = ""
    return results


def _follow_stream(
    path: Path, stream_id: int, pref: str | None, follow_proto: str
) -> tuple[str, str] | None:
    """Follow one stream. ``None`` means tshark timed out and was given up on."""
    cmd = [_tshark_path() or "tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(
        ["-r", str(path), "-q", "-z", f"follow,{follow_proto},ascii,{stream_id}"]
    )
    proc = _run_tshark(cmd)
    if proc is None:
        return None
    return proc.stdout, proc.stderr


@dataclass
class _Protocol:
    """One protocol ``--decrypt`` follows, and what it found so far."""

    protocol: str
    pref_key: str
    display_filter: str
    follow_protos: tuple[str, ...]
    keylog: Path
    output_dir: Path
    limit: int
    errors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    outputs: list[Path] = field(default_factory=list)
    count: int = 0
    found_any: bool = False
    limit_hit: bool = False

    @property
    def pref(self) -> str:
        return f"{self.pref_key}:{self.keylog}"

    def summary(self, path: Path) -> DecryptSummary:
        return DecryptSummary(
            path=path,
            protocol=self.protocol,
            keylog_path=self.keylog,
            output_dir=self.output_dir,
            stream_count=self.count,
            outputs=self.outputs,
            errors=self.errors,
            notes=self.notes,
        )


def _tls(keylog: Path, output_dir: Path, limit: int) -> _Protocol:
    # TLS needs the ``ssl`` fallback for tshark builds that predate the rename.
    return _Protocol("TLS", _TLS[0], _TLS[1], ("tls", "ssl"), keylog, output_dir, limit)


def _ssh(keylog: Path, output_dir: Path, limit: int) -> _Protocol:
    return _Protocol("SSH", _SSH[0], _SSH[1], ("ssh",), keylog, output_dir, limit)


def _decrypt(path: Path, protocols: list[_Protocol]) -> list[DecryptSummary]:
    """Each protocol's streams listed (from a copy of the run's read when one
    was started for it), then followed -- every protocol's at once, in one
    tshark run per part (per ``_FOLLOW_BATCH`` streams), up to the last frame
    they need -- each stream written to a file of its own. A stream that run
    gives nothing for is followed on its own (and, for TLS, as ``ssl`` too)."""
    if not _tshark_available():
        for job in protocols:
            job.errors.append("tshark not found on PATH.")
        return [job.summary(path) for job in protocols]
    tool = _tshark_path()
    warnings = [f"tshark trust warning: {warning}" for warning in executable_path_warnings(Path(tool))] if tool else []
    for job in protocols:
        job.errors.extend(warnings)
        restrict_dir_permissions(job.output_dir)
    prefs = list(dict.fromkeys(job.pref for job in protocols))
    # tshark reads one file at a time: a joined split capture is decrypted
    # part by part (a stream cut by a part boundary is followed in each part).
    parts = capture_parts(path)
    for part_index, part in enumerate(parts):
        active = [job for job in protocols if not job.limit_hit]
        if not active:
            break
        part_tag = f"p{part_index:03d}_" if len(parts) > 1 else ""
        listed = []
        wanted: list[tuple[_Protocol, int, int | None]] = []
        for job in active:
            streams, labels, stream_errors, last_frames = _collect_streams(part, job.display_filter, job.pref)
            job.errors.extend(stream_errors)
            job.found_any = job.found_any or bool(streams)
            listed.append((job, streams, labels))
            # The streams the limit will let through.
            room = job.limit - job.count if job.limit else len(streams)
            wanted.extend((job, stream_id, last_frames.get(stream_id)) for stream_id in streams[: max(room, 0)])
        prefetched: dict[tuple[str, int], tuple[str, str]] = {}
        for start in range(0, len(wanted), _FOLLOW_BATCH):
            batch = wanted[start : start + _FOLLOW_BATCH]
            frames = [frame for _job, _stream, frame in batch]
            bound = None if any(frame is None for frame in frames) else max(frames)  # type: ignore[type-var]
            got = _follow_streams(
                part, [(job.follow_protos[0], stream_id) for job, stream_id, _frame in batch], prefs, bound
            )
            if got:
                prefetched.update(got)
        for job, streams, labels in listed:
            _write_streams(job, part, part_tag, streams, labels, prefetched)
    for job in protocols:
        if not job.found_any:
            job.notes.append(f"No {job.protocol} streams detected for decryption.")
    return [job.summary(path) for job in protocols]


def _write_streams(
    job: _Protocol,
    part: Path,
    part_tag: str,
    streams: list[int],
    labels: dict[int, str],
    prefetched: dict[tuple[str, int], tuple[str, str]],
) -> None:
    tag = job.protocol.lower()
    for stream_id in streams:
        if job.limit and job.count >= job.limit:
            job.notes.append(f"{job.protocol} stream limit reached ({job.limit}).")
            job.limit_hit = True
            break
        label = _stream_label(stream_id, labels)
        filename = job.output_dir / f"{tag}_{part_tag}{stream_id}_{label}.txt"
        stdout = stderr = ""
        timed_out = False
        for index, follow_proto in enumerate(job.follow_protos):
            followed = prefetched.pop((follow_proto, stream_id), None) if index == 0 else None
            if followed is None:
                followed = _follow_stream(part, stream_id, job.pref, follow_proto)
            if followed is None:
                suffix = f" as {follow_proto}" if index else ""
                job.errors.append(
                    f"tshark timed out after {TSHARK_TIMEOUT:.0f}s following "
                    f"{job.protocol} stream {stream_id}{suffix}; skipped."
                )
                timed_out = True
                break
            stdout, stderr = followed
            if stdout or not stderr:
                break  # got data, or a clean empty result: no fallback needed
        if timed_out:
            continue
        if stderr.strip():
            job.errors.append(stderr.strip())
        if stdout:
            with open_private(filename, "w", encoding="utf-8", errors="ignore") as handle:
                handle.write(stdout)
            job.outputs.append(filename)
            job.count += 1


def decrypt_tls(
    path: Path, keylog: Path, output_dir: Path, limit: int
) -> DecryptSummary:
    return _decrypt(path, [_tls(keylog, output_dir, limit)])[0]


def decrypt_ssh(
    path: Path, keylog: Path, output_dir: Path, limit: int
) -> DecryptSummary:
    return _decrypt(path, [_ssh(keylog, output_dir, limit)])[0]


def decrypt_capture(
    path: Path,
    *,
    tls_keylog: Path | None,
    ssh_keylog: Path | None,
    tls_output_dir: Path,
    ssh_output_dir: Path,
    limit: int,
) -> list[DecryptSummary]:
    """TLS and SSH (those with a key log) together: one follow run per part
    for both. Their summaries, TLS first."""
    protocols = []
    if tls_keylog:
        protocols.append(_tls(tls_keylog, tls_output_dir, limit))
    if ssh_keylog:
        protocols.append(_ssh(ssh_keylog, ssh_output_dir, limit))
    return _decrypt(path, protocols) if protocols else []
