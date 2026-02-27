from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import shutil
import subprocess


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


def _tshark_available() -> bool:
    return shutil.which("tshark") is not None


def _run_tshark(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True)


def _collect_streams(path: Path, display_filter: str, pref: str | None) -> tuple[list[int], list[str]]:
    errors: list[str] = []
    cmd = ["tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(["-r", str(path), "-T", "fields", "-e", "tcp.stream", "-Y", display_filter])
    proc = _run_tshark(cmd)
    if proc.returncode != 0:
        errors.append(proc.stderr.strip() or "tshark stream listing failed.")
        return [], errors
    streams: set[int] = set()
    for line in proc.stdout.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            streams.add(int(text))
        except ValueError:
            continue
    return sorted(streams), errors


def _stream_label(path: Path, stream_id: int) -> str:
    cmd = [
        "tshark",
        "-r",
        str(path),
        "-Y",
        f"tcp.stream=={stream_id}",
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-c",
        "1",
    ]
    proc = _run_tshark(cmd)
    if proc.returncode != 0:
        return f"stream_{stream_id}"
    parts = proc.stdout.strip().split("\t")
    if len(parts) >= 4:
        src_ip = parts[0] or parts[4] if len(parts) > 4 else parts[0]
        src_port = parts[1]
        dst_ip = parts[2] or parts[5] if len(parts) > 5 else parts[2]
        dst_port = parts[3]
        if src_ip and dst_ip:
            return f"{src_ip}-{src_port}_to_{dst_ip}-{dst_port}"
    return f"stream_{stream_id}"


def _follow_stream(path: Path, stream_id: int, pref: str | None, follow_proto: str) -> tuple[str, str]:
    cmd = ["tshark"]
    if pref:
        cmd.extend(["-o", pref])
    cmd.extend(["-r", str(path), "-q", "-z", f"follow,{follow_proto},ascii,{stream_id}"])
    proc = _run_tshark(cmd)
    return proc.stdout, proc.stderr


def decrypt_tls(path: Path, keylog: Path, output_dir: Path, limit: int) -> DecryptSummary:
    errors: list[str] = []
    notes: list[str] = []
    outputs: list[Path] = []

    if not _tshark_available():
        return DecryptSummary(
            path=path,
            protocol="TLS",
            keylog_path=keylog,
            output_dir=output_dir,
            stream_count=0,
            outputs=[],
            errors=["tshark not found on PATH."],
            notes=[],
        )

    pref = f"tls.keylog_file:{keylog}"
    streams, stream_errors = _collect_streams(path, "tls", pref)
    if stream_errors:
        errors.extend(stream_errors)
    if not streams:
        notes.append("No TLS streams detected for decryption.")

    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for stream_id in streams:
        if limit and count >= limit:
            notes.append(f"TLS stream limit reached ({limit}).")
            break
        label = _sanitize_filename(_stream_label(path, stream_id))
        filename = output_dir / f"tls_{stream_id}_{label}.txt"
        stdout, stderr = _follow_stream(path, stream_id, pref, "tls")
        if not stdout and stderr:
            stdout, stderr = _follow_stream(path, stream_id, pref, "ssl")
        if stderr.strip():
            errors.append(stderr.strip())
        if stdout:
            filename.write_text(stdout, encoding="utf-8", errors="ignore")
            outputs.append(filename)
            count += 1

    return DecryptSummary(
        path=path,
        protocol="TLS",
        keylog_path=keylog,
        output_dir=output_dir,
        stream_count=count,
        outputs=outputs,
        errors=errors,
        notes=notes,
    )


def decrypt_ssh(path: Path, keylog: Path, output_dir: Path, limit: int) -> DecryptSummary:
    errors: list[str] = []
    notes: list[str] = []
    outputs: list[Path] = []

    if not _tshark_available():
        return DecryptSummary(
            path=path,
            protocol="SSH",
            keylog_path=keylog,
            output_dir=output_dir,
            stream_count=0,
            outputs=[],
            errors=["tshark not found on PATH."],
            notes=[],
        )

    pref = f"ssh.keylog_file:{keylog}"
    streams, stream_errors = _collect_streams(path, "ssh", pref)
    if stream_errors:
        errors.extend(stream_errors)
    if not streams:
        notes.append("No SSH streams detected for decryption.")

    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    for stream_id in streams:
        if limit and count >= limit:
            notes.append(f"SSH stream limit reached ({limit}).")
            break
        label = _sanitize_filename(_stream_label(path, stream_id))
        filename = output_dir / f"ssh_{stream_id}_{label}.txt"
        stdout, stderr = _follow_stream(path, stream_id, pref, "ssh")
        if stderr.strip():
            errors.append(stderr.strip())
        if stdout:
            filename.write_text(stdout, encoding="utf-8", errors="ignore")
            outputs.append(filename)
            count += 1

    return DecryptSummary(
        path=path,
        protocol="SSH",
        keylog_path=keylog,
        output_dir=output_dir,
        stream_count=count,
        outputs=outputs,
        errors=errors,
        notes=notes,
    )
