from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import json
import sqlite3

from pcapper.exporting import ExportBundle, export_csv, export_json, export_sqlite


def _bundle() -> ExportBundle:
    summary = SimpleNamespace(
        detections=[
            {"details": "password=supersecret", "note": "=SUM(A1)"},
            {"details": "token=abcd1234"},
        ],
        artifacts=[SimpleNamespace(detail="api_key=supersecret")],
        hosts=[],
    )
    return ExportBundle(path=Path("sample.pcap"), summaries={"test": summary})


def test_export_json_redacts(tmp_path: Path) -> None:
    bundle = _bundle()
    out_path = tmp_path / "out.json"
    export_json(bundle, out_path, redact=True)
    data = json.loads(out_path.read_text(encoding="utf-8"))
    raw = json.dumps(data)
    assert "supersecret" not in raw
    assert "redacted:" in raw


def test_export_csv_redacts_and_sanitizes(tmp_path: Path) -> None:
    bundle = _bundle()
    out_path = tmp_path / "out.csv"
    export_csv(bundle, out_path, redact=True)
    text = out_path.read_text(encoding="utf-8")
    assert "supersecret" not in text
    assert "redacted:" in text
    assert "'=SUM(A1)" in text


def test_export_sqlite_redacts(tmp_path: Path) -> None:
    bundle = _bundle()
    out_path = tmp_path / "out.sqlite"
    export_sqlite(bundle, out_path, redact=True)
    conn = sqlite3.connect(str(out_path))
    try:
        cur = conn.cursor()
        rows = list(cur.execute("SELECT data FROM detections"))
        assert rows
        payloads = "\n".join(row[0] for row in rows)
        assert "supersecret" not in payloads
        assert "redacted:" in payloads
    finally:
        conn.close()
