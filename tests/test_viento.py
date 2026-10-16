"""Unit and integration tests for VMG Viento Open-Core CLI."""

import gzip
import sqlite3
import tempfile
from pathlib import Path

from viento import __version__
from viento.bench import run_sqlite_contention_benchmark
from viento.cli import main
from viento.dr_drill import run_dr_drill
from viento.linter import InvariantLinter


def test_viento_semver_version():
    assert __version__ == "0.1.0"
    assert main(["version"]) == 0


def test_viento_self_lint_clean():
    repo_root = Path(__file__).resolve().parents[1]
    linter = InvariantLinter(repo_root)
    violations = linter.run()
    assert violations == [], f"Unexpected violations: {[str(v) for v in violations]}"


def test_viento_bench_execution():
    report = run_sqlite_contention_benchmark(iterations=40)
    assert report["iterations"] == 40
    assert report["wal_tuned"]["total_ms"] >= 0
    assert report["delete_default"]["total_ms"] >= 0
    assert report["speedup_factor"] > 0


def test_viento_dr_drill_compressed_archive():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        raw_db = base / "sample.sqlite3"
        conn = sqlite3.connect(str(raw_db))
        conn.execute("CREATE TABLE monitors (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("INSERT INTO monitors (name) VALUES ('api-gateway');")
        conn.commit()
        conn.close()

        gz_db = base / "sample.sqlite3.gz"
        with open(raw_db, "rb") as f_in, gzip.open(gz_db, "wb") as f_out:
            f_out.write(f_in.read())
        raw_db.unlink()

        results = run_dr_drill(base)
        assert len(results) == 1
        assert results[0].passed is True
        assert results[0].integrity_status.lower() == "ok"
        assert results[0].table_count == 1
        assert results[0].total_rows == 1
        assert main(["dr-drill", "--backup-dir", str(base)]) == 0
