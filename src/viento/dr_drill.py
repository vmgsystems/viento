"""
viento.dr_drill
Automated cold-archive decompression and B-Tree integrity verification
(`PRAGMA integrity_check` + non-empty schema audit) for SQLite backups.
"""

import gzip
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class ArchiveDrillResult:
    archive_name: str
    passed: bool
    integrity_status: str
    table_count: int
    total_rows: int
    detail: str


def verify_sqlite_archive(archive_path: Path) -> ArchiveDrillResult:
    with tempfile.TemporaryDirectory(prefix="viento-dr-") as tmpdir:
        tmp_db = Path(tmpdir) / "restored.sqlite3"
        try:
            if archive_path.name.endswith(".gz"):
                with gzip.open(archive_path, "rb") as f_in, open(tmp_db, "wb") as f_out:
                    shutil.copyfileobj(f_in, f_out)
            else:
                shutil.copy2(archive_path, tmp_db)

            conn = sqlite3.connect(str(tmp_db))
            try:
                integrity = conn.execute("PRAGMA integrity_check;").fetchone()[0]
                tables = [
                    r[0]
                    for r in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                    ).fetchall()
                ]
                total_rows = 0
                for tbl in tables:
                    safe_tbl = tbl.replace('"', '""')
                    cnt = conn.execute(f'SELECT COUNT(*) FROM "{safe_tbl}";').fetchone()[0]
                    total_rows += int(cnt)
                passed = integrity.lower() == "ok" and len(tables) > 0
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=passed,
                    integrity_status=integrity,
                    table_count=len(tables),
                    total_rows=total_rows,
                    detail="OK" if passed else "Integrity or empty-schema failure",
                )
            finally:
                conn.close()
        except Exception as exc:
            return ArchiveDrillResult(
                archive_name=archive_path.name,
                passed=False,
                integrity_status="error",
                table_count=0,
                total_rows=0,
                detail=str(exc),
            )


def run_dr_drill(backup_dir: Path) -> List[ArchiveDrillResult]:
    results: List[ArchiveDrillResult] = []
    if not backup_dir.exists():
        return results
    candidates = sorted(
        list(backup_dir.glob("*.sqlite3.gz"))
        + list(backup_dir.glob("*.db.gz"))
        + list(backup_dir.glob("*.sqlite3"))
        + list(backup_dir.glob("*.db"))
    )
    for arch in candidates:
        results.append(verify_sqlite_archive(arch))
    return results
