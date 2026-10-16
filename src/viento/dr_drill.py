"""
viento.dr_drill
Automated cold-archive decompression and integrity verification (`viento dr-drill`)
for SQLite (`.sqlite3.gz`, `.db.gz`, `.sqlite3`, `.db`) and PostgreSQL (`.sql.gz`, `.sql`)
backups with bounded streaming decompression and virtual-table resilience.
"""

import gzip
import re
import shutil
import sqlite3
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List

DEFAULT_MAX_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024  # 2 GiB safety ceiling


@dataclass
class ArchiveDrillResult:
    archive_name: str
    passed: bool
    integrity_status: str
    table_count: int
    total_rows: int
    detail: str


def _stream_decompress_bounded(gz_path: Path, dst_path: Path, max_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES) -> int:
    total = 0
    chunk_size = 65536
    with gzip.open(gz_path, "rb") as f_in, open(dst_path, "wb") as f_out:
        while True:
            buf = f_in.read(chunk_size)
            if not buf:
                break
            total += len(buf)
            if total > max_bytes:
                raise ValueError(f"Decompressed archive exceeds safety ceiling ({max_bytes} bytes)")
            f_out.write(buf)
    return total


def verify_sqlite_archive(
    archive_path: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> ArchiveDrillResult:
    with tempfile.TemporaryDirectory(prefix="viento-dr-") as tmpdir:
        tmp_db = Path(tmpdir) / "restored.sqlite3"
        try:
            if archive_path.name.endswith(".gz"):
                _stream_decompress_bounded(archive_path, tmp_db, max_bytes=max_uncompressed_bytes)
            else:
                shutil.copy2(archive_path, tmp_db)

            conn = sqlite3.connect(str(tmp_db))
            try:
                integrity = conn.execute("PRAGMA integrity_check;").fetchone()[0]
                rows = conn.execute(
                    "SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
                tables = [r[0] for r in rows]
                total_rows = 0
                for tbl_name, create_sql in rows:
                    if create_sql.strip().upper().startswith("CREATE VIRTUAL TABLE"):
                        continue
                    safe_tbl = tbl_name.replace('"', '""')
                    try:
                        cnt = conn.execute(f'SELECT COUNT(*) FROM "{safe_tbl}";').fetchone()[0]
                        total_rows += int(cnt)
                    except sqlite3.OperationalError:
                        # Skip custom extension-backed shadow tables if extension is not loaded
                        continue
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


def verify_postgres_sql_archive(
    archive_path: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> ArchiveDrillResult:
    """Verifies a PostgreSQL pg_dump (.sql or .sql.gz) archive for decompression, schema DDL, and completion markers."""
    try:
        total_bytes = 0
        table_count = 0
        row_count = 0
        in_copy_block = False
        has_completion_footer = False
        create_table_re = re.compile(r"^\s*CREATE\s+TABLE\b", re.IGNORECASE)
        insert_re = re.compile(r"^\s*INSERT\s+INTO\b", re.IGNORECASE)
        copy_re = re.compile(r"^\s*COPY\s+\S+.*FROM\s+stdin;", re.IGNORECASE)

        opener = (lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace")) if archive_path.name.endswith(".gz") else (
            lambda p: open(p, "r", encoding="utf-8", errors="replace")
        )
        with opener(archive_path) as f_in:
            for line in f_in:
                total_bytes += len(line.encode("utf-8", errors="replace"))
                if total_bytes > max_uncompressed_bytes:
                    raise ValueError(f"Decompressed SQL dump exceeds safety ceiling ({max_uncompressed_bytes} bytes)")
                if in_copy_block:
                    if line.startswith("\\."):
                        in_copy_block = False
                    else:
                        row_count += 1
                    continue
                if create_table_re.search(line):
                    table_count += 1
                elif copy_re.search(line):
                    in_copy_block = True
                elif insert_re.search(line):
                    row_count += 1
                elif "PostgreSQL database dump complete" in line or "COMMIT;" in line:
                    has_completion_footer = True

        passed = table_count > 0 and not in_copy_block
        status_str = "ok" if passed else ("truncated_copy" if in_copy_block else "empty_schema")
        detail = "OK (pg_dump verified)" if (passed and has_completion_footer) else ("OK" if passed else "Missing tables or truncated COPY block")
        return ArchiveDrillResult(
            archive_name=archive_path.name,
            passed=passed,
            integrity_status=status_str,
            table_count=table_count,
            total_rows=row_count,
            detail=detail,
        )
    except Exception as exc:
        return ArchiveDrillResult(
            archive_name=archive_path.name,
            passed=False,
            integrity_status="error",
            table_count=0,
            total_rows=0,
            detail=str(exc),
        )


def run_dr_drill(
    backup_dir: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> List[ArchiveDrillResult]:
    results: List[ArchiveDrillResult] = []
    if not backup_dir.exists():
        return results
    sqlite_candidates = sorted(
        list(backup_dir.glob("*.sqlite3.gz"))
        + list(backup_dir.glob("*.db.gz"))
        + list(backup_dir.glob("*.sqlite3"))
        + list(backup_dir.glob("*.db"))
    )
    sql_candidates = sorted(
        list(backup_dir.glob("*.sql.gz"))
        + list(backup_dir.glob("*.sql"))
    )
    for arch in sqlite_candidates:
        results.append(verify_sqlite_archive(arch, max_uncompressed_bytes=max_uncompressed_bytes))
    for arch in sql_candidates:
        results.append(verify_postgres_sql_archive(arch, max_uncompressed_bytes=max_uncompressed_bytes))
    return results
