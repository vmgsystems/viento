"""
viento.dr_drill
Automated cold-archive decompression and integrity verification (`viento dr-drill`)
for SQLite (`.sqlite3.gz`, `.db.gz`, `.sqlite3`, `.db`), PostgreSQL SQL dumps (`.sql.gz`, `.sql`),
PostgreSQL custom-format archives (`PGDMP` `.dump`, `.backup`, `.pgdump`), and Kubernetes `etcd`
BoltDB (`bbolt`) snapshots (`.etcd`, `.snap`) with bounded streaming decompression and virtual-table resilience.
"""

import gzip
import re
import shutil
import sqlite3
import struct
import subprocess
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
                raw_size = archive_path.stat().st_size
                if raw_size > max_uncompressed_bytes:
                    raise ValueError(
                        f"Uncompressed archive size ({raw_size} bytes) exceeds safety ceiling ({max_uncompressed_bytes} bytes)"
                    )
                shutil.copy2(archive_path, tmp_db)

            conn = sqlite3.connect(str(tmp_db))
            try:
                integrity_rows = [str(r[0]) for r in conn.execute("PRAGMA integrity_check;").fetchall()]
                integrity = integrity_rows[0] if len(integrity_rows) == 1 else "; ".join(integrity_rows)
                rows = conn.execute(
                    "SELECT name, COALESCE(sql, '') FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
                ).fetchall()
                tables = [r[0] for r in rows]
                total_rows = 0
                table_read_errors = []
                for tbl_name, create_sql in rows:
                    if create_sql.strip().upper().startswith("CREATE VIRTUAL TABLE"):
                        continue
                    safe_tbl = tbl_name.replace('"', '""')
                    try:
                        cnt = conn.execute(f'SELECT COUNT(*) FROM "{safe_tbl}";').fetchone()[0]
                        total_rows += int(cnt)
                    except sqlite3.Error as tbl_exc:
                        table_read_errors.append(f"{tbl_name}: {tbl_exc}")
                passed = (
                    len(integrity_rows) == 1
                    and integrity.lower() == "ok"
                    and len(tables) > 0
                    and not table_read_errors
                )
                if passed:
                    detail = "OK"
                elif table_read_errors:
                    detail = f"Unreadable table(s): {'; '.join(table_read_errors)}"
                else:
                    detail = "Integrity or empty-schema failure"
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=passed,
                    integrity_status=integrity if not table_read_errors else "corrupt_table",
                    table_count=len(tables),
                    total_rows=total_rows,
                    detail=detail,
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
    require_completion_footer: bool = True,
) -> ArchiveDrillResult:
    """Verifies a PostgreSQL pg_dump (.sql or .sql.gz) archive for decompression, schema DDL, and completion markers."""
    try:
        if not archive_path.name.endswith(".gz"):
            raw_size = archive_path.stat().st_size
            if raw_size > max_uncompressed_bytes:
                raise ValueError(
                    f"Uncompressed SQL dump size ({raw_size} bytes) exceeds safety ceiling ({max_uncompressed_bytes} bytes)"
                )

        total_bytes = 0
        table_count = 0
        row_count = 0
        in_copy_block = False
        has_pg_dump_header = False
        has_completion_footer = False
        create_table_re = re.compile(r"^\s*CREATE\s+TABLE\b", re.IGNORECASE)
        insert_re = re.compile(r"^\s*INSERT\s+INTO\b", re.IGNORECASE)
        copy_re = re.compile(r"^\s*COPY\s+\S+.*FROM\s+stdin;", re.IGNORECASE)
        commit_re = re.compile(r"^\s*COMMIT\s*;\s*$", re.IGNORECASE)
        ddl_dml_re = re.compile(
            r"^\s*(CREATE|INSERT|COPY|ALTER|DROP|SET|BEGIN|SELECT|UPDATE|DELETE)\b",
            re.IGNORECASE,
        )

        opener = (lambda p: gzip.open(p, "rt", encoding="utf-8", errors="replace")) if archive_path.name.endswith(".gz") else (
            lambda p: open(p, "r", encoding="utf-8", errors="replace")
        )
        with opener(archive_path) as f_in:
            for line in f_in:
                total_bytes += len(line.encode("utf-8", errors="replace"))
                if total_bytes > max_uncompressed_bytes:
                    raise ValueError(f"Decompressed SQL dump exceeds safety ceiling ({max_uncompressed_bytes} bytes)")
                if in_copy_block:
                    if line.rstrip("\r\n") == "\\.":
                        in_copy_block = False
                    else:
                        row_count += 1
                    continue
                if "PostgreSQL database dump" in line and "complete" not in line:
                    has_pg_dump_header = True
                if create_table_re.search(line):
                    table_count += 1
                    has_completion_footer = False
                elif copy_re.search(line):
                    in_copy_block = True
                    has_completion_footer = False
                elif insert_re.search(line):
                    row_count += 1
                    has_completion_footer = False
                elif "PostgreSQL database dump complete" in line:
                    has_completion_footer = True
                elif commit_re.match(line):
                    if not has_pg_dump_header:
                        has_completion_footer = True
                elif ddl_dml_re.search(line):
                    has_completion_footer = False

        passed = table_count > 0 and not in_copy_block and (has_completion_footer or not require_completion_footer)
        if in_copy_block:
            status_str = "truncated_copy"
        elif table_count == 0:
            status_str = "empty_schema"
        elif require_completion_footer and not has_completion_footer:
            status_str = "missing_completion_footer"
        else:
            status_str = "ok"

        if passed and has_completion_footer:
            detail = "OK (pg_dump verified)"
        elif passed:
            detail = "OK"
        elif in_copy_block:
            detail = "Truncated COPY block"
        elif table_count == 0:
            detail = "Empty schema (no CREATE TABLE found)"
        else:
            detail = "Truncated dump: missing PostgreSQL completion footer"
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


def verify_postgres_custom_archive(
    archive_path: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> ArchiveDrillResult:
    """Verifies a PostgreSQL custom-format (pg_dump -Fc / PGDMP) archive (.dump, .backup, .pgdump, and .gz variants)."""
    with tempfile.TemporaryDirectory(prefix="viento-pgdmp-") as tmpdir:
        tmp_dump = Path(tmpdir) / "restored.dump"
        try:
            if archive_path.name.endswith(".gz"):
                _stream_decompress_bounded(archive_path, tmp_dump, max_bytes=max_uncompressed_bytes)
            else:
                raw_size = archive_path.stat().st_size
                if raw_size > max_uncompressed_bytes:
                    raise ValueError(
                        f"Uncompressed custom dump size ({raw_size} bytes) exceeds safety ceiling ({max_uncompressed_bytes} bytes)"
                    )
                shutil.copy2(archive_path, tmp_dump)

            data = tmp_dump.read_bytes()
            if len(data) < 32 or not data.startswith(b"PGDMP"):
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=False,
                    integrity_status="invalid_pgdmp_header",
                    table_count=0,
                    total_rows=0,
                    detail="Invalid or missing 5-byte PGDMP custom archive header",
                )
            vmaj, vmin, vrev = data[5], data[6], data[7]
            if vmaj < 1 or vmaj > 2:
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=False,
                    integrity_status="unsupported_pgdmp_version",
                    table_count=0,
                    total_rows=0,
                    detail=f"Unsupported PGDMP version {vmaj}.{vmin}.{vrev}",
                )

            if shutil.which("pg_restore"):
                proc = subprocess.run(
                    ["pg_restore", "--list", str(tmp_dump)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    lines = [ln for ln in proc.stdout.splitlines() if ln.strip() and not ln.strip().startswith(";")]
                    tbl_cnt = sum(1 for ln in lines if " TABLE " in ln)
                    data_cnt = sum(1 for ln in lines if " TABLE DATA " in ln)
                    passed = tbl_cnt > 0
                    return ArchiveDrillResult(
                        archive_name=archive_path.name,
                        passed=passed,
                        integrity_status="ok" if passed else "empty_toc",
                        table_count=tbl_cnt,
                        total_rows=max(data_cnt, tbl_cnt),
                        detail=f"OK (PGDMP v{vmaj}.{vmin}.{vrev}, pg_restore TOC verified)" if passed else "Empty PGDMP TOC",
                    )

            text_view = data.decode("utf-8", errors="ignore")
            create_tables = re.findall(r"CREATE\s+TABLE\b", text_view, flags=re.IGNORECASE)
            table_toc_markers = re.findall(r"\bTABLE\s+DATA\b", text_view)
            has_end_marker = b"PGDMP_END" in data or text_view.rstrip().endswith(";") or len(table_toc_markers) > 0
            table_count = len(create_tables)
            row_blocks = max(len(table_toc_markers), table_count)
            passed = table_count > 0 and has_end_marker
            if not passed:
                status = "empty_toc" if table_count == 0 else "truncated_pgdmp"
                detail = "Empty PGDMP schema (no CREATE TABLE TOC entries found)" if table_count == 0 else "Truncated PGDMP archive"
            else:
                status = "ok"
                detail = f"OK (PGDMP v{vmaj}.{vmin}.{vrev} verified)"
            return ArchiveDrillResult(
                archive_name=archive_path.name,
                passed=passed,
                integrity_status=status,
                table_count=table_count,
                total_rows=row_blocks,
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


def verify_etcd_snapshot_archive(
    archive_path: Path,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
) -> ArchiveDrillResult:
    """Verifies a Kubernetes etcd BoltDB (bbolt) snapshot (.etcd, .snap, and .gz variants)."""
    bbolt_magic = 0xEDDA0CDA
    page_size = 4096
    with tempfile.TemporaryDirectory(prefix="viento-etcd-") as tmpdir:
        tmp_snap = Path(tmpdir) / "snapshot.etcd"
        try:
            if archive_path.name.endswith(".gz"):
                _stream_decompress_bounded(archive_path, tmp_snap, max_bytes=max_uncompressed_bytes)
            else:
                raw_size = archive_path.stat().st_size
                if raw_size > max_uncompressed_bytes:
                    raise ValueError(
                        f"Uncompressed etcd snapshot size ({raw_size} bytes) exceeds safety ceiling ({max_uncompressed_bytes} bytes)"
                    )
                shutil.copy2(archive_path, tmp_snap)

            data = tmp_snap.read_bytes()
            if len(data) < page_size * 4:
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=False,
                    integrity_status="truncated_snapshot",
                    table_count=0,
                    total_rows=0,
                    detail=f"Snapshot smaller than minimum 4-page BoltDB layout ({len(data)} bytes)",
                )

            # In bbolt, page 0 and page 1 are meta pages. Page header is 16 bytes (pgid:u64, flags:u16, count:u16, overflow:u32),
            # followed at offset 16 by meta struct (magic:u32 = 0xEDDA0CDA, version:u32 = 2, pageSize:u32, flags:u32).
            valid_meta_pages = 0
            declared_pgid_ceiling = 4
            for page_idx in (0, 1):
                base_off = page_idx * page_size
                magic, version, psize = struct.unpack_from("<III", data, base_off + 16)
                if magic == bbolt_magic and version == 2 and psize in {4096, 8192, 16384}:
                    valid_meta_pages += 1
                    # pgid in meta struct is at offset 16 + 40 = 56 (u64)
                    if len(data) >= base_off + 64:
                        meta_pgid = struct.unpack_from("<Q", data, base_off + 56)[0]
                        if meta_pgid > declared_pgid_ceiling:
                            declared_pgid_ceiling = meta_pgid

            if valid_meta_pages == 0:
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=False,
                    integrity_status="invalid_bbolt_magic",
                    table_count=0,
                    total_rows=0,
                    detail="Missing BoltDB (0xEDDA0CDA) v2 meta page signature",
                )

            expected_min_bytes = declared_pgid_ceiling * page_size
            if len(data) < expected_min_bytes:
                return ArchiveDrillResult(
                    archive_name=archive_path.name,
                    passed=False,
                    integrity_status="truncated_snapshot",
                    table_count=0,
                    total_rows=0,
                    detail=f"Snapshot truncated at {len(data)} bytes (meta page requires >= {expected_min_bytes} bytes)",
                )

            bucket_markers = [b for b in (b"key", b"meta", b"lease", b"auth", b"members", b"cluster") if b in data[page_size * 2:]]
            k8s_key_hits = data.count(b"/registry/")
            bucket_count = len(bucket_markers)
            passed = bucket_count >= 2
            return ArchiveDrillResult(
                archive_name=archive_path.name,
                passed=passed,
                integrity_status="ok" if passed else "missing_etcd_buckets",
                table_count=bucket_count,
                total_rows=max(k8s_key_hits, bucket_count),
                detail="OK (bbolt etcd snapshot verified)" if passed else "Missing core etcd buckets (key/meta)",
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
    require_completion_footer: bool = True,
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
    pg_custom_candidates = sorted(
        list(backup_dir.glob("*.dump.gz"))
        + list(backup_dir.glob("*.dump"))
        + list(backup_dir.glob("*.pgdump.gz"))
        + list(backup_dir.glob("*.pgdump"))
        + list(backup_dir.glob("*.backup.gz"))
        + list(backup_dir.glob("*.backup"))
    )
    etcd_candidates = sorted(
        list(backup_dir.glob("*.etcd.gz"))
        + list(backup_dir.glob("*.etcd"))
        + list(backup_dir.glob("*.snap.gz"))
        + list(backup_dir.glob("*.snap"))
    )
    for arch in sqlite_candidates:
        results.append(verify_sqlite_archive(arch, max_uncompressed_bytes=max_uncompressed_bytes))
    for arch in sql_candidates:
        results.append(
            verify_postgres_sql_archive(
                arch,
                max_uncompressed_bytes=max_uncompressed_bytes,
                require_completion_footer=require_completion_footer,
            )
        )
    for arch in pg_custom_candidates:
        results.append(verify_postgres_custom_archive(arch, max_uncompressed_bytes=max_uncompressed_bytes))
    for arch in etcd_candidates:
        results.append(verify_etcd_snapshot_archive(arch, max_uncompressed_bytes=max_uncompressed_bytes))
    return results
