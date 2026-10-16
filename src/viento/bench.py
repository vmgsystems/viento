"""
viento.bench
Empirical, apples-to-apples SQLite storage lock-contention benchmark comparing
default rollback-journal (DELETE + synchronous=FULL) against tuned WAL mode
(WAL + synchronous=NORMAL + 64 MiB cache + 256 MiB mmap).

Both modes execute the exact same autocommit INSERT and interleaved SELECT
queries so the measured speedup reflects journal/sync/mmap physics rather than
transaction batching differences.
"""

import shutil
import sqlite3
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict


@dataclass
class BenchResult:
    mode: str
    iterations: int
    autocommit_insert_ms: float
    interleaved_query_ms: float
    batched_tx_ms: float
    total_ms: float


def _run_mode(db_path: Path, wal_tuned: bool, iterations: int) -> BenchResult:
    if db_path.exists():
        db_path.unlink()
    writer = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    reader = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    try:
        for conn in (writer, reader):
            if wal_tuned:
                conn.execute("PRAGMA journal_mode = WAL;")
                conn.execute("PRAGMA synchronous = NORMAL;")
                conn.execute("PRAGMA cache_size = -64000;")
                conn.execute("PRAGMA temp_store = MEMORY;")
                conn.execute("PRAGMA mmap_size = 268435456;")
                conn.execute("PRAGMA busy_timeout = 30000;")
            else:
                conn.execute("PRAGMA journal_mode = DELETE;")
                conn.execute("PRAGMA synchronous = FULL;")
                conn.execute("PRAGMA cache_size = -2000;")
                conn.execute("PRAGMA busy_timeout = 30000;")

        writer.execute(
            "CREATE TABLE heartbeat (id INTEGER PRIMARY KEY AUTOINCREMENT, monitor_id INT, status INT, ping REAL, ts INT);"
        )
        writer.execute("CREATE INDEX idx_hb_mon_ts ON heartbeat(monitor_id, ts);")

        # Phase 1: Apples-to-apples single-statement autocommit INSERTs (identical SQL in both modes)
        t0 = time.perf_counter()
        for i in range(iterations):
            writer.execute(
                "INSERT INTO heartbeat (monitor_id, status, ping, ts) VALUES (?, ?, ?, ?);",
                (i % 35, 1, 4.2 + (i % 7), 1700000000 + i),
            )
        t_autocommit = (time.perf_counter() - t0) * 1000.0

        # Phase 2: Apples-to-apples interleaved reader aggregation queries
        t1 = time.perf_counter()
        for m in range(min(35, max(1, iterations // 2))):
            reader.execute(
                "SELECT AVG(ping), SUM(status), COUNT(*) FROM heartbeat WHERE monitor_id = ?;",
                (m,),
            ).fetchone()
        t_query = (time.perf_counter() - t1) * 1000.0

        # Phase 3: Apples-to-apples batched transaction (BEGIN IMMEDIATE ... COMMIT in both modes)
        t2 = time.perf_counter()
        writer.execute("BEGIN IMMEDIATE;")
        for i in range(iterations):
            writer.execute(
                "INSERT INTO heartbeat (monitor_id, status, ping, ts) VALUES (?, ?, ?, ?);",
                (i % 35, 1, 3.8 + (i % 5), 1700010000 + i),
            )
        writer.execute("COMMIT;")
        t_batched = (time.perf_counter() - t2) * 1000.0

        total = t_autocommit + t_query + t_batched
        return BenchResult(
            mode="WAL_TUNED" if wal_tuned else "DELETE_DEFAULT",
            iterations=iterations,
            autocommit_insert_ms=round(t_autocommit, 2),
            interleaved_query_ms=round(t_query, 2),
            batched_tx_ms=round(t_batched, 2),
            total_ms=round(total, 2),
        )
    finally:
        reader.close()
        writer.close()


def run_sqlite_contention_benchmark(workdir: Path = None, iterations: int = 100) -> Dict[str, object]:
    own_tmp = workdir is None
    base = Path(tempfile.mkdtemp(prefix="viento-bench-")) if own_tmp else Path(workdir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        delete_res = _run_mode(base / "bench_delete.db", wal_tuned=False, iterations=iterations)
        wal_res = _run_mode(base / "bench_wal.db", wal_tuned=True, iterations=iterations)
        speedup = round(delete_res.total_ms / max(wal_res.total_ms, 0.01), 2)
        autocommit_speedup = round(delete_res.autocommit_insert_ms / max(wal_res.autocommit_insert_ms, 0.01), 2)
        return {
            "methodology": "symmetric-autocommit-and-batched",
            "iterations": iterations,
            "delete_default": delete_res.__dict__,
            "wal_tuned": wal_res.__dict__,
            "autocommit_speedup_factor": autocommit_speedup,
            "speedup_factor": speedup,
        }
    finally:
        if own_tmp:
            shutil.rmtree(base, ignore_errors=True)
