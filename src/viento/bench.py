"""
viento.bench
Empirical SQLite storage lock-contention benchmark comparing rollback-journal
(DELETE) mode against tuned WAL mode (64 MiB cache + 256 MiB mmap).
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
    insert_ms: float
    query_ms: float
    total_ms: float


def _run_mode(db_path: Path, wal_tuned: bool, iterations: int) -> BenchResult:
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    try:
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

        conn.execute(
            "CREATE TABLE heartbeat (id INTEGER PRIMARY KEY AUTOINCREMENT, monitor_id INT, status INT, ping REAL, ts INT);"
        )
        conn.execute("CREATE INDEX idx_hb_mon_ts ON heartbeat(monitor_id, ts);")

        t0 = time.perf_counter()
        if wal_tuned:
            conn.execute("BEGIN IMMEDIATE;")
            for i in range(iterations):
                conn.execute(
                    "INSERT INTO heartbeat (monitor_id, status, ping, ts) VALUES (?, ?, ?, ?);",
                    (i % 35, 1, 4.2 + (i % 7), 1700000000 + i),
                )
            conn.execute("COMMIT;")
        else:
            for i in range(iterations):
                conn.execute(
                    "INSERT INTO heartbeat (monitor_id, status, ping, ts) VALUES (?, ?, ?, ?);",
                    (i % 35, 1, 4.2 + (i % 7), 1700000000 + i),
                )
        t_insert = (time.perf_counter() - t0) * 1000.0

        t1 = time.perf_counter()
        for m in range(min(35, max(1, iterations // 2))):
            conn.execute(
                "SELECT AVG(ping), SUM(status), COUNT(*) FROM heartbeat WHERE monitor_id = ?;",
                (m,),
            ).fetchone()
        t_query = (time.perf_counter() - t1) * 1000.0

        return BenchResult(
            mode="WAL_TUNED" if wal_tuned else "DELETE_DEFAULT",
            iterations=iterations,
            insert_ms=round(t_insert, 2),
            query_ms=round(t_query, 2),
            total_ms=round(t_insert + t_query, 2),
        )
    finally:
        conn.close()


def run_sqlite_contention_benchmark(workdir: Path = None, iterations: int = 100) -> Dict[str, object]:
    own_tmp = workdir is None
    base = Path(tempfile.mkdtemp(prefix="viento-bench-")) if own_tmp else Path(workdir)
    base.mkdir(parents=True, exist_ok=True)
    try:
        delete_res = _run_mode(base / "bench_delete.db", wal_tuned=False, iterations=iterations)
        wal_res = _run_mode(base / "bench_wal.db", wal_tuned=True, iterations=iterations)
        speedup = round(delete_res.total_ms / max(wal_res.total_ms, 0.01), 2)
        return {
            "iterations": iterations,
            "delete_default": delete_res.__dict__,
            "wal_tuned": wal_res.__dict__,
            "speedup_factor": speedup,
        }
    finally:
        if own_tmp:
            shutil.rmtree(base, ignore_errors=True)
