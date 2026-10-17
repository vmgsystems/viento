"""
viento.cli
Command-line interface for VMG Viento (`viento lint`, `viento bench`, `viento dr-drill`, `viento version`).
"""

import argparse
import json
import sys
from pathlib import Path

from viento import __version__
from viento.bench import run_sqlite_contention_benchmark
from viento.dr_drill import run_dr_drill
from viento.linter import InvariantLinter


def cmd_lint(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    linter = InvariantLinter(root)
    violations = linter.run()
    if getattr(args, "verify_flux_sync", False):
        violations.extend(linter.check_flux_kustomization_readiness())
    score = max(0.0, round(10.0 - (len(violations) * 0.5), 1))
    if args.json:
        print(
            json.dumps(
                {
                    "version": __version__,
                    "score": score,
                    "violations_count": len(violations),
                    "violations": [str(v) for v in violations],
                },
                indent=2,
            )
        )
    else:
        print(f"VMG Viento Readiness Score: {score} / 10.0 ({len(violations)} violation(s))")
        for v in violations:
            print(f"  * {v}")
    return 1 if violations else 0


def cmd_bench(args: argparse.Namespace) -> int:
    if int(getattr(args, "iterations", 100)) < 1:
        print("Error: --iterations must be >= 1", file=sys.stderr)
        return 2
    workdir = Path(args.workdir).resolve() if args.workdir else None
    report = run_sqlite_contention_benchmark(workdir=workdir, iterations=args.iterations)
    print(json.dumps(report, indent=2))
    return 0


def cmd_dr_drill(args: argparse.Namespace) -> int:
    max_size_mb = int(getattr(args, "max_size_mb", 2048))
    if max_size_mb < 1:
        print("Error: --max-size-mb must be >= 1", file=sys.stderr)
        return 2
    backup_dir = Path(args.backup_dir).resolve()
    max_bytes = max_size_mb * 1024 * 1024
    results = run_dr_drill(backup_dir, max_uncompressed_bytes=max_bytes)
    if not results:
        print(f"No SQLite or PostgreSQL backup archives found in {backup_dir}", file=sys.stderr)
        return 1
    failed = [r for r in results if not r.passed]
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(
            f"[{status}] {r.archive_name} | integrity={r.integrity_status} | tables={r.table_count} | rows={r.total_rows}"
        )
    return 1 if failed else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="viento", description="VMG Viento Autonomous Infrastructure CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="Run mechanical GitOps & Kubernetes zero-trust linter")
    p_lint.add_argument("path", nargs="?", default=".", help="Repository path to lint")
    p_lint.add_argument("--json", action="store_true", help="Output JSON scorecard")
    p_lint.add_argument("--verify-flux-sync", action="store_true", help="Verify live FluxCD Kustomizations report Ready=True")

    p_bench = sub.add_parser("bench", help="Run SQLite DELETE vs tuned WAL contention benchmark")
    p_bench.add_argument("--workdir", default=None, help="Directory to benchmark (defaults to temp dir)")
    p_bench.add_argument("--iterations", type=int, default=100, help="Number of transactions per run")

    p_dr = sub.add_parser("dr-drill", help="Decompress and verify cold SQLite & PostgreSQL backup archives")
    p_dr.add_argument("--backup-dir", required=True, help="Directory containing .sqlite3.gz, .db, or .sql.gz backups")
    p_dr.add_argument("--max-size-mb", type=int, default=2048, help="Max uncompressed archive size in MiB (default: 2048)")

    sub.add_parser("version", help="Print VMG Viento SemVer version")

    args = parser.parse_args(argv)
    if args.command == "version":
        print(__version__)
        return 0
    if args.command == "lint":
        return cmd_lint(args)
    if args.command == "bench":
        return cmd_bench(args)
    if args.command == "dr-drill":
        return cmd_dr_drill(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
