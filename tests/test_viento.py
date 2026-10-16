"""Comprehensive unit and behavioral test suite for VMG Viento Open-Core CLI."""

import gzip
import sqlite3
import tempfile
from pathlib import Path

from viento import __version__
from viento.bench import run_sqlite_contention_benchmark
from viento.cli import main
from viento.dr_drill import run_dr_drill, verify_sqlite_archive
from viento.linter import InvariantLinter


def test_viento_semver_version():
    assert __version__ == "0.2.0"
    assert main(["version"]) == 0


def test_viento_self_lint_clean():
    repo_root = Path(__file__).resolve().parents[1]
    linter = InvariantLinter(repo_root)
    violations = linter.run()
    assert violations == [], f"Unexpected violations: {[str(v) for v in violations]}"


def test_viento_external_repo_portability_any_directory_and_readme():
    """Verifies viento lint inspects K8s manifests in arbitrary directories (e.g., clusters/prod/)
    and does not penalize external README.md files that omit Viento-specific marketing tokens."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "README.md").write_text("# External Enterprise GitOps Repository\n", encoding="utf-8")
        clusters_dir = root / "clusters" / "production"
        clusters_dir.mkdir(parents=True)

        (clusters_dir / "api.yaml").write_text(
            """apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-api
spec:
  template:
    spec:
      containers:
        - name: api
          image: ghcr.io/acme/api:1.4.2
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
""",
            encoding="utf-8",
        )
        linter = InvariantLinter(root)
        assert linter.run() == []

        (clusters_dir / "bad.yaml").write_text(
            """apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-api
spec:
  template:
    spec:
      containers:
        - name: api
          image: nginx:latest
          securityContext:
            privileged: true
""",
            encoding="utf-8",
        )
        violations = linter.run()
        rules = {v.rule for v in violations}
        assert "DISALLOW_LATEST_TAG" in rules
        assert "REQUIRE_RESOURCE_LIMITS" in rules
        assert "DISALLOW_PRIVILEGED_CONTAINERS" in rules


def test_viento_linter_sops_promql_flagger_and_pvc_shrink_rules():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "README.md").write_text("# Test Repo\n", encoding="utf-8")
        (root / ".viento.yaml").write_text(
            """pvc_capacity_floors:
  apps/postgres-data-pvc: "10Gi"
""",
            encoding="utf-8",
        )
        k8s_dir = root / "manifests"
        k8s_dir.mkdir()
        (k8s_dir / "bundle.yaml").write_text(
            """apiVersion: v1
kind: Secret
metadata:
  name: unencrypted-secret
stringData:
  api_key: placeholder
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-data-pvc
  namespace: apps
spec:
  resources:
    requests:
      storage: 2Gi
---
apiVersion: flagger.app/v1beta1
kind: Canary
metadata:
  name: bad-canary
spec:
  analysis:
    iterations: 5
    stepWeight: 10
---
apiVersion: flagger.app/v1beta1
kind: MetricTemplate
metadata:
  name: bad-metric
spec:
  query: |
    sum(rate(traefik_service_requests_total{service=~"{{ target }}", code!~"5.*"}[1m]))
    / (sum(rate(traefik_service_requests_total{service=~"{{ target }}"}[1m]))) * 100
""",
            encoding="utf-8",
        )
        linter = InvariantLinter(root)
        violations = linter.run()
        rules = {v.rule for v in violations}
        assert "SOPS_ENCRYPTION" in rules
        assert "PVC_CAPACITY_SHRINK_FORBIDDEN" in rules
        assert "FLAGGER_SCHEMA_MUTUAL_EXCLUSION" in rules
        assert "TRAEFIK_METRIC_REGEX" in rules
        assert "PROMQL_ZERO_DENOMINATOR_GUARD" in rules


def test_viento_bench_symmetric_methodology():
    report = run_sqlite_contention_benchmark(iterations=40)
    assert report["methodology"] == "symmetric-autocommit-and-batched"
    assert report["iterations"] == 40
    for key in ("autocommit_insert_ms", "interleaved_query_ms", "batched_tx_ms", "total_ms"):
        assert report["wal_tuned"][key] >= 0
        assert report["delete_default"][key] >= 0
    assert report["speedup_factor"] > 0
    assert report["autocommit_speedup_factor"] > 0


def test_viento_dr_drill_sqlite_postgres_and_safety_ceiling():
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

        pg_dump_sql = """-- PostgreSQL database dump
CREATE TABLE public.workflows (
    id integer NOT NULL,
    name text NOT NULL
);
COPY public.workflows (id, name) FROM stdin;
1\talert-triage
2\tdr-verifier
\\.
-- PostgreSQL database dump complete
"""
        gz_sql = base / "n8n.sql.gz"
        with gzip.open(gz_sql, "wt", encoding="utf-8") as f_sql:
            f_sql.write(pg_dump_sql)

        results = run_dr_drill(base)
        assert len(results) == 2
        by_name = {r.archive_name: r for r in results}
        assert by_name["sample.sqlite3.gz"].passed is True
        assert by_name["sample.sqlite3.gz"].total_rows == 1
        assert by_name["n8n.sql.gz"].passed is True
        assert by_name["n8n.sql.gz"].table_count == 1
        assert by_name["n8n.sql.gz"].total_rows == 2
        assert main(["dr-drill", "--backup-dir", str(base), "--max-size-mb", "64"]) == 0

        capped_res = verify_sqlite_archive(gz_db, max_uncompressed_bytes=128)
        assert capped_res.passed is False
        assert "exceeds safety ceiling" in capped_res.detail
