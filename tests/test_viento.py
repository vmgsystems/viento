"""Comprehensive unit and behavioral test suite for VMG Viento Open-Core CLI."""

import gzip
import sqlite3
import tempfile
from pathlib import Path

import pytest

from viento import __version__
from viento.bench import run_sqlite_contention_benchmark
from viento.cli import main
from viento.dr_drill import run_dr_drill, verify_postgres_sql_archive, verify_sqlite_archive
from viento.linter import InvariantLinter


def test_viento_semver_version_and_single_source_sync():
    repo_root = Path(__file__).resolve().parents[1]
    version_file = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    pyproject_text = (repo_root / "pyproject.toml").read_text(encoding="utf-8")
    readme_text = (repo_root / "README.md").read_text(encoding="utf-8")

    assert __version__ == "0.2.3"
    assert version_file == __version__
    assert f'version = "{__version__}"' in pyproject_text
    assert f"(`v{__version__}`)" in readme_text
    assert main(["version"]) == 0


def test_viento_self_lint_clean():
    repo_root = Path(__file__).resolve().parents[1]
    linter = InvariantLinter(repo_root)
    violations = linter.run()
    assert violations == [], f"Unexpected violations: {[str(v) for v in violations]}"


def test_viento_kyverno_policy_parity_with_linter():
    repo_root = Path(__file__).resolve().parents[1]
    kyverno_text = (repo_root / "policies" / "kyverno-zero-trust.yaml").read_text(encoding="utf-8")
    assert "require-image-tag-or-digest" in kyverno_text
    assert 'image: "*:* | *@*"' in kyverno_text
    assert "requests:" in kyverno_text
    assert "limits:" in kyverno_text


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
          image: registry.internal:5000/acme/api:1.4.2
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
        - name: untagged-port-registry
          image: registry.internal:5000/acme/untagged-service
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 64Mi
""",
            encoding="utf-8",
        )
        violations = linter.run()
        rules = {v.rule for v in violations}
        assert "DISALLOW_LATEST_TAG" in rules
        assert "REQUIRE_RESOURCE_LIMITS" in rules
        assert "DISALLOW_PRIVILEGED_CONTAINERS" in rules
        latest_msgs = [v.message for v in violations if v.rule == "DISALLOW_LATEST_TAG"]
        assert any("registry.internal:5000/acme/untagged-service" in m for m in latest_msgs)


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


def test_viento_linter_adversarial_hardening_regressions():
    """Covers >8 KiB preamble comment padding, root .sops.yaml exclusion, multi-doc & key-level SOPS smuggling,
    uppercase :LATEST / malformed @sha256 digests, null/empty resource limits, string-quoted privilege,
    glob privileged_allowlist across initContainers, and multiline PromQL rate division without > 0."""
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "README.md").write_text("# Adversarial Test Repo\n", encoding="utf-8")
        # Root .sops.yaml creation rules config must NOT be flagged as an unencrypted secret
        (root / ".sops.yaml").write_text(
            """creation_rules:
  - path_regex: .*\\.sops\\.ya?ml$
    encrypted_regex: '^(data|stringData)$'
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
""",
            encoding="utf-8",
        )
        (root / ".viento.yaml").write_text(
            """privileged_allowlist:
  - "*-dind-runner*"
""",
            encoding="utf-8",
        )
        k8s_dir = root / "manifests"
        k8s_dir.mkdir()

        # 1. >8 KiB comment preamble before a violating Deployment
        preamble = "# " + ("A" * 9000) + "\n"
        (k8s_dir / "padded_deployment.yaml").write_text(
            preamble
            + """apiVersion: apps/v1
kind: Deployment
metadata:
  name: padded-evasion
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:LATEST
          resources:
            requests:
              cpu: 10m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 64Mi
""",
            encoding="utf-8",
        )

        # 2. Multi-document .sops.yaml + key-level plaintext smuggling inside a Secret with sops.mac
        (k8s_dir / "smuggled.sops.yaml").write_text(
            """apiVersion: v1
kind: Secret
metadata:
  name: partially-encrypted-secret
data:
  token: ENC[AES256_GCM,data:aaaa,iv:bbbb,tag:cccc,type:str]
stringData:
  leaked_key: cleartext-secret-value
sops:
  mac: ENC[AES256_GCM,data:xxxx,iv:yyyy,tag:zzzz,type:str]
---
apiVersion: v1
kind: Secret
metadata:
  name: smuggled-plaintext-secret
stringData:
  password: cleartext-value
""",
            encoding="utf-8",
        )

        # 3. ephemeralContainers with malformed @sha256 digest and string "true" privileged
        (k8s_dir / "ephemeral_pod.yaml").write_text(
            """apiVersion: v1
kind: Pod
metadata:
  name: debug-pod
spec:
  containers:
    - name: main
      image: alpine:3.20
      resources:
        requests:
          cpu: ""
          memory: null
        limits:
          cpu: 100m
          memory: 64Mi
  ephemeralContainers:
    - name: debugger
      image: busybox@sha256:bad
      securityContext:
        privileged: "true"
""",
            encoding="utf-8",
        )

        # 4. Allowlisted *-dind-runner* with privileged initContainer must NOT be flagged
        (k8s_dir / "allowed_runner.yaml").write_text(
            """apiVersion: apps/v1
kind: Deployment
metadata:
  name: ci-dind-runner
spec:
  template:
    spec:
      initContainers:
        - name: init-dind
          image: docker:27.1.1-dind
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 256Mi
      containers:
        - name: runner
          image: docker:27.1.1-dind
          securityContext:
            privileged: true
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

        # 5. Multiline / unparenthesized PromQL rate division lacking > 0
        (k8s_dir / "unparenthesized_metric.yaml").write_text(
            """apiVersion: flagger.app/v1beta1
kind: MetricTemplate
metadata:
  name: multiline-metric
spec:
  query: |
    sum(rate(traefik_service_requests_total{service=~".*{{ target }}.*", code!~"5.*"}[1m]))
    /
    sum(rate(traefik_service_requests_total{service=~".*{{ target }}.*"}[1m])) * 100
""",
            encoding="utf-8",
        )

        linter = InvariantLinter(root)
        violations = linter.run()
        by_file_and_rule = {(Path(v.file_path).name, v.rule) for v in violations}

        assert (".sops.yaml", "SOPS_ENCRYPTION") not in by_file_and_rule
        assert ("allowed_runner.yaml", "DISALLOW_PRIVILEGED_CONTAINERS") not in by_file_and_rule
        assert ("padded_deployment.yaml", "DISALLOW_LATEST_TAG") in by_file_and_rule
        assert ("smuggled.sops.yaml", "SOPS_ENCRYPTION") in by_file_and_rule
        sops_msgs = [v.message for v in violations if Path(v.file_path).name == "smuggled.sops.yaml"]
        assert any("stringData.leaked_key" in m for m in sops_msgs)
        assert any("smuggled-plaintext-secret" in m for m in sops_msgs)
        assert ("ephemeral_pod.yaml", "DISALLOW_LATEST_TAG") in by_file_and_rule
        assert ("ephemeral_pod.yaml", "DISALLOW_PRIVILEGED_CONTAINERS") in by_file_and_rule
        assert ("ephemeral_pod.yaml", "REQUIRE_RESOURCE_LIMITS") in by_file_and_rule
        assert ("unparenthesized_metric.yaml", "PROMQL_ZERO_DENOMINATOR_GUARD") in by_file_and_rule


def test_viento_bench_symmetric_methodology():
    with pytest.raises(ValueError, match="iterations must be >= 1"):
        run_sqlite_contention_benchmark(iterations=0)

    report = run_sqlite_contention_benchmark(iterations=40)
    assert report["methodology"] == "symmetric-autocommit-and-batched"
    assert report["iterations"] == 40
    for key in ("autocommit_insert_ms", "interleaved_query_ms", "batched_tx_ms", "concurrent_rw_ms", "total_ms"):
        assert report["wal_tuned"][key] >= 0
        assert report["delete_default"][key] >= 0
    assert report["speedup_factor"] > 0
    assert report["autocommit_speedup_factor"] > 0
    assert report["concurrent_rw_speedup_factor"] > 0


def test_viento_dr_drill_sqlite_postgres_and_safety_ceiling():
    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)

        raw_db = base / "sample.sqlite3"
        conn = sqlite3.connect(str(raw_db))
        conn.execute("CREATE TABLE monitors (id INTEGER PRIMARY KEY, name TEXT);")
        conn.execute("INSERT INTO monitors (name) VALUES ('api-gateway');")
        conn.commit()
        conn.close()

        # Verify uncompressed .sqlite3 exceeding max_uncompressed_bytes fails prior to copy
        uncompressed_capped = verify_sqlite_archive(raw_db, max_uncompressed_bytes=128)
        assert uncompressed_capped.passed is False
        assert "exceeds safety ceiling" in uncompressed_capped.detail

        gz_db = base / "sample.sqlite3.gz"
        with open(raw_db, "rb") as f_in, gzip.open(gz_db, "wb") as f_out:
            f_out.write(f_in.read())
        raw_db.unlink()

        # Include a row starting with \.env to verify COPY block does not terminate prematurely
        pg_dump_sql = """-- PostgreSQL database dump
CREATE TABLE public.workflows (
    id integer NOT NULL,
    name text NOT NULL
);
COPY public.workflows (id, name) FROM stdin;
\\.env\talert-triage
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

        # Truncated COPY block containing \.prefix row without real \. terminator must fail as truncated_copy
        truncated_copy_prefix = base / "truncated_copy_prefix.sql"
        truncated_copy_prefix.write_text(
            """-- PostgreSQL database dump
CREATE TABLE public.workflows (id integer NOT NULL, name text NOT NULL);
COPY public.workflows (id, name) FROM stdin;
\\.env\tspoofed-row-not-terminator
""",
            encoding="utf-8",
        )
        trunc_prefix_res = verify_postgres_sql_archive(truncated_copy_prefix)
        assert trunc_prefix_res.passed is False
        assert trunc_prefix_res.integrity_status == "truncated_copy"

        truncated_sql = base / "truncated_between_tables.sql"
        truncated_sql.write_text(
            """-- PostgreSQL database dump
CREATE TABLE public.workflows (id integer NOT NULL, name text NOT NULL);
COPY public.workflows (id, name) FROM stdin;
1\talert-triage
\\.
""",
            encoding="utf-8",
        )
        trunc_res = verify_postgres_sql_archive(truncated_sql)
        assert trunc_res.passed is False
        assert trunc_res.integrity_status == "missing_completion_footer"

        # Verify early COMMIT; in a truncated pg_dump file does not spoof completion footer
        early_commit_sql = base / "truncated_early_commit.sql"
        early_commit_sql.write_text(
            """-- PostgreSQL database dump
BEGIN;
CREATE TABLE public.workflows (id integer NOT NULL, name text NOT NULL);
INSERT INTO public.workflows VALUES (1, 'alert-triage');
COMMIT;
-- Mid-stream connection reset before final dump footer
""",
            encoding="utf-8",
        )
        early_commit_res = verify_postgres_sql_archive(early_commit_sql)
        assert early_commit_res.passed is False
        assert early_commit_res.integrity_status == "missing_completion_footer"
