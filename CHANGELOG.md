# Changelog

All notable changes to `VMG Viento` follow [Semantic Versioning 2.0.0](https://semver.org/).

## [v0.2.2] - 2026-10-16

### Security & Adversarial Hardening
- **Expanded Kubernetes YAML Candidate Preamble Scan Window (`viento lint`):** Increased `is_candidate_k8s_yaml` header inspection window from `8 KiB` to `1 MiB` (`1,048,576` bytes) to prevent comment-padding evasion before `apiVersion:` and `kind:` declarations.
- **Per-Document SOPS MAC Verification (`viento lint`):** Enforced per-document `sops.mac` verification across multi-document YAML streams (`---`) in `SOPS_ENCRYPTION` so plaintext `Secret` manifests cannot be smuggled alongside an encrypted document.
- **Ephemeral Container Security & Entrypoint Hygiene (`viento lint`):** Added `ephemeralContainers` inspection for `DISALLOW_LATEST_TAG`, `DISALLOW_PRIVILEGED_CONTAINERS`, and entrypoint command hygiene, achieving full parity with `policies/kyverno-zero-trust.yaml`.
- **Generalized PromQL Zero-Denominator Guard (`viento lint`):** Upgraded `PROMQL_ZERO_DENOMINATOR_GUARD` detection via regex (`/\s*\(?\s*(?:sum\s*\(\s*)?rate\s*\(`) to catch multiline and unparenthesized rate divisions lacking `> 0`.
- **Truncated `pg_dump` Early-`COMMIT;` Latch & Uncompressed Ceiling Guards (`viento dr-drill`):** Hardened `verify_postgres_sql_archive` against early `COMMIT;` latch spoofing on truncated `pg_dump` streams and enforced `max_uncompressed_bytes` prior to copying uncompressed `.sqlite3`, `.db`, and `.sql` archives.
- **Multi-Threaded Concurrent Contention Phase & Boundary Validation (`viento bench` / `viento dr-drill`):** Added Phase 4 true multi-threaded concurrent reader + writer lock contention benchmarking (`concurrent_rw_ms` with `threading.Barrier(2)`) and strict boundary validation (`iterations >= 1`, `max_size_mb >= 1`).

## [v0.2.1] - 2026-10-16

### Fixed & Changed
- **Registry Port-Aware Image Tag Pinning (`viento lint`):** `DISALLOW_LATEST_TAG` now inspects the image reference path after the last `/` so untagged images hosted on custom-port registries (`host:port/repo`) are accurately flagged instead of treating `:port` as an image tag.
- **Strict PostgreSQL `pg_dump` Completion Footer Verification (`viento dr-drill`):** Requires a valid `PostgreSQL database dump complete` footer (`missing_completion_footer` detection) so mid-stream truncated SQL dumps are rejected even when earlier DDL/DML headers are present.
- **1:1 Kyverno `ClusterPolicy` Parity (`policies/kyverno-zero-trust.yaml`):** Added `require-image-tag-or-digest` (`image: "*:* | *@*"`) to `disallow-latest-tag` to block untagged images at the API server boundary, and updated `require-resource-limits` (`check-resources`) to enforce both CPU and memory `requests` and `limits` across `containers` and `initContainers`.
- **Single-Source SemVer Synchronization & Native `pytest` Configuration:** Synchronized `0.2.1` across `VERSION`, `pyproject.toml`, `viento.__version__`, and `README.md`, and configured `[tool.pytest.ini_options]` with `pythonpath = ["src"]` and `testpaths = ["tests"]` for out-of-the-box test execution.

## [v0.2.0] - 2026-10-16

### Added
- **Universal Content-Aware Kubernetes YAML Discovery (`viento lint`):** Automatically detects and validates Kubernetes manifests (`Deployment`, `StatefulSet`, `DaemonSet`, `Job`, `CronJob`, `Pod`, `Secret`, `PersistentVolumeClaim`, `Canary`, `MetricTemplate`, `Provider`) across any directory (`clusters/`, `k8s/`, `manifests/`, `apps/`, `iac/k8s/`).
- **Symmetric Apples-to-Apples Contention Benchmark (`viento bench`):** Reports `autocommit_insert_ms`, `interleaved_query_ms`, and `batched_tx_ms` across identical SQL execution profiles in `DELETE_DEFAULT` and `WAL_TUNED` modes, plus PVC-backed Kubernetes benchmark Job template (`manifests/viento-bench-job.yaml`).
- **PostgreSQL Cold-Archive & Bounded Decompression Support (`viento dr-drill`):** Added `pg_dump` (`.sql.gz` / `.sql`) verification, `--max-size-mb` streaming decompression ceiling against gzip bombs, and virtual-table resilience.
- **Configurable `.viento.yaml` Schema & CLI Flags:** Added `pvc_capacity_floors`, `privileged_allowlist`, `decommissioned_tokens`, `--verify-flux-sync` CLI flag, and standard `KUBECONFIG` / `~/.kube/config` resolution with guaranteed temporary certificate file cleanup.

## [v0.1.0] - 2026-10-16

### Added
- **`viento-lint`:** Mechanical GitOps and Kubernetes zero-trust invariant linter with `0.0-10.0` VMG Readiness Scorecard (`DISALLOW_LATEST_TAG`, `REQUIRE_RESOURCE_LIMITS`, `SOPS_ENCRYPTION`, `PROMQL_ZERO_DENOMINATOR_GUARD`, `SQLITE_BACKUP_TIMEOUT_GUARD`, `PVC_CAPACITY_SHRINK_FORBIDDEN`).
- **`viento-bench`:** Empirical SQLite storage lock-contention benchmark comparing `DELETE` rollback-journal mode vs tuned `WAL` (`cache_size = -64000`, `mmap_size = 268435456`, `busy_timeout = 30000`).
- **`viento-dr-drill`:** Cold-archive `.sqlite3.gz` decompression and `PRAGMA integrity_check` verification runner.
- **`policies/kyverno-zero-trust.yaml`:** Production `Enforce`-mode Kyverno `ClusterPolicy` manifests (`disallow-latest-tag`, `require-resource-limits`, `disallow-privileged-containers`).
