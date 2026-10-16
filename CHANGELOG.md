# Changelog

All notable changes to `VMG Viento` follow [Semantic Versioning 2.0.0](https://semver.org/).

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
