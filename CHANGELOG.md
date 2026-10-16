# Changelog

All notable changes to `VMG Viento` follow [Semantic Versioning 2.0.0](https://semver.org/).

## [v0.1.0] - 2026-10-16

### Added
- **`viento-lint`:** Mechanical GitOps and Kubernetes zero-trust invariant linter with `0.0-10.0` VMG Readiness Scorecard (`DISALLOW_LATEST_TAG`, `REQUIRE_RESOURCE_LIMITS`, `SOPS_ENCRYPTION`, `PROMQL_ZERO_DENOMINATOR_GUARD`, `SQLITE_BACKUP_TIMEOUT_GUARD`, `PVC_CAPACITY_SHRINK_FORBIDDEN`).
- **`viento-bench`:** Empirical SQLite storage lock-contention benchmark comparing `DELETE` rollback-journal mode vs tuned `WAL` (`cache_size = -64000`, `mmap_size = 268435456`, `busy_timeout = 30000`).
- **`viento-dr-drill`:** Cold-archive `.sqlite3.gz` decompression and `PRAGMA integrity_check` verification runner.
- **`policies/kyverno-zero-trust.yaml`:** Production `Enforce`-mode Kyverno `ClusterPolicy` manifests (`disallow-latest-tag`, `require-resource-limits`, `disallow-privileged-containers`).
