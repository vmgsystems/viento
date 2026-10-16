# VMG Viento (`v0.2.1`)

**Autonomous Infrastructure & Zero-Drag Operations — Maximum Net Velocity Toward the Mark.**

`VMG Viento` is the open-core diagnostic, benchmarking, and mechanical GitOps verification suite by **VMG Systems LLC** (`https://www.vmg.systems`), licensed under **Apache License 2.0**.

---

## Overview

In sailing and vector physics, **Velocity Made Good (VMG)** measures true net velocity directly toward the mark, stripping away leeway and drag. `VMG Viento` eliminates infrastructure drag across Kubernetes and hybrid-cloud environments through three open-source diagnostic engines and zero-trust policy baselines:

1. **`viento-lint` (`viento lint`):** Universal content-aware GitOps & Kubernetes zero-trust invariant linter enforcing pinned image tags (`DISALLOW_LATEST_TAG`), container CPU/memory requests and limits (`REQUIRE_RESOURCE_LIMITS`), non-privileged execution (`DISALLOW_PRIVILEGED_CONTAINERS`), SOPS secret encryption (`SOPS_ENCRYPTION`), Flagger Canary schema mutual exclusion, Traefik v3 metric regexes, PromQL zero-denominator guards (`PROMQL_ZERO_DENOMINATOR_GUARD`), SQLite online backup `.timeout 60000` guards, and live/configured PVC capacity shrink prevention (`PVC_CAPACITY_SHRINK_FORBIDDEN`) across any directory structure.
2. **`viento-bench` (`viento bench`):** Empirical, symmetric SQLite storage lock-contention benchmark measuring single-statement autocommit `INSERT` latency (`autocommit_insert_ms`), interleaved reader aggregations (`interleaved_query_ms`), and batched transactions (`batched_tx_ms`) between default rollback-journal (`DELETE`) mode and tuned NVMe `WAL` mode (`64 MiB` page cache + `256 MiB` `mmap`).
3. **`viento-dr-drill` (`viento dr-drill`):** Automated cold-archive decompression and integrity verification for both SQLite (`.sqlite3.gz`, `.db`) and PostgreSQL `pg_dump` (`.sql.gz`, `.sql`) backups with bounded streaming decompression (`--max-size-mb`) and virtual-table resilience.
4. **Zero-Trust Kyverno Policies (`policies/kyverno-zero-trust.yaml`):** Production `Enforce`-mode admission policies tuned for a `39 MiB` memory footprint.

---

## Quickstart

```bash
pip install -e .

# 1. Lint a GitOps repository and compute its 0.0-10.0 VMG Readiness Score
viento lint .

# 2. Benchmark SQLite DELETE journal vs tuned WAL mode on a target directory
viento bench --workdir /tmp/viento-bench --iterations 50

# 3. Verify cold SQLite & PostgreSQL backup archives (.sqlite3.gz / .db / .sql.gz)
viento dr-drill --backup-dir ./backups --max-size-mb 2048
```

---

## Open-Core (`Apache-2.0`) vs. Commercial Enterprise Boundary

| Capability / Module | Tier | License |
| :--- | :--- | :--- |
| `viento-lint` (GitOps & Kubernetes Zero-Trust Readiness Scorecard) | Open-Core | Apache-2.0 |
| `viento-bench` (SQLite Storage Lock-Contention Benchmark) | Open-Core | Apache-2.0 |
| `viento-dr-drill` (Cold Backup Decompression & Integrity Verifier) | Open-Core | Apache-2.0 |
| `kyverno-zero-trust.yaml` (39 MiB Admission-Only Kyverno Policies) | Open-Core | Apache-2.0 |
| Zero-Downtime Storage Cutover & Edge Router Dead-Man's Switch Automation | VMG Viento Deployment | Commercial |
| Hermes Closed-Loop AI SRE Engine (`/api/alerts/auto-triage` + K8s Sandbox) | VMG Viento Enterprise | Commercial |
| Managed 24/7 Overwatch & Signed Weekly DR Compliance Attestations | Viento Trim & Assurance | Commercial |

---

## Semantic Versioning (`SemVer 2.0.0`)

`VMG Viento` strictly follows **SemVer 2.0.0 (`MAJOR.MINOR.PATCH`)**:
* **`MAJOR` (`X.0.0`):** Breaking changes to `.viento.yaml` schema, CLI flags, or default-enabled blocking rule IDs.
* **`MINOR` (`0.Y.0`):** New opt-in linter rules, benchmark modes, or Helm/Kustomize manifest templates.
* **`PATCH` (`0.0.Z`):** Bug fixes, parser refinements, and dependency updates.
