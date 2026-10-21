#!/usr/bin/env python3
"""
viento.linter
Mechanical GitOps & Kubernetes Zero-Trust Invariant Linter (`viento lint`).
Enforces architectural invariants, Kubernetes zero-trust admission policies,
PromQL stability guards, SOPS secrets hygiene, PVC shrink protection, and
JavaScript/ESM syntax validity across any Kubernetes GitOps repository.
"""

import argparse
import base64
import fnmatch
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

SKIP_DIRS = {
    ".git", ".vscode", ".idea", "node_modules", "vendor",
    "__pycache__", ".pytest_cache", ".claude",
    ".playwright-mcp", "playwright-report", "test-results", "dist", "build",
    ".browsers", ".vercel", ".terraform", "scratch", ".venv", "venv"
}

TEXT_EXTENSIONS = {
    ".py", ".yaml", ".yml", ".json", ".sh", ".ps1", ".mjs", ".js", ".md", ".txt", ".conf", ".xml", ".ts"
}

SECRET_PATTERNS = [
    (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}"), "SLACK_TOKEN"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PRIVATE_KEY"),
    (re.compile(r"AIza[0-9A-Za-z-_]{35}"), "GOOGLE_API_KEY"),
    (re.compile(r"gh[pousr]_[0-9A-Za-z]{30,}"), "GITHUB_TOKEN"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
]

WORKLOAD_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"
}

K8S_RELEVANT_KINDS = WORKLOAD_KINDS | {
    "Namespace", "Service", "Secret", "PersistentVolumeClaim", "Canary", "MetricTemplate", "Provider"
}


class GitIgnoreResolver:
    """In-memory .gitignore pattern resolver ensuring mechanical checks respect ignore boundaries."""

    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.patterns: List[str] = []
        self.negations: List[str] = []
        self.load_gitignore()

    def load_gitignore(self):
        gitignore_path = self.repo_root / ".gitignore"
        if gitignore_path.exists():
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if line.startswith("!"):
                                self.negations.append(line[1:].strip("/"))
                            else:
                                self.patterns.append(line.strip("/"))
            except Exception:
                pass

    def is_ignored(self, path: Path) -> bool:
        try:
            rel_path = path.resolve().relative_to(self.repo_root)
        except ValueError:
            rel_path = path
        rel_posix = rel_path.as_posix()
        for part in rel_path.parts:
            if part in SKIP_DIRS:
                return True
        for neg in self.negations:
            if fnmatch.fnmatch(rel_path.name, neg) or fnmatch.fnmatch(rel_posix, neg):
                return False
        for part in rel_path.parts:
            for pat in self.patterns:
                if fnmatch.fnmatch(part, pat) or fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, f"{pat}/*"):
                    return True
        return False


class InvariantViolation:
    def __init__(self, file_path: str, rule: str, message: str, line_number: int = 0):
        self.file_path = file_path
        self.rule = rule
        self.message = message
        self.line_number = line_number

    def __str__(self):
        loc = f":{self.line_number}" if self.line_number else ""
        return f"[{self.rule}] {self.file_path}{loc} - {self.message}"


class InvariantLinter:
    def __init__(
        self,
        repo_root: Path,
        pvc_floors: Optional[Dict[str, str]] = None,
    ):
        self.repo_root = repo_root.resolve()
        self.violations: List[InvariantViolation] = []
        self.gitignore = GitIgnoreResolver(self.repo_root)
        self.config: Dict[str, Any] = self._load_viento_config()
        self._explicit_pvc_floors = pvc_floors or {}
        self._live_pvc_cache: Dict[str, Dict[str, Any]] = {}
        self._live_pvc_loaded: bool = False
        self._namespace_psa_enforce: Dict[str, Tuple[str, str]] = {}
        self._host_access_workloads: List[Tuple[str, str, str, List[str]]] = []
        self._service_selectors: List[Tuple[str, str, str, Dict[str, str]]] = []
        self._job_pod_labels: List[Tuple[str, str, str, Dict[str, str]]] = []

    def _load_viento_config(self) -> Dict[str, Any]:
        cfg_path = self.repo_root / ".viento.yaml"
        if cfg_path.exists() and yaml is not None:
            try:
                data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                pass
        return {}

    @staticmethod
    def parse_k8s_storage_bytes(val: Any) -> int:
        if not val:
            return 0
        s = str(val).strip()
        units = {
            "Ki": 1024,
            "Mi": 1024 ** 2,
            "Gi": 1024 ** 3,
            "Ti": 1024 ** 4,
            "K": 1000,
            "M": 1000 ** 2,
            "G": 1000 ** 3,
            "T": 1000 ** 4,
        }
        for suffix, mult in units.items():
            if s.endswith(suffix):
                try:
                    return int(float(s[:-len(suffix)]) * mult)
                except ValueError:
                    return 0
        try:
            return int(float(s))
        except ValueError:
            return 0

    def _resolve_kubeconfig_path(self) -> Optional[Path]:
        cfg_kc = self.config.get("kubeconfig")
        if cfg_kc:
            p = (self.repo_root / str(cfg_kc)).resolve()
            if p.exists():
                return p
        env_kc = os.environ.get("KUBECONFIG", "").split(os.pathsep)[0].strip()
        if env_kc:
            p = Path(env_kc).expanduser()
            if p.exists():
                return p
        default_kc = Path.home() / ".kube" / "config"
        if default_kc.exists():
            return default_kc
        return None

    def _with_k8s_ssl_context(self, kc_text: str):
        """Creates a temporary SSLContext from kubeconfig and guarantees temp-file cleanup."""
        server_m = re.search(r"server:\s*(\S+)", kc_text)
        ca_m = re.search(r"certificate-authority-data:\s*(\S+)", kc_text)
        cert_m = re.search(r"client-certificate-data:\s*(\S+)", kc_text)
        key_m = re.search(r"client-key-data:\s*(\S+)", kc_text)
        if not (server_m and ca_m and cert_m and key_m):
            return None, None, []

        server = server_m.group(1)
        temp_files: List[str] = []
        try:
            with tempfile.NamedTemporaryFile(delete=False) as ca_f, \
                 tempfile.NamedTemporaryFile(delete=False) as cert_f, \
                 tempfile.NamedTemporaryFile(delete=False) as key_f:
                temp_files.extend([ca_f.name, cert_f.name, key_f.name])
                ca_f.write(base64.b64decode(ca_m.group(1)))
                ca_f.flush()
                cert_f.write(base64.b64decode(cert_m.group(1)))
                cert_f.flush()
                key_f.write(base64.b64decode(key_m.group(1)))
                key_f.flush()
            ctx = ssl.create_default_context(cafile=temp_files[0])
            ctx.load_cert_chain(certfile=temp_files[1], keyfile=temp_files[2])
            return server, ctx, temp_files
        except Exception:
            for tf in temp_files:
                try:
                    os.unlink(tf)
                except OSError:
                    pass
            return None, None, []

    def _load_live_pvcs(self):
        if self._live_pvc_loaded:
            return
        self._live_pvc_loaded = True

        cfg_floors = self.config.get("pvc_capacity_floors") or {}
        merged_floors: Dict[str, str] = {}
        if isinstance(cfg_floors, dict):
            merged_floors.update({str(k): str(v) for k, v in cfg_floors.items()})
        merged_floors.update(self._explicit_pvc_floors)

        for pvc_key, floor_storage in merged_floors.items():
            self._live_pvc_cache[pvc_key] = {
                "storage": floor_storage,
                "bytes": self.parse_k8s_storage_bytes(floor_storage),
                "storageClassName": "static-baseline",
            }

        kubeconfig_path = self._resolve_kubeconfig_path()
        if not kubeconfig_path:
            return
        temp_files: List[str] = []
        try:
            kc_text = kubeconfig_path.read_text(encoding="utf-8")
            server, ctx, temp_files = self._with_k8s_ssl_context(kc_text)
            if not server or not ctx:
                return
            req = urllib.request.Request(f"{server}/api/v1/persistentvolumeclaims")
            with urllib.request.urlopen(req, context=ctx, timeout=2) as resp:
                items = json.loads(resp.read().decode("utf-8")).get("items", [])
                for item in items:
                    meta = item.get("metadata", {})
                    ns = meta.get("namespace", "default")
                    name = meta.get("name", "")
                    req_storage = item.get("spec", {}).get("resources", {}).get("requests", {}).get("storage", "")
                    sc = item.get("spec", {}).get("storageClassName", "")
                    self._live_pvc_cache[f"{ns}/{name}"] = {
                        "storage": req_storage,
                        "bytes": self.parse_k8s_storage_bytes(req_storage),
                        "storageClassName": sc,
                    }
        except Exception:
            pass
        finally:
            for tf in temp_files:
                try:
                    os.unlink(tf)
                except OSError:
                    pass

    def check_k8s_container_spec(
        self,
        container: Dict[str, Any],
        file_path: str,
        workload_name: str,
        is_ephemeral: bool = False,
    ):
        """Rule: DISALLOW_LATEST_TAG, REQUIRE_RESOURCE_LIMITS & DISALLOW_PRIVILEGED_CONTAINERS"""
        image = str(container.get("image") or "").strip()
        c_name = container.get("name", "unknown")

        if not image:
            self.violations.append(
                InvariantViolation(file_path, "DISALLOW_LATEST_TAG", f"Container '{c_name}' in '{workload_name}' missing image")
            )
        else:
            last_segment = image.rsplit("/", 1)[-1]
            lower_seg = last_segment.lower()
            has_valid_digest = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", last_segment))
            has_invalid_at = ("@" in last_segment) and not has_valid_digest
            if (
                lower_seg.endswith(":latest")
                or ":latest@" in lower_seg
                or last_segment.endswith((":", "@"))
                or has_invalid_at
                or ("@" not in last_segment and ":" not in last_segment)
            ):
                self.violations.append(
                    InvariantViolation(
                        file_path, "DISALLOW_LATEST_TAG",
                        f"Container '{c_name}' in '{workload_name}' uses floating or unpinned image tag: '{image}'"
                    )
                )

        if not is_ephemeral:
            resources = container.get("resources")
            if not isinstance(resources, dict) or not resources:
                self.violations.append(
                    InvariantViolation(
                        file_path, "REQUIRE_RESOURCE_LIMITS",
                        f"Container '{c_name}' in '{workload_name}' missing 'resources' spec"
                    )
                )
            else:
                requests = resources.get("requests") if isinstance(resources.get("requests"), dict) else {}
                limits = resources.get("limits") if isinstance(resources.get("limits"), dict) else {}
                for metric in ("cpu", "memory"):
                    req_val = requests.get(metric)
                    if req_val is None or str(req_val).strip() == "":
                        self.violations.append(
                            InvariantViolation(
                                file_path, "REQUIRE_RESOURCE_LIMITS",
                                f"Container '{c_name}' in '{workload_name}' missing resources.requests.{metric}"
                            )
                        )
                    lim_val = limits.get(metric)
                    if lim_val is None or str(lim_val).strip() == "":
                        self.violations.append(
                            InvariantViolation(
                                file_path, "REQUIRE_RESOURCE_LIMITS",
                                f"Container '{c_name}' in '{workload_name}' missing resources.limits.{metric}"
                            )
                        )

        base_workload = workload_name.split(" (", 1)[0]
        short_name = base_workload.split("/", 1)[-1]
        allowlist = set(self.config.get("privileged_allowlist") or [])
        is_allowed = any(
            fnmatch.fnmatch(workload_name, pat)
            or fnmatch.fnmatch(base_workload, pat)
            or fnmatch.fnmatch(short_name, pat)
            for pat in allowlist
        )
        if not is_allowed:
            sec_ctx = container.get("securityContext")
            if not isinstance(sec_ctx, dict):
                sec_ctx = {}
            priv = sec_ctx.get("privileged")
            allow_esc = sec_ctx.get("allowPrivilegeEscalation")
            if (
                priv is True
                or str(priv).strip().lower() == "true"
                or allow_esc is True
                or str(allow_esc).strip().lower() == "true"
            ):
                self.violations.append(
                    InvariantViolation(
                        file_path, "DISALLOW_PRIVILEGED_CONTAINERS",
                        f"Container '{c_name}' in '{workload_name}' sets privileged=true or allowPrivilegeEscalation=true"
                    )
                )

    def extract_pod_spec(self, doc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        kind = doc.get("kind", "")
        name = (doc.get("metadata") or {}).get("name", "unnamed")
        spec = doc.get("spec") or {}

        if kind == "Pod":
            return name, spec
        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
            template = spec.get("template") or {}
            return name, template.get("spec") or {}
        if kind == "CronJob":
            job_template = (spec.get("jobTemplate") or {}).get("spec") or {}
            template = job_template.get("template") or {}
            return name, template.get("spec") or {}
        return name, {}

    def check_plaintext_secrets(self, file_path: Path, content: Optional[str] = None):
        """Rule: PLAINTEXT_SECRET_DEFENSE - Scan non-SOPS text files for live secret signatures."""
        if file_path.name.endswith((".sops.yaml", ".sops.yml")):
            return
        if file_path.name in {"linter.py", "lint_invariants.py", "test_viento.py", "test_lint_invariants.py", "agent_pr_reviewer.py", "test_agent_pr_reviewer.py"}:
            return

        try:
            rel_path = str(file_path.resolve().relative_to(self.repo_root))
        except ValueError:
            rel_path = str(file_path)

        try:
            text = content if content is not None else file_path.read_text(encoding="utf-8", errors="ignore")
            matched_patterns = [
                (pattern, secret_type)
                for pattern, secret_type in SECRET_PATTERNS
                if pattern.search(text)
            ]
            if not matched_patterns:
                return
            for line_idx, line in enumerate(text.splitlines(), start=1):
                if "FIXTURE_ALLOW_SECRET" in line:
                    continue
                for pattern, secret_type in matched_patterns:
                    if pattern.search(line):
                        self.violations.append(
                            InvariantViolation(
                                file_path=rel_path,
                                rule="PLAINTEXT_SECRET_DEFENSE",
                                message=f"Live {secret_type} signature detected in plaintext file",
                                line_number=line_idx
                            )
                        )
        except Exception:
            pass

    @staticmethod
    def is_candidate_k8s_yaml(file_path: Path, content: Optional[str] = None) -> bool:
        """Determines whether a YAML file should be parsed for Kubernetes manifest invariants."""
        if file_path.name in {".viento.yaml", ".viento.yml", ".sops.yaml", ".sops.yml"}:
            return False
        if file_path.name.endswith((".sops.yaml", ".sops.yml")):
            return True
        if any(part in {".github", ".forgejo", "archive", "templates"} for part in file_path.parts):
            return False
        try:
            max_scan_bytes = 1024 * 1024
            if content is not None:
                text = content[:max_scan_bytes]
            else:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read(max_scan_bytes)
            return ("apiVersion:" in text and "kind:" in text)
        except Exception:
            return False

    def check_k8s_manifest(self, file_path: Path, content: Optional[str] = None):
        """Validates Kubernetes manifests for zero-trust admission invariants across any directory."""
        if file_path.name in {".viento.yaml", ".viento.yml", ".sops.yaml", ".sops.yml"}:
            return
        rel_path = str(file_path.relative_to(self.repo_root))
        if yaml is None:
            self.violations.append(
                InvariantViolation(rel_path, "YAML_DEPENDENCY_MISSING", "PyYAML is required to validate Kubernetes manifests")
            )
            return

        if content is None:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                return

        sops_violation_recorded = False
        if file_path.name.endswith((".sops.yaml", ".sops.yml")):
            if "sops:" not in content or "mac:" not in content:
                self.violations.append(
                    InvariantViolation(rel_path, "SOPS_ENCRYPTION", "SOPS secret file missing 'sops:' or 'mac:' encryption markers")
                )
                sops_violation_recorded = True

        try:
            docs = list(yaml.safe_load_all(content))
        except Exception as e:
            self.violations.append(
                InvariantViolation(rel_path, "YAML_SYNTAX", f"Failed to parse YAML: {e}")
            )
            return

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            if kind not in K8S_RELEVANT_KINDS:
                continue

            meta = doc.get("metadata") or {}
            name = meta.get("name", "unnamed")

            if kind == "Namespace":
                labels = meta.get("labels") or {}
                if isinstance(labels, dict):
                    psa_enforce = str(labels.get("pod-security.kubernetes.io/enforce") or "").strip().lower()
                    if psa_enforce in {"baseline", "restricted"} and name != "unnamed":
                        self._namespace_psa_enforce[name] = (psa_enforce, rel_path)

            if kind == "Service":
                svc_sel = (doc.get("spec") or {}).get("selector") or {}
                if isinstance(svc_sel, dict) and svc_sel:
                    ns_svc = str(meta.get("namespace") or "default").strip()
                    self._service_selectors.append(
                        (ns_svc, rel_path, name, {str(k): str(v) for k, v in svc_sel.items()})
                    )

            if kind in {"Job", "CronJob"}:
                ns_job = str(meta.get("namespace") or "default").strip()
                if kind == "Job":
                    tmpl_meta = (((doc.get("spec") or {}).get("template") or {}).get("metadata") or {})
                else:
                    tmpl_meta = (
                        ((((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("metadata")
                        or {}
                    )
                pod_lbls = tmpl_meta.get("labels") or {}
                if isinstance(pod_lbls, dict) and pod_lbls:
                    self._job_pod_labels.append(
                        (ns_job, rel_path, f"{kind}/{name}", {str(k): str(v) for k, v in pod_lbls.items()})
                    )

            if kind == "Secret":
                if not file_path.name.endswith((".sops.yaml", ".sops.yml")):
                    self.violations.append(
                        InvariantViolation(
                            rel_path, "SOPS_ENCRYPTION",
                            f"Kubernetes Secret '{name}' must be stored in encrypted .sops.yaml file"
                        )
                    )
                elif not sops_violation_recorded:
                    sops_meta = doc.get("sops")
                    if not isinstance(sops_meta, dict) or not str(sops_meta.get("mac") or "").startswith("ENC["):
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "SOPS_ENCRYPTION",
                                f"Kubernetes Secret '{name}' in SOPS file missing per-document 'sops.mac' encryption metadata"
                            )
                        )
                    for field_name in ("data", "stringData"):
                        sec_map = doc.get(field_name)
                        if isinstance(sec_map, dict):
                            for k, v in sec_map.items():
                                if not str(v or "").strip().startswith("ENC["):
                                    self.violations.append(
                                        InvariantViolation(
                                            rel_path, "SOPS_ENCRYPTION",
                                            f"Kubernetes Secret '{name}' key '{field_name}.{k}' in SOPS file is not encrypted with 'ENC[...]'"
                                        )
                                    )

            if kind in WORKLOAD_KINDS:
                w_name, pod_spec = self.extract_pod_spec(doc)
                containers = pod_spec.get("containers") or []
                init_containers = pod_spec.get("initContainers") or []
                ephemeral_containers = pod_spec.get("ephemeralContainers") or []
                for c in containers:
                    self.check_k8s_container_spec(c, rel_path, f"{kind}/{w_name}")
                for c in init_containers:
                    self.check_k8s_container_spec(c, rel_path, f"{kind}/{w_name} (init)")
                for c in ephemeral_containers:
                    self.check_k8s_container_spec(
                        c, rel_path, f"{kind}/{w_name} (ephemeral)", is_ephemeral=True
                    )

                ns = str(meta.get("namespace") or "default").strip()
                host_reasons: List[str] = []
                vols = pod_spec.get("volumes") or []
                hostpath_vols = [str(v.get("name", "vol")) for v in vols if isinstance(v, dict) and v.get("hostPath")]
                if hostpath_vols:
                    host_reasons.append(f"hostPath volumes ({', '.join(hostpath_vols)})")
                all_c_ports = [
                    p.get("hostPort")
                    for c in (containers + init_containers + ephemeral_containers)
                    if isinstance(c, dict)
                    for p in (c.get("ports") or [])
                    if isinstance(p, dict) and p.get("hostPort")
                ]
                if all_c_ports:
                    host_reasons.append(f"hostPort ({', '.join(str(hp) for hp in all_c_ports)})")
                for host_flag in ("hostNetwork", "hostPID", "hostIPC"):
                    if pod_spec.get(host_flag) is True or str(pod_spec.get(host_flag)).strip().lower() == "true":
                        host_reasons.append(f"{host_flag}=true")
                if host_reasons:
                    self._host_access_workloads.append((ns, rel_path, f"{kind}/{w_name}", host_reasons))

                all_c = containers + init_containers + ephemeral_containers
                for c in all_c:
                    cmd_list = (c.get("command") or []) + (c.get("args") or [])
                    cmd_str = " ".join(str(item) for item in cmd_list)
                    if "sqlite3" in cmd_str and re.search(r"(?:^|[\s\x22\x27])\.(?:backup|dump)\b", cmd_str):
                        if ".timeout 60000" not in cmd_str:
                            self.violations.append(
                                InvariantViolation(
                                    rel_path, "SQLITE_BACKUP_TIMEOUT_GUARD",
                                    f"Container '{c.get('name')}' in '{kind}/{w_name}' executes sqlite3 backup without '-cmd \".timeout 60000\"'"
                                )
                            )
                    if "sed -i" in cmd_str and ("INSERT INTO " in cmd_str or "INSERT OR IGNORE INTO " in cmd_str or '["' in cmd_str):
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "K8S_ENTRYPOINT_CODE_PATCH_FORBIDDEN",
                                f"Container '{c.get('name')}' in '{kind}/{w_name}' injects SQL INSERT or nested JSON quotes into source files via sed -i at startup"
                            )
                        )

            if kind == "Canary":
                analysis = (doc.get("spec") or {}).get("analysis") or {}
                has_iterations = "iterations" in analysis
                has_weights = "stepWeight" in analysis or "maxWeight" in analysis
                if has_iterations and has_weights:
                    self.violations.append(
                        InvariantViolation(
                            rel_path, "FLAGGER_SCHEMA_MUTUAL_EXCLUSION",
                            f"Canary '{name}' combines 'iterations' with 'stepWeight'/'maxWeight'. Must use one or the other."
                        )
                    )

            if kind == "MetricTemplate":
                query = (doc.get("spec") or {}).get("query", "")
                if "traefik_service_requests" in query:
                    if 'service=~"{{ target }}' in query and '.*{{ target }}' not in query:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "TRAEFIK_METRIC_REGEX",
                                f"MetricTemplate '{name}' query uses prefix match. Traefik v3 requires wildcard: '.*{{{{ target }}}}.*'"
                            )
                        )
                if "/" in query and "rate(" in query:
                    if re.search(r"/\s*\(?\s*(?:sum\s*\(\s*)?rate\s*\(", query) and "> 0" not in query:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "PROMQL_ZERO_DENOMINATOR_GUARD",
                                f"MetricTemplate '{name}' contains rate division without zero-denominator guard '> 0'"
                            )
                        )

            if kind == "Provider" and "notification.toolkit.fluxcd.io" in str(doc.get("apiVersion", "")):
                p_type = (doc.get("spec") or {}).get("type", "")
                p_addr = (doc.get("spec") or {}).get("address", "")
                if p_type == "alertmanager" and "/api/v2/alerts" not in p_addr:
                    self.violations.append(
                        InvariantViolation(
                            rel_path, "FLUX_PROVIDER_ENDPOINT",
                            f"Flux Alertmanager Provider '{name}' address '{p_addr}' missing '/api/v2/alerts/' endpoint path (causes HTTP 405)"
                        )
                    )

            if kind == "PersistentVolumeClaim":
                self._load_live_pvcs()
                ns = meta.get("namespace", "default")
                key = f"{ns}/{name}"
                if key in self._live_pvc_cache:
                    live_pvc = self._live_pvc_cache[key]
                    manifest_storage = ((doc.get("spec") or {}).get("resources") or {}).get("requests", {}).get("storage", "")
                    manifest_bytes = self.parse_k8s_storage_bytes(manifest_storage)
                    if manifest_bytes > 0 and live_pvc["bytes"] > 0 and manifest_bytes < live_pvc["bytes"]:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "PVC_CAPACITY_SHRINK_FORBIDDEN",
                                f"PVC '{key}' requests '{manifest_storage}', which is smaller than baseline/live PVC capacity '{live_pvc['storage']}'"
                            )
                        )

    def check_opnsense_config(self, file_path: Path):
        """Rule: OPNSENSE_ALIAS_HIERARCHY - Aliases must be under <Firewall><Alias><aliases>."""
        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            if root.findall("./aliases"):
                self.violations.append(
                    InvariantViolation(
                        rel_path, "OPNSENSE_ALIAS_HIERARCHY",
                        "OPNsense config contains deprecated root-level <aliases>. Must be nested inside <Firewall><Alias><aliases>."
                    )
                )
        except Exception:
            pass

    def check_wrapper_duplication(self, file_path: Path):
        """Rule: NO_INLINE_SOURCE_DUPLICATION - Wrapper scripts must remain concise (<600 lines)."""
        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            line_count = len(content.splitlines())
            if line_count > 600:
                self.violations.append(
                    InvariantViolation(
                        rel_path, "NO_INLINE_SOURCE_DUPLICATION",
                        f"Wrapper script ({line_count} lines) exceeds 600-line modular wrapper ceiling"
                    )
                )
        except Exception:
            pass

    def check_node_syntax(self, file_path: Path):
        """Rule: NODE_JS_SYNTAX_CHECK - Validate JavaScript/ESM syntax via node --check."""
        node_bin = shutil.which("node")
        if not node_bin:
            return
        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            proc = subprocess.run([node_bin, "--check", str(file_path)], capture_output=True, text=True, timeout=10)
            if proc.returncode != 0:
                err_msg = (proc.stderr or proc.stdout or "Syntax error").strip().splitlines()[0]
                self.violations.append(
                    InvariantViolation(
                        rel_path, "NODE_JS_SYNTAX_CHECK",
                        f"JavaScript syntax check failed: {err_msg}"
                    )
                )
        except Exception:
            pass

    def check_documentation_decommissioned_resources(self, file_path: Path, content: Optional[str] = None):
        """Rule: DECOMMISSIONED_RESOURCE_LEAK - Optional via .viento.yaml decommissioned_tokens."""
        tokens = self.config.get("decommissioned_tokens") or []
        if not tokens or not isinstance(tokens, list):
            return
        rel_path = str(file_path.relative_to(self.repo_root))
        qualifiers = {
            "decommission", "decommissioned", "destroy", "destroyed", "retire", "retired",
            "migrated", "legacy", "former", "historical", "past", "reclaim", "reclaimed",
            "purged", "stopped", "deprecated", "timeline", "completed"
        }
        try:
            text = content if content is not None else file_path.read_text(encoding="utf-8", errors="ignore")
            for line_idx, line in enumerate(text.splitlines(), start=1):
                lower = line.lower()
                for tok in tokens:
                    tok_str = str(tok).lower()
                    if tok_str and tok_str in lower and not any(q in lower for q in qualifiers):
                        self.violations.append(
                            InvariantViolation(
                                file_path=rel_path,
                                rule="DECOMMISSIONED_RESOURCE_LEAK",
                                message=f"Referencing decommissioned resource '{tok}' without decommissioning qualifier",
                                line_number=line_idx
                            )
                        )
        except Exception:
            pass

    def check_readme_coverage(self):
        """Rule: README_COVERAGE - Ensure README.md exists and satisfies optional .viento.yaml anchors."""
        readme_path = self.repo_root / "README.md"
        if not (self.repo_root / ".git").exists() and not readme_path.exists() and not self.config:
            return

        if not readme_path.exists():
            self.violations.append(
                InvariantViolation("README.md", "README_COVERAGE", "Master README.md missing from repository root")
            )
            return

        content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
        required_anchors: List[Tuple[str, str]] = []
        if "readme_required_anchors" in self.config and isinstance(self.config["readme_required_anchors"], list):
            for item in self.config["readme_required_anchors"]:
                if isinstance(item, dict) and "token" in item:
                    tok = str(item["token"]).lower()
                    required_anchors.append((tok, str(item.get("description", tok))))
                elif isinstance(item, str):
                    required_anchors.append((item.lower(), item))

        missing = [desc for token, desc in required_anchors if token not in content]
        if missing:
            self.violations.append(
                InvariantViolation(
                    "README.md", "README_COVERAGE",
                    f"README.md missing documentation for: {', '.join(missing)}"
                )
            )

    def check_psa_namespace_conflicts(self):
        """Rule: PSA_BASELINE_HOSTPATH_CONFLICT - Workloads using hostPath/hostPort cannot run in baseline/restricted PSA namespaces."""
        for ns, rel_path, workload_id, reasons in self._host_access_workloads:
            if ns in self._namespace_psa_enforce:
                psa_level, ns_file = self._namespace_psa_enforce[ns]
                self.violations.append(
                    InvariantViolation(
                        rel_path,
                        "PSA_BASELINE_HOSTPATH_CONFLICT",
                        f"Workload '{workload_id}' in namespace '{ns}' uses {'; '.join(reasons)}, which violates PodSecurity '{psa_level}' enforced on Namespace '{ns}' ({ns_file})",
                    )
                )

    def check_job_service_selector_collisions(self):
        """Rule: CRONJOB_SERVICE_SELECTOR_COLLISION - Batch Job/CronJob pod labels must not match a live Service selector."""
        for job_ns, job_file, job_id, pod_labels in self._job_pod_labels:
            for svc_ns, svc_file, svc_name, selector in self._service_selectors:
                if job_ns == svc_ns and all(pod_labels.get(k) == v for k, v in selector.items()):
                    self.violations.append(
                        InvariantViolation(
                            job_file,
                            "CRONJOB_SERVICE_SELECTOR_COLLISION",
                            f"{job_id} in namespace '{job_ns}' has pod template labels matching Service/{svc_name} selector {selector} ({svc_file}), routing Service traffic into batch Job pods",
                        )
                    )

    def run(self, target_dir: Path = None) -> List[InvariantViolation]:
        self.violations.clear()
        self._namespace_psa_enforce.clear()
        self._host_access_workloads.clear()
        self._service_selectors.clear()
        self._job_pod_labels.clear()
        base = (target_dir or self.repo_root).resolve()

        for root, dirs, files in os.walk(base):
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not self.gitignore.is_ignored(Path(root) / d)
            ]
            for file in files:
                p = Path(root) / file
                if self.gitignore.is_ignored(p):
                    continue
                ext = p.suffix.lower()
                posix_path = p.as_posix()

                content: Optional[str] = None
                if ext in TEXT_EXTENSIONS or file in {"Dockerfile", "Makefile"}:
                    try:
                        content = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        content = None
                    self.check_plaintext_secrets(p, content=content)

                if ext in {".md", ".py", ".sh", ".ts", ".yaml", ".yml"}:
                    self.check_documentation_decommissioned_resources(p, content=content)

                if ext in {".yaml", ".yml"} and self.is_candidate_k8s_yaml(p, content=content):
                    self.check_k8s_manifest(p, content=content)

                if file.endswith(".xml") and "opnsense" in posix_path.lower():
                    self.check_opnsense_config(p)

                if ext in {".ps1", ".sh"} and "scripts" in p.parts:
                    self.check_wrapper_duplication(p)

                if ext in {".mjs", ".js"}:
                    self.check_node_syntax(p)

        self.check_psa_namespace_conflicts()
        self.check_job_service_selector_collisions()
        self.check_readme_coverage()
        return self.violations

    def check_flux_kustomization_readiness(self) -> List[InvariantViolation]:
        """Verifies live FluxCD Kustomizations report Ready=True."""
        flux_violations: List[InvariantViolation] = []
        kubeconfig_path = self._resolve_kubeconfig_path()
        if not kubeconfig_path:
            return flux_violations
        temp_files: List[str] = []
        try:
            kc_text = kubeconfig_path.read_text(encoding="utf-8")
            server, ctx, temp_files = self._with_k8s_ssl_context(kc_text)
            if not server or not ctx:
                return flux_violations

            items = []
            for attempt in range(4):
                req = urllib.request.Request(f"{server}/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations")
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    items = json.loads(resp.read().decode("utf-8")).get("items", [])
                if any(
                    next((c for c in ks.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {}).get("reason")
                    in {"Progressing", "DependencyNotReady"}
                    for ks in items
                ) and attempt < 3:
                    time.sleep(2)
                    continue
                break
            for ks in items:
                name = ks.get("metadata", {}).get("name", "unknown")
                conds = ks.get("status", {}).get("conditions", [])
                ready = next((c for c in conds if c.get("type") == "Ready"), {})
                if ready.get("status") != "True":
                    flux_violations.append(
                        InvariantViolation(
                            f"flux-system/Kustomization/{name}",
                            "FLUX_RECONCILIATION_FAILED",
                            f"Kustomization '{name}' Ready={ready.get('status')} ({ready.get('reason')}): {ready.get('message')}"
                        )
                    )
        except Exception:
            pass
        finally:
            for tf in temp_files:
                try:
                    os.unlink(tf)
                except OSError:
                    pass
        return flux_violations
