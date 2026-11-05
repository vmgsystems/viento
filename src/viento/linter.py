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

EMOJI_REGEX = re.compile(
    r"[\U0001F600-\U0001F64F"
    r"\U0001F300-\U0001F5FF"
    r"\U0001F680-\U0001F6FF"
    r"\U0001F1E0-\U0001F1FF"
    r"\U00002702-\U000027B0"
    r"\U0001F900-\U0001F9FF"
    r"\U0001FA70-\U0001FAFF]"
)

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
        enforce_zero_emoji: bool = False,
    ):
        self.repo_root = repo_root.resolve()
        self.violations: List[InvariantViolation] = []
        self.gitignore = GitIgnoreResolver(self.repo_root)
        self.config: Dict[str, Any] = self._load_viento_config()
        self.enforce_zero_emoji: bool = bool(enforce_zero_emoji or self.config.get("enforce_zero_emoji", False))
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

    def check_emojis(self, file_path: Path, content: Optional[str] = None):
        """Rule: ZERO_EMOJI - Opt-in via .viento.yaml enforce_zero_emoji or --enforce-zero-emoji."""
        if not self.enforce_zero_emoji:
            return
        if file_path.name in {"linter.py", "lint_invariants.py", "test_viento.py", "test_lint_invariants.py"}:
            return

        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            text = content if content is not None else file_path.read_text(encoding="utf-8", errors="ignore")
            if not EMOJI_REGEX.search(text):
                return
            for line_idx, line in enumerate(text.splitlines(), start=1):
                if "FIXTURE_ALLOW_EMOJI" in line:
                    continue
                match = EMOJI_REGEX.search(line)
                if match:
                    char = match.group(0)
                    self.violations.append(
                        InvariantViolation(
                            file_path=rel_path,
                            rule="ZERO_EMOJI",
                            message=f"Disallowed emoji detected (U+{ord(char):04X})",
                            line_number=line_idx
                        )
                    )
        except Exception:
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
                all_c = containers + init_containers + ephemeral_containers
                all_c_ports = [
                    p.get("hostPort")
                    for c in all_c
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
                    self.check_emojis(p, content=content)
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

    @staticmethod
    def _deep_merge_dict(base_dict: Dict[str, Any], patch_dict: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in patch_dict.items():
            if isinstance(v, dict) and isinstance(base_dict.get(k), dict):
                InvariantLinter._deep_merge_dict(base_dict[k], v)
            elif isinstance(v, list) and isinstance(base_dict.get(k), list) and k in {"containers", "initContainers", "ephemeralContainers"}:
                by_name = {c.get("name"): c for c in base_dict[k] if isinstance(c, dict) and c.get("name")}
                for item in v:
                    if isinstance(item, dict) and item.get("name") in by_name:
                        InvariantLinter._deep_merge_dict(by_name[item["name"]], item)
                    else:
                        base_dict[k].append(item)
            else:
                base_dict[k] = v
        return base_dict

    def render_kustomize_overlay(self, kustomize_dir: Path) -> str:
        """Renders a Kustomize overlay directory using kustomize/kubectl or native Python YAML assembly."""
        for cmd in (["kustomize", "build", str(kustomize_dir)], ["kubectl", "kustomize", str(kustomize_dir)]):
            if shutil.which(cmd[0]):
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15, check=False)
                    if proc.returncode == 0 and proc.stdout.strip():
                        return proc.stdout
                except Exception:
                    pass
        if yaml is None:
            return ""
        kust_file = kustomize_dir / "kustomization.yaml"
        if not kust_file.exists():
            kust_file = kustomize_dir / "kustomization.yml"
        if not kust_file.exists():
            return ""
        try:
            kust_doc = yaml.safe_load(kust_file.read_text(encoding="utf-8")) or {}
            if not isinstance(kust_doc, dict):
                return ""
            resources = (kust_doc.get("resources") or []) + (kust_doc.get("bases") or [])
            images = kust_doc.get("images") or []
            patches = (kust_doc.get("patches") or []) + (kust_doc.get("patchesStrategicMerge") or [])
            target_ns = kust_doc.get("namespace")

            docs: List[Dict[str, Any]] = []
            for res in resources:
                res_path = (kustomize_dir / str(res)).resolve()
                if res_path.is_dir():
                    sub_yaml = self.render_kustomize_overlay(res_path)
                    if sub_yaml:
                        docs.extend([d for d in yaml.safe_load_all(sub_yaml) if isinstance(d, dict)])
                elif res_path.is_file():
                    docs.extend([d for d in yaml.safe_load_all(res_path.read_text(encoding="utf-8")) if isinstance(d, dict)])

            for patch_entry in patches:
                patch_text = ""
                if isinstance(patch_entry, str):
                    p_file = (kustomize_dir / patch_entry).resolve()
                    if p_file.is_file():
                        patch_text = p_file.read_text(encoding="utf-8")
                elif isinstance(patch_entry, dict):
                    if "patch" in patch_entry:
                        patch_text = str(patch_entry["patch"])
                    elif "path" in patch_entry:
                        p_file = (kustomize_dir / str(patch_entry["path"])).resolve()
                        if p_file.is_file():
                            patch_text = p_file.read_text(encoding="utf-8")
                if patch_text:
                    for p_doc in yaml.safe_load_all(patch_text):
                        if not isinstance(p_doc, dict):
                            continue
                        p_kind = p_doc.get("kind")
                        p_name = (p_doc.get("metadata") or {}).get("name")
                        for d in docs:
                            if d.get("kind") == p_kind and (d.get("metadata") or {}).get("name") == p_name:
                                self._deep_merge_dict(d, p_doc)

            image_map = {str(img.get("name")): img for img in images if isinstance(img, dict) and img.get("name")}
            for d in docs:
                if target_ns and isinstance(d.get("metadata"), dict):
                    d["metadata"].setdefault("namespace", target_ns)
                if d.get("kind") in WORKLOAD_KINDS and image_map:
                    _, pod_spec = self.extract_pod_spec(d)
                    for c_list_key in ("containers", "initContainers", "ephemeralContainers"):
                        for c in pod_spec.get(c_list_key) or []:
                            raw_img = str(c.get("image") or "").strip()
                            img_repo = raw_img.split(":", 1)[0].split("@", 1)[0]
                            if img_repo in image_map or raw_img in image_map:
                                rule = image_map.get(img_repo) or image_map.get(raw_img)
                                new_repo = str(rule.get("newName") or img_repo)
                                if rule.get("digest"):
                                    c["image"] = f"{new_repo}@{rule['digest']}"
                                elif rule.get("newTag") is not None:
                                    c["image"] = f"{new_repo}:{rule['newTag']}"
                                else:
                                    c["image"] = new_repo

            return yaml.safe_dump_all(docs) if docs else ""
        except Exception:
            return ""

    def render_helm_chart(self, chart_dir: Path) -> str:
        """Renders a Helm chart directory using helm template or native Python template substitution."""
        if shutil.which("helm"):
            try:
                proc = subprocess.run(
                    ["helm", "template", "viento-release", str(chart_dir)],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return proc.stdout
            except Exception:
                pass
        if yaml is None:
            return ""
        try:
            chart_meta = yaml.safe_load((chart_dir / "Chart.yaml").read_text(encoding="utf-8")) or {}
            values_path = chart_dir / "values.yaml"
            values = yaml.safe_load(values_path.read_text(encoding="utf-8")) if values_path.exists() else {}
            if not isinstance(values, dict):
                values = {}
            templates_dir = chart_dir / "templates"
            if not templates_dir.is_dir():
                return ""

            def _lookup_path(root_obj: Any, dotted: str) -> Any:
                cur = root_obj
                for part in dotted.split("."):
                    if not part:
                        continue
                    if isinstance(cur, dict) and part in cur:
                        cur = cur[part]
                    else:
                        return None
                return cur

            def _replace_expr(match: re.Match) -> str:
                expr = match.group(1).strip().lstrip("-").rstrip("-").strip()
                default_val = None
                if "|" in expr:
                    parts = [p.strip() for p in expr.split("|")]
                    expr = parts[0]
                    for pipe_part in parts[1:]:
                        m_def = re.match(r"default\s+[\x22\x27]?([^\x22\x27]+)[\x22\x27]?", pipe_part)
                        if m_def:
                            default_val = m_def.group(1)
                if expr.startswith(".Values."):
                    val = _lookup_path(values, expr[len(".Values."):])
                elif expr.startswith(".Chart."):
                    key = expr[len(".Chart."):]
                    val = chart_meta.get(key) or chart_meta.get(key[0].lower() + key[1:])
                elif expr == ".Release.Name":
                    val = "viento-release"
                elif expr == ".Release.Namespace":
                    val = "default"
                else:
                    val = default_val
                if val is None:
                    val = default_val if default_val is not None else ""
                if isinstance(val, bool):
                    return "true" if val else "false"
                return str(val)

            rendered_docs: List[str] = []
            for tpl_file in sorted(templates_dir.rglob("*")):
                if not tpl_file.is_file() or tpl_file.suffix.lower() not in {".yaml", ".yml"}:
                    continue
                raw_tpl = tpl_file.read_text(encoding="utf-8", errors="ignore")
                rendered = re.sub(r"\{\{(.*?)\}\}", _replace_expr, raw_tpl)
                rendered_docs.append(rendered)
            return "\n---\n".join(rendered_docs)
        except Exception:
            return ""

    def check_rendered_overlays(self, target_dir: Path = None, kustomize_build: bool = False, helm_template: bool = False):
        """Optionally renders and validates Kustomize overlays and Helm charts across the repository."""
        if not kustomize_build and not helm_template:
            return
        base = (target_dir or self.repo_root).resolve()
        existing_keys = {(v.rule, v.message) for v in self.violations}

        for root, dirs, files in os.walk(base):
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not self.gitignore.is_ignored(Path(root) / d)
            ]
            root_path = Path(root)
            file_set = set(files)

            if kustomize_build and ("kustomization.yaml" in file_set or "kustomization.yml" in file_set):
                kust_file = root_path / ("kustomization.yaml" if "kustomization.yaml" in file_set else "kustomization.yml")
                rendered = self.render_kustomize_overlay(root_path)
                if rendered:
                    before_len = len(self.violations)
                    self.check_k8s_manifest(kust_file, content=rendered)
                    deduped = self.violations[:before_len]
                    for v in self.violations[before_len:]:
                        if (v.rule, v.message) not in existing_keys:
                            existing_keys.add((v.rule, v.message))
                            deduped.append(v)
                    self.violations = deduped

            if helm_template and "Chart.yaml" in file_set:
                chart_file = root_path / "Chart.yaml"
                rendered = self.render_helm_chart(root_path)
                if rendered:
                    before_len = len(self.violations)
                    self.check_k8s_manifest(chart_file, content=rendered)
                    deduped = self.violations[:before_len]
                    for v in self.violations[before_len:]:
                        if (v.rule, v.message) not in existing_keys:
                            existing_keys.add((v.rule, v.message))
                            deduped.append(v)
                    self.violations = deduped

    def to_sarif(self, version: str = "0.4.0") -> Dict[str, Any]:
        """Generates an OASIS SARIF v2.1.0 report for GitHub/Forgejo/GitLab code scanning."""
        unique_rules = sorted({v.rule for v in self.violations})
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VMG Viento",
                            "informationUri": "https://www.vmg.systems",
                            "version": version,
                            "rules": [
                                {
                                    "id": rule_id,
                                    "shortDescription": {"text": f"VMG Viento architectural & security invariant: {rule_id}"},
                                }
                                for rule_id in unique_rules
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": v.rule,
                            "level": "error",
                            "message": {"text": v.message},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": v.file_path},
                                        "region": {"startLine": max(1, int(v.line_number or 1))},
                                    }
                                }
                            ],
                        }
                        for v in self.violations
                    ],
                }
            ],
        }

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
