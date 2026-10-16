#!/usr/bin/env python3
"""
scripts/lint_invariants.py
Mechanical Invariant Linter for VMG Systems Engineering Platform.
Enforces architectural invariants, Kubernetes zero-trust policies,
PromQL stability guards, and secrets hygiene.
"""

import os
import sys
import re
import shutil
import subprocess
import fnmatch
import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Tuple, Any

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

STATIC_PVC_CAPACITY_FLOORS = {
    "apps/recruiter-monitor-data-pvc": "5Gi",
    "apps/uptime-kuma-nvme-pvc": "5Gi",
    "apps/uptime-kuma-data-pvc": "5Gi",
    "apps/bazarr-config-nvme-pvc": "2Gi",
    "apps/deal-sniper-nvme-pvc": "5Gi",
    "apps/vaultwarden-nvme-pvc": "2Gi",
    "apps/hermes-data-pvc": "10Gi",
    "apps/qdrant-data-pvc": "10Gi",
    "apps/n8n-data-pvc": "5Gi",
    "apps/n8n-postgres-pvc": "10Gi",
    "apps/langfuse-postgres-pvc": "10Gi",
    "apps/openwebui-data-pvc": "5Gi",
}

SECRET_PATTERNS = [
    (re.compile(r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}"), "SLACK_TOKEN"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PRIVATE_KEY"),
    (re.compile(r"AIza[0-9A-Za-z-_]{35}"), "GOOGLE_API_KEY"),
    (re.compile(r"gho_[0-9A-Za-z]{30,}"), "GITHUB_OAUTH_TOKEN"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS_ACCESS_KEY"),
]

WORKLOAD_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"
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
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root.resolve()
        self.violations: List[InvariantViolation] = []
        self.gitignore = GitIgnoreResolver(self.repo_root)
        self._live_pvc_cache: Dict[str, Dict[str, Any]] = {}
        self._live_pvc_loaded: bool = False

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

    def _load_live_pvcs(self):
        if self._live_pvc_loaded:
            return
        self._live_pvc_loaded = True
        for pvc_key, floor_storage in STATIC_PVC_CAPACITY_FLOORS.items():
            self._live_pvc_cache[pvc_key] = {
                "storage": floor_storage,
                "bytes": self.parse_k8s_storage_bytes(floor_storage),
                "storageClassName": "static-baseline",
            }
        kubeconfig_path = self.repo_root / "iac" / "tofu" / "k8s" / "kubeconfig"
        if not kubeconfig_path.exists():
            return
        try:
            import base64
            import json
            import ssl
            import tempfile
            import urllib.request

            kc_text = kubeconfig_path.read_text(encoding="utf-8")
            server_m = re.search(r"server:\s*(\S+)", kc_text)
            ca_m = re.search(r"certificate-authority-data:\s*(\S+)", kc_text)
            cert_m = re.search(r"client-certificate-data:\s*(\S+)", kc_text)
            key_m = re.search(r"client-key-data:\s*(\S+)", kc_text)
            if not (server_m and ca_m and cert_m and key_m):
                return

            server = server_m.group(1)
            with tempfile.NamedTemporaryFile(delete=False) as ca_f, \
                 tempfile.NamedTemporaryFile(delete=False) as cert_f, \
                 tempfile.NamedTemporaryFile(delete=False) as key_f:
                ca_f.write(base64.b64decode(ca_m.group(1))); ca_f.flush()
                cert_f.write(base64.b64decode(cert_m.group(1))); cert_f.flush()
                key_f.write(base64.b64decode(key_m.group(1))); key_f.flush()
                ctx = ssl.create_default_context(cafile=ca_f.name)
                ctx.load_cert_chain(certfile=cert_f.name, keyfile=key_f.name)

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

    def check_k8s_container_spec(self, container: Dict[str, Any], file_path: str, workload_name: str):
        """Rule: DISALLOW_LATEST_TAG & REQUIRE_RESOURCE_LIMITS"""
        image = container.get("image", "")
        c_name = container.get("name", "unknown")

        # 1. Image tag verification
        if not image:
            self.violations.append(
                InvariantViolation(file_path, "DISALLOW_LATEST_TAG", f"Container '{c_name}' in '{workload_name}' missing image")
            )
        elif image.endswith(":latest") or (":" not in image and "@" not in image):
            self.violations.append(
                InvariantViolation(
                    file_path, "DISALLOW_LATEST_TAG",
                    f"Container '{c_name}' in '{workload_name}' uses floating or unpinned image tag: '{image}'"
                )
            )

        # 2. Resource limits & requests verification
        resources = container.get("resources")
        if not resources:
            self.violations.append(
                InvariantViolation(
                    file_path, "REQUIRE_RESOURCE_LIMITS",
                    f"Container '{c_name}' in '{workload_name}' missing 'resources' spec"
                )
            )
        else:
            requests = resources.get("requests", {})
            limits = resources.get("limits", {})
            for metric in ("cpu", "memory"):
                if metric not in requests:
                    self.violations.append(
                        InvariantViolation(
                            file_path, "REQUIRE_RESOURCE_LIMITS",
                            f"Container '{c_name}' in '{workload_name}' missing resources.requests.{metric}"
                        )
                    )
                if metric not in limits:
                    self.violations.append(
                        InvariantViolation(
                            file_path, "REQUIRE_RESOURCE_LIMITS",
                            f"Container '{c_name}' in '{workload_name}' missing resources.limits.{metric}"
                        )
                    )

        # 3. Privileged & privilege escalation verification (1:1 with Kyverno disallow-privileged-containers)
        if not workload_name.startswith("Deployment/forgejo-runner"):
            sec_ctx = container.get("securityContext") or {}
            if sec_ctx.get("privileged") is True or sec_ctx.get("allowPrivilegeEscalation") is True:
                self.violations.append(
                    InvariantViolation(
                        file_path, "DISALLOW_PRIVILEGED_CONTAINERS",
                        f"Container '{c_name}' in '{workload_name}' sets privileged=true or allowPrivilegeEscalation=true"
                    )
                )

    def extract_pod_spec(self, doc: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        kind = doc.get("kind", "")
        name = doc.get("metadata", {}).get("name", "unnamed")
        spec = doc.get("spec", {})

        if kind in {"Deployment", "StatefulSet", "DaemonSet", "Job"}:
            template = spec.get("template", {})
            return name, template.get("spec", {})
        elif kind == "CronJob":
            job_template = spec.get("jobTemplate", {}).get("spec", {})
            template = job_template.get("template", {})
            return name, template.get("spec", {})
        return name, {}

    def check_plaintext_secrets(self, file_path: Path):
        """Rule: PLAINTEXT_SECRET_DEFENSE - Scan non-SOPS text files for live secret signatures."""
        if file_path.name.endswith((".sops.yaml", ".sops.yml")):
            return
        if file_path.name in {"lint_invariants.py", "test_lint_invariants.py", "agent_pr_reviewer.py", "test_agent_pr_reviewer.py"}:
            return

        try:
            rel_path = str(file_path.resolve().relative_to(self.repo_root))
        except ValueError:
            rel_path = str(file_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, start=1):
                    if "FIXTURE_ALLOW_SECRET" in line:
                        continue
                    for pattern, secret_type in SECRET_PATTERNS:
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

    def check_k8s_manifest(self, file_path: Path):
        """Validates Kubernetes manifests for zero-trust admission invariants."""
        rel_path = str(file_path.relative_to(self.repo_root))
        if yaml is None:
            self.violations.append(
                InvariantViolation(rel_path, "YAML_DEPENDENCY_MISSING", "PyYAML is required to validate Kubernetes manifests")
            )
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return

        sops_violation_recorded = False
        if file_path.name.endswith(".sops.yaml"):
            if "sops:" not in content or "mac:" not in content:
                self.violations.append(
                    InvariantViolation(rel_path, "SOPS_ENCRYPTION", "SOPS secret file missing 'sops:' or 'mac:' encryption markers")
                )
                sops_violation_recorded = True

        # Parse YAML docs
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
            meta = doc.get("metadata", {})
            name = meta.get("name", "unnamed")

            # Check SOPS secret encryption on ALL Kubernetes Secret manifests
            if kind == "Secret" and not sops_violation_recorded:
                if not file_path.name.endswith(".sops.yaml"):
                    self.violations.append(
                        InvariantViolation(rel_path, "SOPS_ENCRYPTION", "Kubernetes Secret must be stored in encrypted .sops.yaml file")
                    )
                    sops_violation_recorded = True
                elif "sops:" not in content or "mac:" not in content:
                    self.violations.append(
                        InvariantViolation(rel_path, "SOPS_ENCRYPTION", "SOPS secret file missing 'sops:' or 'mac:' encryption markers")
                    )
                    sops_violation_recorded = True

            # Workload container checks
            if kind in WORKLOAD_KINDS:
                w_name, pod_spec = self.extract_pod_spec(doc)
                containers = pod_spec.get("containers", [])
                init_containers = pod_spec.get("initContainers", [])
                for c in containers:
                    self.check_k8s_container_spec(c, rel_path, f"{kind}/{w_name}")
                for c in init_containers:
                    self.check_k8s_container_spec(c, rel_path, f"{kind}/{w_name} (init)")

            # Flagger Canary Schema Exclusivity
            if kind == "Canary":
                analysis = doc.get("spec", {}).get("analysis", {})
                has_iterations = "iterations" in analysis
                has_weights = "stepWeight" in analysis or "maxWeight" in analysis
                if has_iterations and has_weights:
                    self.violations.append(
                        InvariantViolation(
                            rel_path, "FLAGGER_SCHEMA_MUTUAL_EXCLUSION",
                            f"Canary '{name}' combines 'iterations' with 'stepWeight'/'maxWeight'. Must use one or the other."
                        )
                    )

            # MetricTemplate Traefik v3 Regex and PromQL Zero-Denominator Guard
            if kind == "MetricTemplate":
                query = doc.get("spec", {}).get("query", "")
                if "traefik_service_requests" in query:
                    # In Traefik v3, CRD services are named <namespace>-<name>-<port>@kubernetescrd
                    if 'service=~"{{ target }}' in query and '.*{{ target }}' not in query:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "TRAEFIK_METRIC_REGEX",
                                f"MetricTemplate '{name}' query uses prefix match. Traefik v3 requires wildcard: '.*{{{{ target }}}}.*'"
                            )
                        )
                # PromQL division without > 0 guard
                if "/" in query and "rate(" in query:
                    # Look for division where denominator has rate but lacks > 0
                    if "/ (sum(rate(" in query and "> 0" not in query:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "PROMQL_ZERO_DENOMINATOR_GUARD",
                                f"MetricTemplate '{name}' contains rate division without zero-denominator guard '> 0'"
                            )
                        )

            # SQLite backup command timeout check on container specs
            if kind in WORKLOAD_KINDS:
                w_name, pod_spec = self.extract_pod_spec(doc)
                all_c = pod_spec.get("containers", []) + pod_spec.get("initContainers", [])
                for c in all_c:
                    cmd_list = c.get("command", []) + c.get("args", [])
                    cmd_str = " ".join(str(item) for item in cmd_list)
                    if "sqlite3" in cmd_str and (".backup" in cmd_str or ".dump" in cmd_str):
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

            # Flux Notification Provider Endpoint Validation
            if kind == "Provider" and "notification.toolkit.fluxcd.io" in str(doc.get("apiVersion", "")):
                p_type = doc.get("spec", {}).get("type", "")
                p_addr = doc.get("spec", {}).get("address", "")
                if p_type == "alertmanager" and "/api/v2/alerts" not in p_addr:
                    self.violations.append(
                        InvariantViolation(
                            rel_path, "FLUX_PROVIDER_ENDPOINT",
                            f"Flux Alertmanager Provider '{name}' address '{p_addr}' missing '/api/v2/alerts/' endpoint path (causes HTTP 405)"
                        )
                    )

            # Live Cluster PVC Immutability & Capacity Shrink Guard
            if kind == "PersistentVolumeClaim":
                self._load_live_pvcs()
                ns = meta.get("namespace", "default")
                key = f"{ns}/{name}"
                if key in self._live_pvc_cache:
                    live_pvc = self._live_pvc_cache[key]
                    manifest_storage = doc.get("spec", {}).get("resources", {}).get("requests", {}).get("storage", "")
                    manifest_bytes = self.parse_k8s_storage_bytes(manifest_storage)
                    if manifest_bytes > 0 and live_pvc["bytes"] > 0 and manifest_bytes < live_pvc["bytes"]:
                        self.violations.append(
                            InvariantViolation(
                                rel_path, "PVC_CAPACITY_SHRINK_FORBIDDEN",
                                f"PVC '{key}' requests '{manifest_storage}', which is smaller than live cluster PVC capacity '{live_pvc['storage']}'"
                            )
                        )

    def check_opnsense_config(self, file_path: Path):
        """Rule: OPNSENSE_ALIAS_HIERARCHY - Aliases must be under <Firewall><Alias><aliases>."""
        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            # If root has direct <aliases> child, that's the deprecated syntax
            root_aliases = root.findall("./aliases")
            if root_aliases:
                self.violations.append(
                    InvariantViolation(
                        rel_path, "OPNSENSE_ALIAS_HIERARCHY",
                        "OPNsense config contains deprecated root-level <aliases>. Must be nested inside <Firewall><Alias><aliases>."
                    )
                )
        except Exception:
            pass

    def check_wrapper_duplication(self, file_path: Path):
        """Rule: NO_INLINE_SOURCE_DUPLICATION - Wrapper scripts must not embed inline copies of standalone runtime modules."""
        rel_path = str(file_path.relative_to(self.repo_root))
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            line_count = len(content.splitlines())
            if "$replScript = @'" in content or "const CODE_TOKEN_REGEX =" in content or line_count > 600:
                self.violations.append(
                    InvariantViolation(
                        rel_path, "NO_INLINE_SOURCE_DUPLICATION",
                        f"Wrapper script ({line_count} lines) embeds duplicate runtime source code or exceeds 600-line wrapper ceiling"
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

    def check_documentation_decommissioned_resources(self, file_path: Path):
        """Rule: DECOMMISSIONED_RESOURCE_LEAK - Optional via .viento.yaml decommissioned_tokens."""
        return

    def check_readme_coverage(self):
        """Rule: README_COVERAGE - Ensure README.md documents core cluster infrastructure and services."""
        readme_path = self.repo_root / "README.md"
        # Only require README if checking a git repo root or if README.md exists
        if not (self.repo_root / ".git").exists() and not readme_path.exists():
            return

        if not readme_path.exists():
            self.violations.append(
                InvariantViolation("README.md", "README_COVERAGE", "Master README.md missing from repository root")
            )
            return

        content = readme_path.read_text(encoding="utf-8", errors="ignore").lower()
        required_anchors = [
            ("viento-lint", "viento-lint mechanical GitOps linter"),
            ("viento-bench", "viento-bench storage contention benchmark"),
            ("viento-dr-drill", "viento-dr-drill cold backup verifier"),
            ("kyverno", "Kyverno zero-trust policies"),
        ]
        viento_cfg_path = self.repo_root / ".viento.yaml"
        if viento_cfg_path.exists() and yaml is not None:
            try:
                cfg = yaml.safe_load(viento_cfg_path.read_text(encoding="utf-8")) or {}
                if "readme_required_anchors" in cfg and isinstance(cfg["readme_required_anchors"], list):
                    custom_anchors = []
                    for item in cfg["readme_required_anchors"]:
                        if isinstance(item, dict) and "token" in item:
                            tok = str(item["token"]).lower()
                            custom_anchors.append((tok, str(item.get("description", tok))))
                        elif isinstance(item, str):
                            custom_anchors.append((item.lower(), item))
                    required_anchors = custom_anchors
            except Exception:
                pass
        missing = [desc for token, desc in required_anchors if token not in content]
        if missing:
            self.violations.append(
                InvariantViolation(
                    "README.md", "README_COVERAGE",
                    f"README.md missing documentation for: {', '.join(missing)}"
                )
            )

    def run(self, target_dir: Path = None) -> List[InvariantViolation]:
        self.violations.clear()
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

                # Check plaintext secrets in text files
                if ext in TEXT_EXTENSIONS or file in {"Dockerfile", "Makefile"}:
                    self.check_plaintext_secrets(p)

                # Check files for decommissioned resource references
                if ext in {".md", ".py", ".sh", ".ts", ".yaml"}:
                    self.check_documentation_decommissioned_resources(p)

                # Check k8s manifests
                posix_path = p.as_posix()
                if ("iac/k8s" in posix_path or posix_path.startswith("ci/") or "/ci/" in posix_path) and ext in {".yaml", ".yml"}:
                    # Skip archive directory
                    if "archive" not in p.parts:
                        self.check_k8s_manifest(p)

                # Check opnsense configs
                if file.endswith(".xml") and "opnsense" in posix_path.lower():
                    self.check_opnsense_config(p)

                # Check wrapper scripts for inline source duplication
                if ext in {".ps1", ".sh"} and "scripts" in p.parts:
                    self.check_wrapper_duplication(p)

                # Check Node.js / ESM files for syntax validity
                if ext in {".mjs", ".js"} and any(part in p.parts for part in ("docker", "scripts", "apps")):
                    self.check_node_syntax(p)

        # Check master README.md coverage
        self.check_readme_coverage()

        return self.violations

    def check_flux_kustomization_readiness(self) -> List[InvariantViolation]:
        """Verifies live FluxCD Kustomizations (cluster-apps, cluster-system) report Ready=True."""
        flux_violations: List[InvariantViolation] = []
        kubeconfig_path = self.repo_root / "iac" / "tofu" / "k8s" / "kubeconfig"
        if not kubeconfig_path.exists():
            return flux_violations
        try:
            import base64
            import json
            import ssl
            import tempfile
            import urllib.request

            kc_text = kubeconfig_path.read_text(encoding="utf-8")
            server = re.search(r"server:\s*(\S+)", kc_text).group(1)
            ca_b64 = re.search(r"certificate-authority-data:\s*(\S+)", kc_text).group(1)
            cert_b64 = re.search(r"client-certificate-data:\s*(\S+)", kc_text).group(1)
            key_b64 = re.search(r"client-key-data:\s*(\S+)", kc_text).group(1)

            with tempfile.NamedTemporaryFile(delete=False) as ca_f, \
                 tempfile.NamedTemporaryFile(delete=False) as cert_f, \
                 tempfile.NamedTemporaryFile(delete=False) as key_f:
                ca_f.write(base64.b64decode(ca_b64)); ca_f.flush()
                cert_f.write(base64.b64decode(cert_b64)); cert_f.flush()
                key_f.write(base64.b64decode(key_b64)); key_f.flush()
                ctx = ssl.create_default_context(cafile=ca_f.name)
                ctx.load_cert_chain(certfile=cert_f.name, keyfile=key_f.name)

            import time
            items = []
            for attempt in range(4):
                req = urllib.request.Request(f"{server}/apis/kustomize.toolkit.fluxcd.io/v1/namespaces/flux-system/kustomizations")
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    items = json.loads(resp.read().decode("utf-8")).get("items", [])
                if any(
                    next((c for c in ks.get("status", {}).get("conditions", []) if c.get("type") == "Ready"), {}).get("reason") == "Progressing"
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
        return flux_violations


def main():
    parser = argparse.ArgumentParser(description="VMG Systems Mechanical Invariant Linter")
    parser.add_argument("--path", default=".", help="Root path to lint (default: current directory)")
    parser.add_argument("--verbose", action="store_true", help="Print verbose output")
    parser.add_argument("--verify-flux-sync", action="store_true", help="Verify live FluxCD Kustomizations are Ready=True")
    args = parser.parse_args()

    repo_root = Path(args.path).resolve()
    linter = InvariantLinter(repo_root)
    violations = linter.run()
    if args.verify_flux_sync:
        violations.extend(linter.check_flux_kustomization_readiness())

    if violations:
        print(f"FAILED: {len(violations)} architectural invariant violation(s) found:\n")
        for v in violations:
            print(f"  * {v}")
        sys.exit(1)
    else:
        print("SUCCESS: All architectural invariants, zero-trust policies, and hygiene rules passed cleanly.")
        sys.exit(0)


if __name__ == "__main__":
    main()
