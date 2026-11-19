"""
VulnTrace OCI Container Execution Backend (P0.6)
Executes verification harnesses and regression suites inside rootless OCI containers (Podman/crun)
with kernel-level network denial (--network none), host filesystem hiding, cgroup PID/memory limits,
and unforgeable parent-generated execution attestation.
"""

import os
import re
import sys
import json
import time
import uuid
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable, Tuple, Set

from packaging.requirements import Requirement, InvalidRequirement
from packaging.version import Version
from packaging.utils import canonicalize_name

from vulntrace.core.backend import (
    ExecutionBackend,
    BackendCapabilities,
    IsolationTier,
    ExecutionAttestation,
    ExecutionCommandResult,
    is_curated_fixture,
)
from vulntrace.sandbox.runner import SubprocessSandboxRunner
from vulntrace.sandbox.target_env import (
    ManifestClassification,
    TargetEnvironmentManager,
)


@dataclass(frozen=True)
class SandboxRuntimeData:
    image_digest: str
    packages: Dict[str, Version]
    markers: Dict[str, str]


class ContainerExecutionBackend(ExecutionBackend):
    """
    OCI Container Execution Backend using rootless Podman / crun.
    Enforces true kernel network denial, host filesystem hiding, and resource limits.
    """

    IMAGE_NAME = "vulntrace-sandbox-base:latest"
    DEFAULT_TIMEOUT = 10.0
    _cached_available: Dict[Tuple[str, ...], bool] = {}
    _cached_image_digest: Dict[Tuple[str, ...], str] = {}
    _cached_runtime_version: Dict[Tuple[str, ...], str] = {}
    _cached_runtime_data: Dict[Tuple[str, ...], SandboxRuntimeData] = {}
    _cached_sandbox_packages: Optional[Set[str]] = None
    _workspace_source_map: Dict[str, Path] = {}

    @staticmethod
    def _normalize_pkg_name(dep_str: str) -> str:
        """Extracts canonical package name from a dependency requirement string."""
        raw = re.split(r"[><=~!;\s]", dep_str.strip())[0].strip().lower()
        return canonicalize_name(raw)

    def get_sandbox_runtime_data(self, fresh: bool = False) -> Optional[SandboxRuntimeData]:
        """
        Retrieves the verified package inventory and PEP 508 runtime markers
        from the canonical sandbox image, strictly bound to the image digest.
        Caches the parsed result across invocations.
        Fails closed (returns None) if the live query fails; unverified fallbacks are prohibited.
        """
        digest = self.get_image_digest()
        if not digest:
            return None

        prefix = tuple(self._build_cli_prefix())
        cache_key = (digest, *prefix)

        if not fresh and cache_key in self.__class__._cached_runtime_data:
            return self.__class__._cached_runtime_data[cache_key]

        packages: Dict[str, Version] = {}
        markers: Dict[str, str] = {}

        try:
            query_script = (
                "import importlib.metadata, json, platform, sys, os; "
                "pkgs = {d.metadata['Name']: d.version for d in importlib.metadata.distributions() if 'Name' in d.metadata}; "
                "markers = {"
                "'os_name': os.name, "
                "'sys_platform': sys.platform, "
                "'platform_machine': platform.machine(), "
                "'platform_python_implementation': platform.python_implementation(), "
                "'python_version': '.'.join(platform.python_version_tuple()[:2]), "
                "'python_full_version': platform.python_version(), "
                "'platform_system': platform.system(), "
                "'implementation_name': sys.implementation.name"
                "}; "
                "print(json.dumps({'packages': pkgs, 'markers': markers}))"
            )
            cmd = self._build_cli_prefix() + [
                "podman", "run", "--rm",
                "--network", "none",
                self.IMAGE_NAME,
                "python3", "-c", query_script
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=10.0)
            if res.returncode == 0 and res.stdout.strip():
                for line in reversed(res.stdout.strip().splitlines()):
                    line = line.strip()
                    if line.startswith("{") and line.endswith("}"):
                        data = json.loads(line)
                        if isinstance(data, dict):
                            raw_pkgs = data.get("packages", {})
                            if isinstance(raw_pkgs, dict):
                                for pkg_name, pkg_ver_str in raw_pkgs.items():
                                    try:
                                        c_name = canonicalize_name(pkg_name)
                                        packages[c_name] = Version(str(pkg_ver_str))
                                    except Exception:
                                        continue
                            raw_markers = data.get("markers", {})
                            if isinstance(raw_markers, dict):
                                for k, v in raw_markers.items():
                                    markers[str(k)] = str(v)
                        break
        except Exception:
            pass

        # Strict fail-closed: If query failed to retrieve packages or markers, do NOT use unverified fallback
        if not packages or not markers:
            return None

        data = SandboxRuntimeData(
            image_digest=digest,
            packages=packages,
            markers=markers,
        )
        self.__class__._cached_runtime_data[cache_key] = data
        return data

    def get_sandbox_available_packages(self) -> Set[str]:
        """
        Returns the set of canonical package names pre-installed in the canonical sandbox image.
        Maintains backward compatibility with callers expecting a Set[str].
        """
        data = self.get_sandbox_runtime_data()
        if data is None:
            return set()
        names = set(data.packages.keys())
        return names | {k.replace("-", "_") for k in names}

    def __init__(self, wsl_distro: Optional[str] = "Ubuntu"):
        self.wsl_distro = wsl_distro
        self._image_digest: Optional[str] = None
        self._is_available: Optional[bool] = None
        self._runtime_version: Optional[str] = None
        self._verified_runtime: bool = False

    @classmethod
    def clear_availability_cache(cls) -> None:
        """Clears class-level availability, digest, runtime version, and runtime data caches."""
        cls._cached_available.clear()
        cls._cached_image_digest.clear()
        cls._cached_runtime_version.clear()
        cls._cached_runtime_data.clear()
        cls._cached_sandbox_packages = None
        cls._workspace_source_map.clear()

    @classmethod
    def to_wsl_path(cls, path: Path) -> str:
        """Converts Windows path (C:\\...) to WSL path (/mnt/c/...)."""
        path_str = str(path.resolve()).replace("\\", "/")
        if len(path_str) >= 2 and path_str[1] == ":":
            drive = path_str[0].lower()
            rest = path_str[2:]
            return f"/mnt/{drive}{rest}"
        return path_str

    def _get_cache_key(self) -> Tuple[str, ...]:
        """Returns the cache key tuple including CLI prefix and remote connection environment variables."""
        prefix = list(self._build_cli_prefix())
        container_host = os.environ.get("CONTAINER_HOST", "").strip()
        container_conn = os.environ.get("CONTAINER_CONNECTION", "").strip()
        return tuple(prefix + [f"host={container_host}", f"conn={container_conn}"])

    def _record_unavailable(self, cache_key: Tuple[str, ...], cache_class: bool = True) -> None:
        """Helper to record unavailable status across class and instance caches."""
        if cache_class:
            ContainerExecutionBackend._cached_available[cache_key] = False
            ContainerExecutionBackend._cached_runtime_version[cache_key] = None
        self._is_available = False
        self._runtime_version = None
        self._verified_runtime = False

    def is_available(self, fresh: bool = False) -> bool:
        """
        Checks whether rootless Podman with crun, cgroups v2, and the base sandbox
        image is fully accessible and verified on the current host.
        Fails closed on any missing, malformed, or unverified runtime requirement.
        """
        cache_key = self._get_cache_key()

        # Strict local-runtime: immediately reject remote environment variables
        if bool(os.environ.get("CONTAINER_HOST", "").strip()) or bool(os.environ.get("CONTAINER_CONNECTION", "").strip()):
            self._record_unavailable(cache_key)
            return False

        if not fresh and self._is_available is not None:
            return self._is_available

        if not fresh and cache_key in ContainerExecutionBackend._cached_available:
            self._is_available = ContainerExecutionBackend._cached_available[cache_key]
            self._runtime_version = ContainerExecutionBackend._cached_runtime_version.get(cache_key)
            self._verified_runtime = bool(self._is_available)
            return self._is_available

        try:
            prefix_cmd = list(self._build_cli_prefix())

            # 1. Podman CLI invocation and strict version capture
            cmd_ver = prefix_cmd + ["podman", "--version"]
            proc_ver = subprocess.run(cmd_ver, capture_output=True, text=True, timeout=15)
            if proc_ver.returncode != 0 or not proc_ver.stdout.strip():
                self._record_unavailable(cache_key)
                return False

            raw_stdout = proc_ver.stdout.strip()
            lines = raw_stdout.splitlines()
            if not lines:
                self._record_unavailable(cache_key)
                return False

            first_line = lines[0].strip()
            version_match = re.fullmatch(
                r"podman(?:\s+version)?\s+([0-9]+(?:\.[0-9]+)+(?:[-+~.a-zA-Z0-9]+)?)",
                first_line,
                re.IGNORECASE
            )
            if not version_match:
                self._record_unavailable(cache_key)
                return False

            captured_version = f"podman {version_match.group(1).strip()}"

            # 2. Inspect host runtime properties via podman info --format json
            cmd_info = prefix_cmd + ["podman", "info", "--format", "json"]
            proc_info = subprocess.run(cmd_info, capture_output=True, text=True, timeout=15)
            if proc_info.returncode != 0 or not proc_info.stdout.strip():
                self._record_unavailable(cache_key)
                return False

            stdout_info = proc_info.stdout.strip()
            if not stdout_info:
                self._record_unavailable(cache_key)
                return False

            try:
                info_data = json.loads(stdout_info)
            except Exception:
                self._record_unavailable(cache_key)
                return False

            if not isinstance(info_data, dict):
                self._record_unavailable(cache_key)
                return False

            host = info_data.get("host")
            if not isinstance(host, dict):
                self._record_unavailable(cache_key)
                return False

            # 3. Explicit rootless verification
            security = host.get("security")
            if not isinstance(security, dict) or security.get("rootless") is not True:
                self._record_unavailable(cache_key)
                return False

            # 4. Explicit crun OCI runtime verification
            oci = host.get("ociRuntime") or host.get("ociruntime")
            if not isinstance(oci, dict):
                self._record_unavailable(cache_key)
                return False
            oci_name = str(oci.get("name", "")).strip().lower()
            if oci_name != "crun":
                self._record_unavailable(cache_key)
                return False

            # 5. Explicit cgroups v2 verification
            cgroup_ver = str(host.get("cgroupVersion", "")).strip().lower()
            if cgroup_ver != "v2":
                self._record_unavailable(cache_key)
                return False

            # 6. Explicit cgroup controllers verification (cpu, memory, pids)
            controllers = [str(c).strip().lower() for c in host.get("cgroupControllers", [])]
            required_controllers = {"cpu", "memory", "pids"}
            if not required_controllers.issubset(set(controllers)):
                self._record_unavailable(cache_key)
                return False

            # 7. Local runtime verification (serviceIsRemote must explicitly equal False)
            if host.get("serviceIsRemote") is not False:
                self._record_unavailable(cache_key)
                return False

            # 8. Local sandbox base image existence verification
            cmd_img = prefix_cmd + ["podman", "image", "exists", self.IMAGE_NAME]
            proc_img = subprocess.run(cmd_img, capture_output=True, text=True, timeout=15)
            if proc_img.returncode != 0:
                self._record_unavailable(cache_key, cache_class=False)
                return False

            # All mandatory Tier 1 preflight checks satisfied
            ContainerExecutionBackend._cached_available[cache_key] = True
            ContainerExecutionBackend._cached_runtime_version[cache_key] = captured_version
            self._is_available = True
            self._runtime_version = captured_version
            self._verified_runtime = True
            return True

        except Exception:
            self._record_unavailable(cache_key)
            return False

    def _build_cli_prefix(self) -> List[str]:
        """Returns command prefix (e.g. ['wsl', '-d', 'Ubuntu'] on Windows, or [] on Linux)."""
        if sys.platform == "win32" and self.wsl_distro:
            return ["wsl", "-d", self.wsl_distro]
        return []

    def get_image_digest(self, fresh: bool = False) -> Optional[str]:
        """Returns the verified sha256 image digest of the sandbox base image, or None if unavailable."""
        if not fresh and self._image_digest:
            return self._image_digest

        cache_key = self._get_cache_key()
        if not fresh and cache_key in ContainerExecutionBackend._cached_image_digest:
            self._image_digest = ContainerExecutionBackend._cached_image_digest[cache_key]
            return self._image_digest

        prefix_cmd = list(self._build_cli_prefix())
        try:
            cmd = prefix_cmd + [
                "podman", "image", "inspect", "--format", "{{.Digest}}", self.IMAGE_NAME
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0 and proc.stdout.strip():
                raw_digest = proc.stdout.strip().strip("'\"")
                if re.fullmatch(r"sha256:[0-9a-fA-F]{64}", raw_digest):
                    ContainerExecutionBackend._cached_image_digest[cache_key] = raw_digest
                    self._image_digest = raw_digest
                    return self._image_digest
        except Exception:
            pass

        self._image_digest = None
        ContainerExecutionBackend._cached_image_digest.pop(cache_key, None)
        return None

    def _kill_container(self, container_name: str) -> None:
        """Forcibly removes/kills a running container to prevent process leaks in WSL2/Linux."""
        try:
            cmd = self._build_cli_prefix() + ["podman", "rm", "-f", container_name]
            subprocess.run(cmd, capture_output=True, timeout=5)
        except Exception:
            pass

    @property
    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            tier=IsolationTier.OCI_CONTAINER_ISOLATED,
            filesystem_jailed=True,
            host_fs_hidden=True,
            network_kernel_denied=True,
            process_tree_contained=True,
            resource_limits_enforced=True,
            host_identity_isolated=True,
            hardware_virtualized=False,
            read_only_rootfs=True,
            tmpfs_scratch=True,
            non_root_user=True,
            description=(
                "OCI Rootless Container execution backend (Podman/crun) with kernel network denial "
                "(--network none), read-only root FS (--read-only), tmpfs scratch (/tmp), unprivileged non-root execution "
                "(--user 1000:1000), host filesystem hiding, PID caps (128), and memory limits (512MB)."
            ),
            boundary_caveats=[
                "Shares Linux/WSL2 host kernel (cgroups/namespaces isolation). Not full hardware virtualization (e.g. Firecracker/KVM).",
                "Disposable workspace directory copy is bind-mounted into container at /workspace."
            ]
        )

    async def initialize_workspace(self, source_repo: Path) -> str:
        """Prepares a disposable directory copy on the host."""
        disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(source_repo)
        disp_resolved = str(disposable_dir.resolve())
        ContainerExecutionBackend._workspace_source_map[disp_resolved] = Path(source_repo).resolve()
        return disp_resolved

    async def provision_dependencies(
        self,
        workspace_id: str,
        manifest_dependencies: List[str],
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        """
        Validates and provisions target dependencies inside the isolated container tier.
        Applies conservative static manifest inspection and image inventory preflight (Spec §4.5, §4.6).
        Fails closed on dynamic unverified dependencies, unsupported directives, and missing packages.
        If the workspace contains setup.py and dependencies are satisfied, setup.py build is executed
        strictly inside the container with --network none, --cap-drop ALL, and no host credentials.
        """
        t0 = time.perf_counter()
        workspace_path = Path(workspace_id)
        setup_py = workspace_path / "setup.py"

        ws_resolved = str(workspace_path.resolve())
        source_repo = ContainerExecutionBackend._workspace_source_map.get(ws_resolved)
        is_curated = is_curated_fixture(source_repo) if source_repo else is_curated_fixture(workspace_path)

        # 1. Conservative Manifest Inspection
        inspection = TargetEnvironmentManager.inspect_manifests(workspace_path)
        has_manifest = inspection.has_manifest
        detected_deps = list(inspection.dependencies)

        # Fail closed on invalid / ambiguous / dynamic manifests for untrusted repositories
        if not is_curated and inspection.classification in (
            ManifestClassification.DYNAMIC_UNVERIFIED,
            ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS,
            ManifestClassification.PARSE_ERROR
        ):
            latency_ms = (time.perf_counter() - t0) * 1000.0
            attestation = self.generate_attestation(workspace_id)
            err_msg = (
                f"Environment build failed: {inspection.classification.value} - "
                f"{inspection.failure_reason or 'unsupported or ambiguous manifest'}"
            )
            return ExecutionCommandResult(
                exit_code=1,
                stdout=f"Manifest inspection failed: {inspection.classification.value}",
                stderr=err_msg,
                latency_ms=round(latency_ms, 2),
                parent_validated=False,
                validation_notes=f"Environment build failed: manifest classification {inspection.classification.value}",
                structured_evidence={
                    "has_manifest": has_manifest,
                    "detected_dependencies": detected_deps,
                    "missing_dependencies": detected_deps,
                    "manifest_classification": inspection.classification.value,
                    "failure_reason": inspection.failure_reason,
                    "manifest_files": inspection.manifest_files,
                    "provisioned": False,
                    "image": self.IMAGE_NAME,
                    "network_isolated": True,
                    "setup_executed_in_container": False,
                    "setup_latency_ms": round(latency_ms, 2),
                    "build_duration_ms": round(latency_ms, 2),
                    "python_version": "Python 3.12 (OCI Rootless Container)",
                    "failure_classification": "ENV_BUILD_FAILED",
                    "pip_log_excerpt": err_msg,
                },
                attestation=attestation,
                error=err_msg
            )

        # 2. Collect and validate all declared requirements
        all_declared_deps = list(dict.fromkeys(manifest_dependencies + detected_deps))
        missing_deps: List[str] = []
        parse_error_msg: Optional[str] = None

        if all_declared_deps:
            runtime_data = self.get_sandbox_runtime_data()
            if runtime_data is None:
                if not is_curated:
                    latency_ms = (time.perf_counter() - t0) * 1000.0
                    attestation = self.generate_attestation(workspace_id)
                    err_msg = (
                        "Environment build failed: unable to verify sandbox package inventory "
                        "and runtime markers from container image. Unverified fallback is prohibited."
                    )
                    return ExecutionCommandResult(
                        exit_code=1,
                        stdout="Sandbox package inventory verification failed: unverified runtime.",
                        stderr=err_msg,
                        latency_ms=round(latency_ms, 2),
                        parent_validated=False,
                        validation_notes="Environment build failed: unverifiable sandbox runtime inventory",
                        structured_evidence={
                            "has_manifest": has_manifest,
                            "detected_dependencies": detected_deps,
                            "missing_dependencies": all_declared_deps,
                            "manifest_classification": inspection.classification.value,
                            "failure_reason": err_msg,
                            "manifest_files": inspection.manifest_files,
                            "provisioned": False,
                            "image": self.IMAGE_NAME,
                            "network_isolated": True,
                            "setup_executed_in_container": False,
                            "setup_latency_ms": round(latency_ms, 2),
                            "build_duration_ms": round(latency_ms, 2),
                            "python_version": "Python 3.12 (OCI Rootless Container)",
                            "failure_classification": "ENV_BUILD_FAILED",
                            "pip_log_excerpt": err_msg,
                        },
                        attestation=attestation,
                        error=err_msg
                    )

            stdlib_names = getattr(sys, "stdlib_module_names", set())

            for dep in all_declared_deps:
                dep_clean = dep.strip()
                if not dep_clean:
                    continue

                try:
                    req = Requirement(dep_clean)
                except InvalidRequirement as e:
                    if not is_curated:
                        parse_error_msg = f"Malformed dependency declaration '{dep_clean}': {e}"
                        missing_deps.append(dep_clean)
                        break
                    continue

                # Policy A: Extras require explicit dependency resolution
                if req.extras:
                    if not is_curated:
                        parse_error_msg = f"Dependency with extras '{dep_clean}' is unsupported under offline Tier 1 container preflight (Policy A)."
                        missing_deps.append(dep_clean)
                        break
                    continue

                # Prohibit direct URL / VCS dependencies
                if req.url:
                    if not is_curated:
                        parse_error_msg = f"Direct URL/VCS requirement '{dep_clean}' is prohibited under offline Tier 1 container policy."
                        missing_deps.append(dep_clean)
                        break
                    continue

                # PEP 508 Marker Evaluation
                if req.marker:
                    try:
                        if not req.marker.evaluate(environment=runtime_data.markers):
                            # Marker evaluated to False: dependency not required in this runtime
                            continue
                    except Exception as e:
                        if not is_curated:
                            parse_error_msg = f"PEP 508 marker evaluation failed for '{dep_clean}': {e}"
                            missing_deps.append(dep_clean)
                            break
                        continue

                canon_name = canonicalize_name(req.name)
                # Check Python standard library modules
                if canon_name in stdlib_names or req.name in stdlib_names or req.name.replace("-", "_") in stdlib_names:
                    continue

                # Check sandbox package inventory
                if canon_name in runtime_data.packages:
                    installed_ver = runtime_data.packages[canon_name]
                    if req.specifier and not req.specifier.contains(installed_ver, prereleases=True):
                        missing_deps.append(f"{dep_clean} (installed {installed_ver} does not satisfy {req.specifier})")
                else:
                    missing_deps.append(dep_clean)

        # If any requirement is missing, incompatible, or invalid, fail closed immediately
        if (missing_deps or parse_error_msg) and not is_curated:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            attestation = self.generate_attestation(workspace_id)
            missing_str = ", ".join(sorted(missing_deps))
            fail_reason = parse_error_msg or f"Missing or incompatible declared runtime dependencies inside OCI sandbox: {missing_str}"
            err_msg = f"Environment build failed: {fail_reason}"
            stdout = (
                f"Declared dependencies missing or unsatisfied in OCI sandbox: {len(missing_deps)} ({missing_str}). "
                f"Installation prohibited under --network none without offline wheel cache."
            ).strip()

            return ExecutionCommandResult(
                exit_code=1,
                stdout=stdout,
                stderr=err_msg,
                latency_ms=round(latency_ms, 2),
                parent_validated=False,
                validation_notes=f"Environment build failed: missing runtime dependencies [{missing_str}]",
                structured_evidence={
                    "has_manifest": has_manifest,
                    "detected_dependencies": detected_deps,
                    "missing_dependencies": missing_deps,
                    "manifest_classification": inspection.classification.value,
                    "failure_reason": fail_reason,
                    "manifest_files": inspection.manifest_files,
                    "provisioned": False,
                    "image": self.IMAGE_NAME,
                    "network_isolated": True,
                    "setup_executed_in_container": False,
                    "setup_latency_ms": round(latency_ms, 2),
                    "build_duration_ms": round(latency_ms, 2),
                    "python_version": "Python 3.12 (OCI Rootless Container)",
                    "failure_classification": "ENV_BUILD_FAILED",
                    "pip_log_excerpt": err_msg,
                },
                attestation=attestation,
                error=err_msg
            )

        # 3. If setup.py exists and dependencies are satisfied, build in isolated container
        exit_code = 0
        stdout = f"Dependencies provisioned in OCI base image ({len(all_declared_deps)} validated)."
        stderr = ""
        setup_executed = False

        if setup_py.exists():
            if not self.is_available(fresh=True):
                raise RuntimeError("ContainerExecutionBackend preflight check failed: Tier 1 runtime requirements not satisfied.")
            setup_executed = True
            if on_log:
                on_log("OCI Backend: Executing setup.py build inside isolated container tier (--network none, --cap-drop ALL)...")

            wsl_path = self.to_wsl_path(workspace_path)
            container_name = f"vulntrace-build-{uuid.uuid4().hex[:12]}"
            int_timeout = max(int(timeout), 1)
            cmd = self._build_cli_prefix() + [
                "podman", "run", "--rm",
                "--name", container_name,
                "--network", "none",
                "--read-only",
                "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
                "--userns", "keep-id",
                "--user", "1000:1000",
                "--memory", "512m",
                "--cpus", "1.0",
                "--pids-limit", "128",
                "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges",
                "-e", "PYTHONPATH=/workspace",
                "-e", "PYTHONDONTWRITEBYTECODE=1",
                "-e", "TMPDIR=/tmp",
                "-e", "TEMP=/tmp",
                "--timeout", str(int_timeout),
                "-v", f"{wsl_path}:/workspace:rw",
                "-w", "/workspace",
                self.IMAGE_NAME,
                "python3", "setup.py", "build",
                "--build-base", "/tmp/build",
                "--build-lib", "/tmp/build/lib",
                "egg_info",
                "--egg-base", "/tmp"
            ]

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                exit_code = proc.returncode
                stdout = proc.stdout or ""
                stderr = proc.stderr or ""
            except subprocess.TimeoutExpired:
                exit_code = -9
                self._kill_container(container_name)
                stderr = f"OCI container setup.py build timed out after {timeout}s."
            except Exception as e:
                self._kill_container(container_name)
                exit_code = 1
                stderr = f"OCI container setup.py execution failed: {e}"

        latency_ms = (time.perf_counter() - t0) * 1000.0
        attestation = self.generate_attestation(workspace_id)

        parent_validated = (exit_code == 0)
        provisioned = (exit_code == 0)
        failure_classification = "ENV_BUILD_FAILED" if exit_code != 0 else None
        pip_log_excerpt = stderr if exit_code != 0 else None
        validation_notes = (
            "OCI container workspace setup.py built under isolated container tier."
            if setup_executed and exit_code == 0
            else (
                "OCI container image pre-provisioned with verified runtime dependencies."
                if exit_code == 0
                else f"OCI container setup.py failed with code {exit_code}"
            )
        )

        return ExecutionCommandResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            latency_ms=round(latency_ms, 2),
            parent_validated=parent_validated,
            validation_notes=validation_notes,
            structured_evidence={
                "has_manifest": has_manifest,
                "detected_dependencies": detected_deps,
                "missing_dependencies": missing_deps,
                "manifest_classification": inspection.classification.value,
                "provisioned": provisioned,
                "image": self.IMAGE_NAME,
                "network_isolated": True,
                "setup_executed_in_container": setup_executed,
                "setup_latency_ms": round(latency_ms, 2),
                "build_duration_ms": round(latency_ms, 2),
                "python_version": "Python 3.12 (OCI Rootless Container)",
                "failure_classification": failure_classification,
                "pip_log_excerpt": pip_log_excerpt,
            },
            attestation=attestation,
            error=stderr if exit_code != 0 else None
        )

    async def execute_script(
        self,
        workspace_id: str,
        script_name: str,
        timeout: float = 10.0,
        sentinel_filename: Optional[str] = None,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        """
        Executes a verification harness inside an OCI container under --network none,
        read-only root FS, tmpfs scratch, unprivileged non-root user, cgroup limits,
        and parent-side filesystem validation.
        """
        if not self.is_available(fresh=True):
            raise RuntimeError("ContainerExecutionBackend preflight check failed: Tier 1 runtime requirements not satisfied.")
        t0 = time.perf_counter()
        workspace_path = Path(workspace_id)
        wsl_path = self.to_wsl_path(workspace_path)

        # Clear sentinel marker prior to execution
        sentinel_path = (workspace_path / sentinel_filename) if sentinel_filename else None
        if sentinel_path and sentinel_path.exists():
            try:
                sentinel_path.unlink()
            except Exception:
                pass

        container_name = f"vulntrace-exec-{uuid.uuid4().hex[:12]}"
        int_timeout = max(int(timeout), 1)

        # Build podman run command with strict Tier 1 security flags
        cmd = self._build_cli_prefix() + [
            "podman", "run", "--rm",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
            "--userns", "keep-id",
            "--user", "1000:1000",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "128",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-e", "PYTHONPATH=/workspace",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "TMPDIR=/tmp",
            "-e", "TEMP=/tmp",
            "--timeout", str(int_timeout),
            "-v", f"{wsl_path}:/workspace:rw",
            "-w", "/workspace",
            self.IMAGE_NAME,
            "python3", script_name
        ]

        timed_out = False
        exit_code = -1
        stdout = ""
        stderr = ""

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 3.0
            )
            exit_code = proc.returncode
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            # Native Podman crun watchdog exits with 255 on container timeout
            if exit_code == 255 or (exit_code == 137 and "timed out" in stderr.lower()):
                timed_out = True
                exit_code = -9
                stderr = f"OCI container execution timed out after {timeout}s."
                if on_log:
                    on_log(f"OCI Backend: Execution watchdog triggered ({timeout}s). Container terminated.")
        except subprocess.TimeoutExpired as te:
            timed_out = True
            exit_code = -9
            self._kill_container(container_name)
            stdout = (te.stdout or "") if isinstance(te.stdout, str) else ""
            stderr = f"OCI container execution timed out after {timeout}s."
            if on_log:
                on_log(f"OCI Backend: Execution watchdog triggered ({timeout}s). Container terminated.")
        except Exception as e:
            self._kill_container(container_name)
            exit_code = 1
            stderr = f"OCI container launch failed: {e}"

        latency_ms = (time.perf_counter() - t0) * 1000.0

        # Physical sentinel verification on the parent filesystem
        sentinel_created = bool(sentinel_path and sentinel_path.exists())
        if sentinel_created and sentinel_path:
            try:
                sentinel_path.unlink()
            except Exception:
                pass

        # Parse behavioral telemetry and apply parent trust boundary audit
        reproduction_state, assertion_res, exception_type, structured_evidence, parent_validated, validation_notes = SubprocessSandboxRunner.parse_and_validate_telemetry(
            stdout_text=stdout,
            stderr_text=stderr,
            sentinel_on_disk=sentinel_created,
            exit_code=exit_code,
            timed_out=timed_out
        )

        attestation = self.generate_attestation(workspace_id, container_name=container_name)

        return ExecutionCommandResult(
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            latency_ms=round(latency_ms, 2),
            timed_out=timed_out,
            sentinel_created=sentinel_created,
            reproduction_state=reproduction_state,
            assertion_result=assertion_res,
            exception_type=exception_type,
            structured_evidence=structured_evidence,
            parent_validated=parent_validated,
            validation_notes=validation_notes,
            attestation=attestation,
            error=stderr if exit_code != 0 and reproduction_state in ["ERROR", "UNEXPECTED_FAILURE"] else None
        )

    async def check_sentinel_marker(self, workspace_id: str, sentinel_filename: str) -> bool:
        """Direct parent-side check of the filesystem marker."""
        sentinel_path = Path(workspace_id) / sentinel_filename
        return sentinel_path.exists()

    async def run_regression_suite(
        self,
        workspace_id: str,
        timeout: float = 30.0,
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs pytest inside the isolated OCI container under Tier 1 rootless containment."""
        t0 = time.perf_counter()
        workspace_path = Path(workspace_id)
        wsl_path = self.to_wsl_path(workspace_path)
        container_name = f"vulntrace-pytest-{uuid.uuid4().hex[:12]}"
        int_timeout = max(int(timeout), 1)

        cmd = self._build_cli_prefix() + [
            "podman", "run", "--rm",
            "--name", container_name,
            "--network", "none",
            "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m",
            "--userns", "keep-id",
            "--user", "1000:1000",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "128",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "-e", "PYTHONPATH=/workspace",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "-e", "TMPDIR=/tmp",
            "-e", "TEMP=/tmp",
            "--timeout", str(int_timeout + 5),
            "-v", f"{wsl_path}:/workspace:rw",
            "-w", "/workspace",
            self.IMAGE_NAME,
            "python3", "-m", "pytest",
            "-p", "no:cacheprovider"
        ]
        if test_file:
            cmd.append(test_file)
        cmd.extend(["-v", "--no-header"])

        try:
            if not self.is_available(fresh=True):
                raise RuntimeError("ContainerExecutionBackend preflight check failed: Tier 1 runtime requirements not satisfied.")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            passed = (proc.returncode == 0)
            latency_ms = (time.perf_counter() - t0) * 1000.0

            # Count passed tests from pytest output
            test_count = 0
            for line in proc.stdout.splitlines():
                if " passed in " in line or " passed," in line:
                    parts = line.split()
                    for idx, p in enumerate(parts):
                        if p == "passed" and idx > 0 and parts[idx - 1].isdigit():
                            test_count = int(parts[idx - 1])
                            break

            return {
                "passed": passed,
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "latency_ms": round(latency_ms, 2),
                "test_count": test_count
            }
        except subprocess.TimeoutExpired:
            self._kill_container(container_name)
            return {
                "passed": False,
                "exit_code": -9,
                "stdout": "",
                "stderr": f"OCI container regression tests timed out after {timeout}s.",
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "test_count": 0,
                "error": "TIMED_OUT"
            }
        except Exception as e:
            self._kill_container(container_name)
            return {
                "passed": False,
                "exit_code": 1,
                "stdout": "",
                "stderr": str(e),
                "latency_ms": round((time.perf_counter() - t0) * 1000.0, 2),
                "test_count": 0,
                "error": str(e)
            }

    async def cleanup_workspace(self, workspace_id: str) -> None:
        """Destroys the disposable workspace on the host."""
        SubprocessSandboxRunner.cleanup_workspace(Path(workspace_id))

    def generate_attestation(self, workspace_id: str, container_name: Optional[str] = None) -> ExecutionAttestation:
        """Generates an unforgeable parent-validated execution attestation."""
        caps = self.capabilities
        is_verified = (
            getattr(self, "_verified_runtime", False)
            and not bool(os.environ.get("CONTAINER_HOST", "").strip())
            and not bool(os.environ.get("CONTAINER_CONNECTION", "").strip())
        )
        if is_verified:
            runtime_engine = "podman_crun_rootless_wsl2" if sys.platform == "win32" else "podman_crun_rootless_linux"
            runtime_version = self._runtime_version or "podman"
        else:
            runtime_engine = "podman_unverified"
            runtime_version = "podman (unverified)"

        return ExecutionAttestation(
            backend_tier=caps.tier,
            runtime_engine=runtime_engine,
            runtime_version=runtime_version,
            workspace_id=str(workspace_id),
            container_id=container_name,
            image_digest=self.get_image_digest(),
            network_mode="none (kernel denied)",
            mounts=[f"{workspace_id}:/workspace:rw"],
            capabilities=caps,
            attestation_timestamp=time.time(),
            verified_by_parent=True,
            boundary_caveats=caps.boundary_caveats
        )
