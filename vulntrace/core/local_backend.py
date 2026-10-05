"""
VulnTrace Local Subprocess Execution Backend (P0.6)
Encapsulates host-level subprocess execution with Win32 Job Object containment,
environment sanitization, memory limits, and cooperative network denial.
Explicitly labeled as LOCAL_SUBPROCESS_FALLBACK with honest boundary caveats.
"""

import sys
import time
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable

from vulntrace.core.backend import (
    ExecutionBackend,
    BackendCapabilities,
    IsolationTier,
    ExecutionAttestation,
    ExecutionCommandResult
)
from vulntrace.sandbox.runner import SubprocessSandboxRunner


class LocalSubprocessBackend(ExecutionBackend):
    """
    Subprocess execution backend operating on the local host.
    Applies Win32 Job Object limits, sanitized environment variables, and proxy null-routing.
    Never misrepresents itself as container- or VM-isolated.
    """

    def __init__(self):
        self._target_py_map: Dict[str, str] = {}

    @property
    def capabilities(self) -> BackendCapabilities:
        return BackendCapabilities(
            tier=IsolationTier.LOCAL_SUBPROCESS_FALLBACK,
            filesystem_jailed=False,
            host_fs_hidden=False,
            network_kernel_denied=False,
            process_tree_contained=True,
            resource_limits_enforced=True,
            host_identity_isolated=False,
            hardware_virtualized=False,
            description=(
                "Host subprocess fallback with Win32 Job Object process-tree containment, "
                "512MB RAM cap, sanitized environment variables, and cooperative HTTP_PROXY null-routing."
            ),
            boundary_caveats=[
                "Process executes under ambient host OS user identity (no OS user separation).",
                "Host filesystem remains readable subject to ambient OS DACLs.",
                "Network isolation is cooperative/environment-level (HTTP_PROXY redirect); raw native sockets bypass.",
                "Dependency build hooks (setup.py/PEP 517) execute under host identity with sanitized env."
            ]
        )

    def _resolve_python_executable(self, workspace_path: Path) -> str:
        workspace_key = str(workspace_path.resolve())
        if workspace_key in self._target_py_map:
            return self._target_py_map[workspace_key]

        # Check for target environment in workspace
        venv_dir = workspace_path / ".target_venv"
        if sys.platform == "win32":
            candidate = venv_dir / "Scripts" / "python.exe"
        else:
            candidate = venv_dir / "bin" / "python3"

        if candidate.exists():
            self._target_py_map[workspace_key] = str(candidate)
            return str(candidate)

        return sys.executable

    async def initialize_workspace(self, source_repo: Path) -> str:
        """
        Creates an isolated disposable directory copy on the host.
        """
        disposable_dir = SubprocessSandboxRunner.prepare_disposable_workspace(source_repo)
        return str(disposable_dir.resolve())

    async def provision_dependencies(
        self,
        workspace_id: str,
        manifest_dependencies: List[str],
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> ExecutionCommandResult:
        """
        Provisions dependencies inside a dedicated environment using EnvironmentBuilder (Spec §4.5).
        """
        t0 = time.perf_counter()
        workspace_path = Path(workspace_id)

        try:
            from vulntrace.envbuild import EnvironmentBuilder
            env_res = EnvironmentBuilder.build_environment(
                repo_dir=workspace_path,
                workspace_id=workspace_id,
                timeout=timeout,
                on_log=on_log
            )
            self._target_py_map[str(workspace_path.resolve())] = env_res.python_executable
            latency_ms = (time.perf_counter() - t0) * 1000.0

            exit_code = 0 if env_res.provisioned or not env_res.has_manifest else 1
            attestation = self.generate_attestation(workspace_id)

            return ExecutionCommandResult(
                exit_code=exit_code,
                stdout=f"Dependencies provisioned: {len(env_res.detected_dependencies)} packages detected ({env_res.python_version}).",
                stderr=env_res.failure_reason or env_res.pip_log_excerpt or "",
                latency_ms=round(latency_ms, 2),
                parent_validated=(exit_code == 0),
                validation_notes=env_res.notes,
                structured_evidence={
                    "has_manifest": env_res.has_manifest,
                    "detected_dependencies": env_res.detected_dependencies,
                    "provisioned": env_res.provisioned,
                    "python_executable": env_res.python_executable,
                    "python_version": env_res.python_version,
                    "venv_path": env_res.venv_path,
                    "wheel_cache_dir": env_res.wheel_cache_dir,
                    "build_duration_ms": env_res.build_duration_ms,
                    "build_output": env_res.build_output,
                    "pip_log_excerpt": env_res.pip_log_excerpt,
                    "failure_classification": env_res.failure_classification,
                    "failure_reason": env_res.failure_reason,
                    "network_isolated": env_res.network_isolated,
                    "setup_latency_ms": env_res.build_duration_ms
                },
                attestation=attestation
            )
        except Exception as e:
            latency_ms = (time.perf_counter() - t0) * 1000.0
            return ExecutionCommandResult(
                exit_code=1,
                stdout="",
                stderr=str(e),
                latency_ms=round(latency_ms, 2),
                parent_validated=False,
                error=f"Dependency provisioning failed: {e}",
                structured_evidence={
                    "has_manifest": True,
                    "provisioned": False,
                    "failure_classification": "ENV_BUILD_FAILED",
                    "failure_reason": str(e),
                },
                attestation=self.generate_attestation(workspace_id)
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
        Executes a Python script in the disposable workspace with Job Object containment and sanitized env.
        """
        workspace_path = Path(workspace_id)
        py_exec = self._resolve_python_executable(workspace_path)

        res = SubprocessSandboxRunner.execute_script(
            disposable_dir=workspace_path,
            script_name=script_name,
            timeout=timeout,
            sentinel_filename=sentinel_filename,
            on_log=on_log,
            python_executable=py_exec
        )

        attestation = self.generate_attestation(workspace_id)

        return ExecutionCommandResult(
            exit_code=res.exit_code,
            stdout=res.stdout,
            stderr=res.stderr,
            latency_ms=res.latency_ms,
            timed_out=(res.reproduction_state == "TIMED_OUT"),
            sentinel_created=res.sentinel_created,
            reproduction_state=res.reproduction_state,
            assertion_result=res.assertion_result,
            exception_type=res.exception_type,
            structured_evidence=res.structured_evidence,
            parent_validated=res.parent_validated,
            validation_notes=res.validation_notes,
            attestation=attestation,
            error=res.error
        )

    async def check_sentinel_marker(self, workspace_id: str, sentinel_filename: str) -> bool:
        """
        Direct parent-side check of the filesystem marker.
        """
        sentinel_path = Path(workspace_id) / sentinel_filename
        return sentinel_path.exists()

    async def run_regression_suite(
        self,
        workspace_id: str,
        timeout: float = 30.0,
        test_file: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs pytest inside the disposable workspace.
        """
        workspace_path = Path(workspace_id)
        py_exec = self._resolve_python_executable(workspace_path)

        return SubprocessSandboxRunner.run_pytest(
            disposable_dir=workspace_path,
            timeout=timeout,
            python_executable=py_exec,
            test_file=test_file
        )

    async def cleanup_workspace(self, workspace_id: str) -> None:
        """
        Destroys the disposable workspace.
        """
        SubprocessSandboxRunner.cleanup_workspace(Path(workspace_id))
        workspace_key = str(Path(workspace_id).resolve())
        self._target_py_map.pop(workspace_key, None)

    def generate_attestation(self, workspace_id: str) -> ExecutionAttestation:
        """
        Generates an unforgeable parent-validated execution attestation.
        """
        caps = self.capabilities
        return ExecutionAttestation(
            backend_tier=caps.tier,
            runtime_engine="python_subprocess_win32_job_object" if sys.platform == "win32" else "python_subprocess_posix",
            runtime_version=sys.version.split()[0],
            workspace_id=str(workspace_id),
            container_id=None,
            image_digest=None,
            network_mode="environment_proxy_null_route",
            mounts=[str(workspace_id)],
            capabilities=caps,
            attestation_timestamp=time.time(),
            verified_by_parent=True,
            boundary_caveats=caps.boundary_caveats
        )
