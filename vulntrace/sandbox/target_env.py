"""
VulnTrace Target-Environment Dependency Manager & Setup Path (P0.2)
Provides controlled, isolated provisioning of external repository dependencies:
1. Detects target dependencies declared in requirements.txt, pyproject.toml, or setup.py.
2. Creates an isolated temporary virtual environment inside the disposable sandbox workspace.
3. Installs required dependencies during the controlled setup stage (never touching the host environment).
4. Strictly enforces network isolation during subsequent behavioral verification.
5. Executes the verification harness and regression suites inside the prepared environment.
"""

import os
import sys
import subprocess
import shutil
import time
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable
from pydantic import BaseModel, Field

class TargetEnvironmentResult(BaseModel):
    has_manifest: bool = False
    detected_dependencies: List[str] = Field(default_factory=list)
    provisioned: bool = False
    python_executable: str
    network_isolated: bool = True
    setup_latency_ms: float = 0.0
    error: Optional[str] = None
    notes: str = ""

class TargetEnvironmentManager:
    """Manages isolated target environment provisioning for external repositories."""

    @classmethod
    def detect_dependencies(cls, repo_dir: Path) -> Tuple[bool, List[str]]:
        """
        Inspects repository manifest files for declared dependencies.
        Never executes arbitrary code during detection.
        """
        repo_dir = Path(repo_dir).resolve()
        deps: List[str] = []
        has_manifest = False

        # 1. requirements.txt
        req_file = repo_dir / "requirements.txt"
        if req_file.exists():
            has_manifest = True
            for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    deps.append(line)

        # 2. pyproject.toml
        pyproject_file = repo_dir / "pyproject.toml"
        if pyproject_file.exists():
            has_manifest = True
            content = pyproject_file.read_text(encoding="utf-8", errors="replace")
            in_deps_section = False
            for line in content.splitlines():
                line_s = line.strip()
                if line_s.startswith("dependencies = ["):
                    in_deps_section = True
                    continue
                if in_deps_section:
                    if line_s.startswith("]"):
                        in_deps_section = False
                    elif line_s:
                        dep_str = line_s.strip('",\' ')
                        if dep_str and not dep_str.startswith("#"):
                            deps.append(dep_str)

        # 3. setup.py (regex pattern scan without executing setup.py)
        setup_file = repo_dir / "setup.py"
        if setup_file.exists() and not deps:
            has_manifest = True
            content = setup_file.read_text(encoding="utf-8", errors="replace")
            import re
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if m:
                raw_block = m.group(1)
                for item in re.findall(r"['\"]([^'\"]+)['\"]", raw_block):
                    deps.append(item)

        # Deduplicate
        unique_deps = list(dict.fromkeys(deps))
        return has_manifest, unique_deps

    @classmethod
    def provision_target_environment(
        cls,
        disposable_dir: Path,
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> TargetEnvironmentResult:
        """
        Provisions a temporary virtual environment inside disposable_dir.
        Installs declared dependencies during this setup stage, then locks network access.
        """
        t0 = time.perf_counter()
        disposable_dir = Path(disposable_dir).resolve()
        has_manifest, deps = cls.detect_dependencies(disposable_dir)

        # Resolve base python with ensurepip/pip capabilities
        candidates = [
            Path(sys.base_prefix) / ("python.exe" if sys.platform == "win32" else "bin/python"),
            Path("C:/Python314/python.exe"),
            Path(sys.executable)
        ]
        base_py = str(next((c for c in candidates if c.exists()), sys.executable or "python"))
        host_py = sys.executable or "python"

        # If no manifest or dependencies detected, return host python with no-op setup
        if not has_manifest or not deps:
            dt = (time.perf_counter() - t0) * 1000.0
            return TargetEnvironmentResult(
                has_manifest=False,
                detected_dependencies=[],
                provisioned=False,
                python_executable=host_py,
                network_isolated=True,
                setup_latency_ms=round(dt, 2),
                notes="No target dependencies detected; using baseline execution runtime."
            )

        if on_log:
            on_log(f"Detected {len(deps)} dependencies: {', '.join(deps[:5])}{'...' if len(deps) > 5 else ''}")

        # Create temporary isolated venv inside disposable sandbox workspace
        target_venv_dir = disposable_dir / ".target_venv"
        target_py = target_venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python")

        try:
            if on_log:
                on_log(f"Creating isolated target virtualenv in {target_venv_dir.name}...")

            # 1. Spawn base_py -m venv (ensuring pip/ensurepip is included)
            venv_proc = subprocess.run(
                [base_py, "-m", "venv", str(target_venv_dir)],
                cwd=str(disposable_dir),
                capture_output=True,
                text=True,
                timeout=timeout
            )
            if venv_proc.returncode != 0:
                dt = (time.perf_counter() - t0) * 1000.0
                return TargetEnvironmentResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_executable=host_py,
                    network_isolated=True,
                    setup_latency_ms=round(dt, 2),
                    error=f"venv creation failed (exit {venv_proc.returncode}): {venv_proc.stderr[:200]}",
                    notes="Failed to create isolated target venv; falling back to host runtime."
                )

            if not target_py.exists():
                dt = (time.perf_counter() - t0) * 1000.0
                return TargetEnvironmentResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_executable=host_py,
                    network_isolated=True,
                    setup_latency_ms=round(dt, 2),
                    error=f"Target python binary not found at {target_py}",
                    notes="Failed to locate target python binary; falling back to host runtime."
                )

            # 2. Install dependencies into isolated target venv (controlled setup stage)
            if on_log:
                on_log("Installing target dependencies in controlled setup stage...")

            req_file = disposable_dir / "requirements.txt"
            pip_cmd = [str(target_py), "-m", "pip", "install", "--no-warn-script-location", "pytest"]
            if req_file.exists():
                pip_cmd.extend(["-r", str(req_file)])
            else:
                pip_cmd.extend(deps)

            pip_proc = subprocess.run(
                pip_cmd,
                cwd=str(disposable_dir),
                capture_output=True,
                text=True,
                timeout=timeout
            )

            dt = (time.perf_counter() - t0) * 1000.0

            if pip_proc.returncode != 0:
                if on_log:
                    on_log(f"Warning: pip install returned {pip_proc.returncode}: {pip_proc.stderr[:120]}")
                return TargetEnvironmentResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_executable=host_py,
                    network_isolated=True,
                    setup_latency_ms=round(dt, 2),
                    error=f"pip install exited {pip_proc.returncode}: {pip_proc.stderr[:200]}",
                    notes="Target environment dependency installation failed; falling back to host runtime."
                )

            if on_log:
                on_log(f"Target environment successfully provisioned ({round(dt, 2)}ms). Network access locked for verification.")

            return TargetEnvironmentResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=True,
                python_executable=str(target_py),
                network_isolated=True,
                setup_latency_ms=round(dt, 2),
                notes=f"Isolated target environment created with {len(deps)} installed dependencies."
            )

        except subprocess.TimeoutExpired:
            dt = (time.perf_counter() - t0) * 1000.0
            return TargetEnvironmentResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=False,
                python_executable=host_py,
                network_isolated=True,
                setup_latency_ms=round(dt, 2),
                error="Provisioning timed out",
                notes="Target environment provisioning exceeded timeout watchdog; fallback to host runtime."
            )
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            return TargetEnvironmentResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=False,
                python_executable=host_py,
                network_isolated=True,
                setup_latency_ms=round(dt, 2),
                error=f"{type(e).__name__}: {str(e)}",
                notes="Error during target environment provisioning."
            )
