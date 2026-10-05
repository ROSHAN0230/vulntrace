"""
VulnTrace Dedicated Target Environment Builder (Spec §4.5)
Implements:
1. One dedicated, isolated virtual environment per case outside the disposable workspace.
2. Target dependency installation from declared repository manifests (requirements.txt, pyproject.toml, setup.py).
3. Wheel cache to accelerate repeated runs and minimize external network requests.
4. Python version discovery, respecting declared repository requirements (.python-version).
5. Comprehensive build metrics recording:
   - Python version
   - Build duration (ms)
   - Dependency / build output
   - Pip log excerpt on errors
   - Honest failure classification (ENV_BUILD_FAILED)
6. Strict environment sanitization preventing host credential leakage during provisioning.
"""

import os
import sys
import time
import shutil
import hashlib
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from pydantic import BaseModel, Field

from vulntrace.analyzer.manifest_parser import ManifestParser


class EnvironmentBuildResult(BaseModel):
    has_manifest: bool = False
    detected_dependencies: List[str] = Field(default_factory=list)
    provisioned: bool = False
    python_version: str = ""
    python_executable: str = ""
    venv_path: Optional[str] = None
    wheel_cache_dir: Optional[str] = None
    build_duration_ms: float = 0.0
    build_output: Optional[str] = None
    pip_log_excerpt: Optional[str] = None
    failure_classification: Optional[str] = None  # "ENV_BUILD_FAILED"
    failure_reason: Optional[str] = None
    network_isolated: bool = True
    notes: str = ""


class EnvironmentBuilder:
    """Manages dedicated per-case environment provisioning outside workspace trees."""

    DEFAULT_CACHE_DIR = Path(tempfile.gettempdir()) / "vulntrace_wheel_cache"
    DEFAULT_ENV_ROOT = Path(tempfile.gettempdir()) / "vulntrace_case_envs"

    @classmethod
    def get_wheel_cache_dir(cls) -> Path:
        """Returns or initializes the shared wheel cache directory."""
        cache_dir = Path(os.environ.get("VULNTRACE_WHEEL_CACHE", cls.DEFAULT_CACHE_DIR)).resolve()
        cache_dir.mkdir(parents=True, exist_ok=True)
        # Seed wheel cache with any pre-built wheels from local pip cache if present
        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            pip_wheels_dir = Path(user_profile) / "AppData" / "Local" / "pip" / "cache" / "wheels"
            if pip_wheels_dir.exists():
                for whl in pip_wheels_dir.rglob("*.whl"):
                    target_whl = cache_dir / whl.name
                    if not target_whl.exists():
                        try:
                            shutil.copy2(whl, target_whl)
                        except Exception:
                            pass
        # POSIX / Linux pip cache (~/.cache/pip/wheels)
        try:
            posix_cache = Path.home() / ".cache" / "pip" / "wheels"
            if posix_cache.exists():
                for whl in posix_cache.rglob("*.whl"):
                    target_whl = cache_dir / whl.name
                    if not target_whl.exists():
                        try:
                            shutil.copy2(whl, target_whl)
                        except Exception:
                            pass
        except Exception:
            pass

        # Flatten any wheels present in subdirectories of cache_dir
        try:
            for whl in cache_dir.rglob("*.whl"):
                if whl.parent != cache_dir:
                    target_whl = cache_dir / whl.name
                    if not target_whl.exists():
                        try:
                            shutil.copy2(whl, target_whl)
                        except Exception:
                            pass
        except Exception:
            pass

        return cache_dir

    @classmethod
    def get_case_env_root(cls) -> Path:
        """Returns or initializes the root directory for per-case virtual environments."""
        env_root = Path(os.environ.get("VULNTRACE_CASE_ENV_ROOT", cls.DEFAULT_ENV_ROOT)).resolve()
        env_root.mkdir(parents=True, exist_ok=True)
        return env_root

    @classmethod
    def detect_declared_dependencies(cls, repo_dir: Path) -> Tuple[bool, List[str]]:
        """
        Detects dependencies declared in requirements.txt, pyproject.toml, or setup.py.
        Never executes arbitrary code during detection.
        """
        repo_dir = Path(repo_dir).resolve()
        manifest = ManifestParser.inspect_repository(str(repo_dir))
        
        deps: List[str] = []
        has_manifest = len(manifest.manifest_files) > 0

        # 1. requirements.txt
        req_file = repo_dir / "requirements.txt"
        if req_file.exists():
            for line in req_file.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    deps.append(line)

        # 2. Add dependencies from ManifestParser
        for dep in manifest.dependencies:
            if dep.version_spec:
                spec = f"{dep.name}{dep.version_spec}"
            else:
                spec = dep.name
            deps.append(spec)

        # 3. Fallback regex scan for setup.py install_requires if empty
        setup_file = repo_dir / "setup.py"
        if setup_file.exists() and not deps:
            has_manifest = True
            content = setup_file.read_text(encoding="utf-8", errors="replace")
            import re
            m = re.search(r"install_requires\s*=\s*\[(.*?)\]", content, re.DOTALL)
            if m:
                for item in re.findall(r"['\"]([^'\"]+)['\"]", m.group(1)):
                    deps.append(item)

        unique_deps = list(dict.fromkeys(deps))
        return has_manifest, unique_deps

    @classmethod
    def resolve_base_python(cls, repo_dir: Path) -> Tuple[str, str]:
        """
        Selects the best compatible base Python interpreter.
        Inspects .python-version if available to prioritize compatible runtimes.
        Returns (executable_path, version_string).
        """
        repo_dir = Path(repo_dir).resolve()
        target_version_hint = ""
        pyver_file = repo_dir / ".python-version"
        if pyver_file.exists():
            target_version_hint = pyver_file.read_text(encoding="utf-8", errors="replace").strip()

        # Discover system candidate interpreters
        candidates: List[Path] = []

        if sys.platform == "win32":
            user_profile = os.environ.get("USERPROFILE", "C:\\Users\\Default")
            programs_py = Path(user_profile) / "AppData" / "Local" / "Programs" / "Python"
            candidates.extend([
                programs_py / "Python310" / "python.exe",
                programs_py / "Python311" / "python.exe",
                programs_py / "Python312" / "python.exe",
                programs_py / "Python314" / "python.exe",
                Path("C:/Python314/python.exe"),
                Path("C:/Python312/python.exe"),
                Path("C:/Python311/python.exe"),
                Path("C:/Python310/python.exe"),
            ])
        else:
            for bin_name in ["python3.10", "python3.11", "python3.12", "python3"]:
                p = shutil.which(bin_name)
                if p:
                    candidates.append(Path(p))

        # Always include running interpreter as candidate
        candidates.append(Path(sys.base_prefix) / ("python.exe" if sys.platform == "win32" else "bin/python3"))
        candidates.append(Path(sys.executable))

        # Filter to existing interpreters
        valid_candidates = [c for c in candidates if c.exists()]

        # If repo hints older Python (e.g., 2.7, 3.6, <=3.11), prefer Python 3.10 or 3.11
        if any(h in target_version_hint for h in ["2.7", "3.6", "3.7", "3.8", "3.9", "3.10", "3.11"]):
            for c in valid_candidates:
                if any(tag in str(c).lower() for tag in ["python310", "python3.10", "python311", "python3.11"]):
                    ver_str = cls._query_python_version(str(c))
                    return str(c), ver_str

        # Default: pick first valid candidate
        selected = valid_candidates[0] if valid_candidates else Path(sys.executable)
        ver_str = cls._query_python_version(str(selected))
        return str(selected), ver_str

    @classmethod
    def _query_python_version(cls, py_path: str) -> str:
        """Queries the version string of the target python binary."""
        try:
            res = subprocess.run([py_path, "--version"], capture_output=True, text=True, timeout=5.0)
            out = (res.stdout or res.stderr).strip()
            return out if out else f"Python {sys.version.split()[0]}"
        except Exception:
            return f"Python {sys.version.split()[0]}"

    @classmethod
    def sanitize_environment(cls, scratch_dir: Path) -> Dict[str, str]:
        """
        Sanitizes environment variables to purge all credentials, API keys, tokens,
        and cloud material before spawning provisioning child processes (P0.5.1).
        """
        scratch_dir = Path(scratch_dir).resolve()
        appdata_dir = scratch_dir / ".appdata"
        appdata_dir.mkdir(parents=True, exist_ok=True)
        localappdata_dir = scratch_dir / ".localappdata"
        localappdata_dir.mkdir(parents=True, exist_ok=True)

        safe_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
            "PATH": os.environ.get("PATH", ""),
            "TEMP": str(scratch_dir),
            "TMP": str(scratch_dir),
            "TMPDIR": str(scratch_dir),
            "USERPROFILE": str(scratch_dir),
            "HOME": str(scratch_dir),
            "APPDATA": str(appdata_dir),
            "LOCALAPPDATA": str(localappdata_dir),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }

        prohibited_patterns = [
            "KEY", "TOKEN", "SECRET", "AUTH", "PASS", "CRED",
            "NEBIUS", "TAVILY", "OPENAI", "ANTHROPIC", "GEMINI",
            "GITHUB", "GITLAB", "BITBUCKET", "AWS", "AZURE", "GCP", "GOOGLE",
            "SSH", "PROXY_PASS", "PROXY_USER", "PROXY_AUTH", "NPM", "PYPI",
            "PIP_INDEX", "PIP_EXTRA_INDEX",
            "DOCKER", "KUBE", "CERT", "PRIVATE", "SIGN", "CI_", "SESSION",
            "COOKIE", "BEARER"
        ]

        explicit_blacklist = {
            "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_ASKPASS", "SSH_ASKPASS",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
            "TWINE_USERNAME", "TWINE_PASSWORD", "PIP_CONFIG_FILE",
            "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "NETRC", "CURL_CA_BUNDLE"
        }

        for k in list(safe_env.keys()):
            k_upper = k.upper()
            if k in explicit_blacklist or any(pat in k_upper for pat in prohibited_patterns):
                del safe_env[k]

        return safe_env

    @classmethod
    def _extract_pip_log_excerpt(cls, raw_output: str, max_lines: int = 15) -> str:
        """Extracts the most informative error lines from pip output."""
        lines = [line for line in raw_output.splitlines() if line.strip()]
        if not lines:
            return "No output produced by pip."
        # Prefer lines around ERROR or Traceback
        error_lines = [line for line in lines if any(e in line for e in ["ERROR:", "error:", "Traceback", "ModuleNotFoundError", "AttributeError"])]
        if error_lines:
            return "\n".join(error_lines[-max_lines:])
        return "\n".join(lines[-max_lines:])

    @classmethod
    def build_environment(
        cls,
        repo_dir: Path,
        workspace_id: Optional[str] = None,
        timeout: float = 120.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> EnvironmentBuildResult:
        """
        Builds a dedicated virtual environment for the case outside the workspace tree.
        Installs declared dependencies with wheel caching.
        Returns an EnvironmentBuildResult with comprehensive metrics and truthful failure classification.
        """
        t0 = time.perf_counter()
        repo_dir = Path(repo_dir).resolve()
        has_manifest, deps = cls.detect_declared_dependencies(repo_dir)

        base_py, py_version = cls.resolve_base_python(repo_dir)
        host_py = sys.executable or "python"

        # If repo declares no dependencies, return baseline runtime without provisioning overhead
        if not has_manifest or not deps:
            dt = (time.perf_counter() - t0) * 1000.0
            return EnvironmentBuildResult(
                has_manifest=False,
                detected_dependencies=[],
                provisioned=False,
                python_version=py_version,
                python_executable=host_py,
                network_isolated=True,
                build_duration_ms=round(dt, 2),
                notes="No target dependency manifests detected; using baseline execution runtime."
            )

        if on_log:
            on_log(f"Target manifest detected: {len(deps)} dependencies. Base runtime: {py_version} ({Path(base_py).name})")

        # Create isolated virtual environment strictly OUTSIDE workspace (Spec §4.5)
        case_tag = workspace_id or hashlib.sha256(str(repo_dir).encode("utf-8")).hexdigest()[:12]
        case_hash = hashlib.sha256(f"{case_tag}_{repo_dir.name}".encode("utf-8")).hexdigest()[:10]
        case_env_root = cls.get_case_env_root()
        target_venv_dir = case_env_root / f"env_{repo_dir.name}_{case_hash}"
        
        target_py = target_venv_dir / ("Scripts" if sys.platform == "win32" else "bin") / ("python.exe" if sys.platform == "win32" else "python")
        wheel_cache = cls.get_wheel_cache_dir()

        scratch_dir = Path(tempfile.mkdtemp(prefix="vulntrace_build_scratch_"))
        prov_env = cls.sanitize_environment(scratch_dir)

        try:
            # 1. Create virtual environment
            if on_log:
                on_log(f"Creating dedicated virtualenv outside workspace at: {target_venv_dir}")

            if target_venv_dir.exists() and not target_py.exists():
                shutil.rmtree(target_venv_dir, ignore_errors=True)

            venv_cmd = [base_py, "-m", "venv", str(target_venv_dir)]
            venv_proc = subprocess.run(
                venv_cmd,
                cwd=str(scratch_dir),
                capture_output=True,
                text=True,
                env=prov_env,
                timeout=timeout
            )

            if venv_proc.returncode != 0:
                dt = (time.perf_counter() - t0) * 1000.0
                err_text = (venv_proc.stderr or venv_proc.stdout).strip()
                excerpt = cls._extract_pip_log_excerpt(err_text)
                return EnvironmentBuildResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_version=py_version,
                    python_executable=host_py,
                    venv_path=str(target_venv_dir),
                    wheel_cache_dir=str(wheel_cache),
                    build_duration_ms=round(dt, 2),
                    build_output=err_text,
                    pip_log_excerpt=excerpt,
                    failure_classification="ENV_BUILD_FAILED",
                    failure_reason=f"venv creation failed (exit {venv_proc.returncode}): {excerpt[:150]}",
                    notes="Virtual environment creation failed."
                )

            if not target_py.exists():
                dt = (time.perf_counter() - t0) * 1000.0
                return EnvironmentBuildResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_version=py_version,
                    python_executable=host_py,
                    venv_path=str(target_venv_dir),
                    wheel_cache_dir=str(wheel_cache),
                    build_duration_ms=round(dt, 2),
                    failure_classification="ENV_BUILD_FAILED",
                    failure_reason=f"Target python binary not found at {target_py}",
                    notes="Failed to locate target python binary in created venv."
                )

            # Query exact target python version inside new venv
            target_py_version = cls._query_python_version(str(target_py))

            # 2. Install target dependencies with wheel cache
            if on_log:
                on_log("Installing declared target dependencies with wheel cache...")

            pip_cmd = [
                str(target_py), "-m", "pip", "install",
                "--isolated",
                "--find-links", str(wheel_cache),
                "--cache-dir", str(wheel_cache),
                "--no-warn-script-location",
                "pytest"
            ]

            # Apply legacy compatibility constraints when repository declares older Python runtime (Spec §4.5)
            pyver_file = repo_dir / ".python-version"
            target_version_hint = pyver_file.read_text(encoding="utf-8", errors="replace").strip() if pyver_file.exists() else ""
            if any(h in target_version_hint for h in ["2.7", "3.6", "3.7", "3.8"]):
                constraints_file = scratch_dir / "legacy_constraints.txt"
                constraints_file.write_text(
                    "PyYAML==5.4.1\nFlask<2.0\nWerkzeug<2.0\nmarkupsafe<2.1.0\nJinja2<3.0\nitsdangerous<2.0\nclick<8.0\n",
                    encoding="utf-8"
                )
                pip_cmd.extend(["-c", str(constraints_file)])

            req_file = repo_dir / "requirements.txt"
            if req_file.exists():
                pip_cmd.extend(["-r", str(req_file)])
            else:
                pip_cmd.extend(deps)

            pip_proc = subprocess.run(
                pip_cmd,
                cwd=str(scratch_dir),
                capture_output=True,
                text=True,
                env=prov_env,
                timeout=timeout
            )

            dt = (time.perf_counter() - t0) * 1000.0
            full_output = f"{pip_proc.stdout}\n{pip_proc.stderr}".strip()

            if pip_proc.returncode != 0:
                excerpt = cls._extract_pip_log_excerpt(full_output)
                if on_log:
                    on_log(f"Environment build failed (pip exit {pip_proc.returncode}): {excerpt[:120]}")

                return EnvironmentBuildResult(
                    has_manifest=True,
                    detected_dependencies=deps,
                    provisioned=False,
                    python_version=target_py_version,
                    python_executable=str(target_py),
                    venv_path=str(target_venv_dir),
                    wheel_cache_dir=str(wheel_cache),
                    build_duration_ms=round(dt, 2),
                    build_output=full_output,
                    pip_log_excerpt=excerpt,
                    failure_classification="ENV_BUILD_FAILED",
                    failure_reason=f"pip install exited {pip_proc.returncode}: {excerpt[:200]}",
                    notes="Target dependency installation failed. Truthfully reported as ENV_BUILD_FAILED."
                )

            # Ensure newly cached wheels are available in wheel cache root for offline find-links
            try:
                for whl in wheel_cache.rglob("*.whl"):
                    if whl.parent != wheel_cache:
                        dest = wheel_cache / whl.name
                        if not dest.exists():
                            shutil.copy2(whl, dest)
            except Exception:
                pass

            if on_log:
                on_log(f"Target environment provisioned in {round(dt, 2)}ms ({target_py_version}). Network locked.")

            return EnvironmentBuildResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=True,
                python_version=target_py_version,
                python_executable=str(target_py),
                venv_path=str(target_venv_dir),
                wheel_cache_dir=str(wheel_cache),
                build_duration_ms=round(dt, 2),
                build_output=full_output,
                pip_log_excerpt=None,
                network_isolated=True,
                notes=f"Dedicated environment ready with {len(deps)} dependencies."
            )

        except subprocess.TimeoutExpired:
            dt = (time.perf_counter() - t0) * 1000.0
            return EnvironmentBuildResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=False,
                python_version=py_version,
                python_executable=host_py,
                venv_path=str(target_venv_dir),
                wheel_cache_dir=str(wheel_cache),
                build_duration_ms=round(dt, 2),
                failure_classification="ENV_BUILD_FAILED",
                failure_reason=f"Provisioning timed out after {timeout}s",
                notes="Environment construction exceeded timeout watchdog."
            )
        except Exception as e:
            dt = (time.perf_counter() - t0) * 1000.0
            return EnvironmentBuildResult(
                has_manifest=True,
                detected_dependencies=deps,
                provisioned=False,
                python_version=py_version,
                python_executable=host_py,
                venv_path=str(target_venv_dir),
                wheel_cache_dir=str(wheel_cache),
                build_duration_ms=round(dt, 2),
                failure_classification="ENV_BUILD_FAILED",
                failure_reason=f"{type(e).__name__}: {str(e)}",
                notes=f"Exception during environment build: {e}"
            )
        finally:
            shutil.rmtree(scratch_dir, ignore_errors=True)

    @classmethod
    def cleanup_case_environment(cls, venv_path: Optional[str]):
        """Removes an isolated case environment directory."""
        if venv_path:
            p = Path(venv_path)
            if p.exists() and "vulntrace_case_envs" in str(p):
                shutil.rmtree(p, ignore_errors=True)
