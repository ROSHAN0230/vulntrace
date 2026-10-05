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
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable
from pydantic import BaseModel, Field

class TargetEnvironmentResult(BaseModel):
    has_manifest: bool = False
    detected_dependencies: List[str] = Field(default_factory=list)
    provisioned: bool = False
    python_executable: str
    python_version: str = ""
    network_isolated: bool = True
    setup_latency_ms: float = 0.0
    venv_path: Optional[str] = None
    wheel_cache_dir: Optional[str] = None
    build_output: Optional[str] = None
    pip_log_excerpt: Optional[str] = None
    failure_classification: Optional[str] = None
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
    def sanitize_provisioning_environment(cls, disposable_dir: Path) -> Dict[str, str]:
        """
        Constructs a strictly sanitized environment for dependency provisioning (P0.5.1).
        Proactively purges all credentials, API keys, tokens, auth material,
        proxy credentials, cloud credentials, SSH-related environment variables,
        CI secrets, and package-manager credentials.
        Directs temporary and profile directories into the disposable workspace.

        NOTE ON BOUNDARY LIMITATION:
        Sanitizing environment variables during pip install prevents passive credential
        theft, but arbitrary code execution during setup.py/PEP-517 build hooks remains
        inherently dangerous without VM/container isolation.
        """
        disposable_dir = Path(disposable_dir).resolve()
        appdata_dir = disposable_dir / ".appdata"
        appdata_dir.mkdir(parents=True, exist_ok=True)
        localappdata_dir = disposable_dir / ".localappdata"
        localappdata_dir.mkdir(parents=True, exist_ok=True)

        # Baseline minimal execution environment
        safe_env = {
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
            "WINDIR": os.environ.get("WINDIR", "C:\\Windows"),
            "PATH": os.environ.get("PATH", ""),
            "TEMP": str(disposable_dir),
            "TMP": str(disposable_dir),
            "USERPROFILE": str(disposable_dir),
            "HOME": str(disposable_dir),
            "APPDATA": str(appdata_dir),
            "LOCALAPPDATA": str(localappdata_dir),
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        }

        # Patterns that must NEVER leak into the provisioning environment
        prohibited_patterns = [
            "KEY", "TOKEN", "SECRET", "AUTH", "PASS", "CRED",
            "NEBIUS", "TAVILY", "OPENAI", "ANTHROPIC", "GEMINI",
            "GITHUB", "GITLAB", "BITBUCKET", "AWS", "AZURE", "GCP", "GOOGLE",
            "SSH", "PROXY_PASS", "PROXY_USER", "PROXY_AUTH", "NPM", "PYPI",
            "PIP_INDEX", "PIP_EXTRA_INDEX",
            "DOCKER", "KUBE", "CERT", "PRIVATE", "SIGN", "CI_", "SESSION",
            "COOKIE", "BEARER"
        ]

        # Specific dangerous variables to purge unconditionally
        explicit_blacklist = {
            "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GIT_ASKPASS", "SSH_ASKPASS",
            "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
            "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS",
            "TWINE_USERNAME", "TWINE_PASSWORD", "PIP_CONFIG_FILE",
            "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "NETRC", "CURL_CA_BUNDLE"
        }

        # Double check: remove anything matching prohibited patterns or blacklist
        for k in list(safe_env.keys()):
            k_upper = k.upper()
            if k in explicit_blacklist or any(pat in k_upper for pat in prohibited_patterns):
                del safe_env[k]

        return safe_env

    @classmethod
    def provision_target_environment(
        cls,
        disposable_dir: Path,
        timeout: float = 90.0,
        on_log: Optional[Callable[[str], None]] = None
    ) -> TargetEnvironmentResult:
        """
        Provisions a dedicated target virtual environment using EnvironmentBuilder (Spec §4.5).
        Maintains backward compatibility with TargetEnvironmentResult callers.
        """
        from vulntrace.envbuild.builder import EnvironmentBuilder
        disposable_dir = Path(disposable_dir).resolve()

        env_res = EnvironmentBuilder.build_environment(
            repo_dir=disposable_dir,
            workspace_id=disposable_dir.name,
            timeout=timeout,
            on_log=on_log
        )

        return TargetEnvironmentResult(
            has_manifest=env_res.has_manifest,
            detected_dependencies=env_res.detected_dependencies,
            provisioned=env_res.provisioned,
            python_executable=env_res.python_executable,
            python_version=env_res.python_version,
            network_isolated=env_res.network_isolated,
            setup_latency_ms=env_res.build_duration_ms,
            venv_path=env_res.venv_path,
            wheel_cache_dir=env_res.wheel_cache_dir,
            build_output=env_res.build_output,
            pip_log_excerpt=env_res.pip_log_excerpt,
            failure_classification=env_res.failure_classification,
            error=env_res.failure_reason,
            notes=env_res.notes
        )
