"""
VulnTrace Target-Environment Dependency Manager & Setup Path (P0.2)
Provides controlled, isolated provisioning of external repository dependencies:
1. Statically inspects target manifests (requirements.txt, pyproject.toml, setup.py, setup.cfg).
2. Distinguishes supported static declarations, confirmed absence of dependencies,
   dynamic expressions, unsupported ecosystems, and parsing errors.
3. Strictly enforces fail-closed behavior for unsupported or ambiguous packaging constructs.
4. Protects against workspace directory traversal and symlink escapes in recursive inclusions.
5. Preserves existing sanitized provisioning environment generation for local fallbacks.
"""

import os
import ast
import tomllib
import configparser
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Callable, Set
from pydantic import BaseModel, Field


class ManifestClassification(str, Enum):
    CONFIRMED_NO_DEPENDENCIES = "CONFIRMED_NO_DEPENDENCIES"
    SUPPORTED_VALIDATED = "SUPPORTED_VALIDATED"
    DYNAMIC_UNVERIFIED = "DYNAMIC_UNVERIFIED"
    UNSUPPORTED_OR_AMBIGUOUS = "UNSUPPORTED_OR_AMBIGUOUS"
    PARSE_ERROR = "PARSE_ERROR"


class ManifestInspectionResult(BaseModel):
    has_manifest: bool = False
    dependencies: List[str] = Field(default_factory=list)
    classification: ManifestClassification = ManifestClassification.CONFIRMED_NO_DEPENDENCIES
    failure_reason: Optional[str] = None
    manifest_files: List[str] = Field(default_factory=list)
    unsupported_directives: List[str] = Field(default_factory=list)


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


def _is_path_within_root(path: Path, root: Path) -> bool:
    """Verifies that both unresolved and resolved absolute paths lie within root."""
    try:
        resolved_root = root.resolve()
        resolved_path = path.resolve()
        unresolved_abs = Path(os.path.abspath(path))
        if not resolved_path.is_relative_to(resolved_root):
            return False
        if not unresolved_abs.is_relative_to(resolved_root):
            return False
        return True
    except (OSError, ValueError, TypeError):
        return False


class TargetEnvironmentManager:
    """Manages isolated target environment provisioning for external repositories."""

    @classmethod
    def _parse_requirements_file(
        cls,
        file_path: Path,
        workspace_root: Path,
        seen_files: Set[Path],
        depth: int = 0
    ) -> Tuple[List[str], Optional[ManifestClassification], Optional[str], List[str]]:
        """
        Recursively parses requirements.txt files with strict cycle detection,
        workspace confinement checks, and fail-closed handling for unsupported directives.
        Preserves detected dependencies while recording classification failures.
        """
        try:
            resolved_file = file_path.resolve()
        except (OSError, ValueError) as e:
            return [], ManifestClassification.PARSE_ERROR, f"Cannot resolve requirements file path {file_path}: {e}", [str(file_path)]

        if not _is_path_within_root(file_path, workspace_root):
            return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, f"Security boundary violation: requirements file escapes workspace root: {file_path.name}", [str(file_path)]

        if not file_path.exists() or not file_path.is_file():
            return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, f"Referenced requirements file does not exist: {file_path}", [str(file_path)]

        if resolved_file in seen_files:
            return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, f"Circular requirements inclusion detected: {file_path.name}", [str(file_path)]

        if depth > 10:
            return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, "Recursive requirements inclusion depth limit (10) exceeded.", [str(file_path)]

        seen = seen_files | {resolved_file}
        manifest_files = [str(file_path)]
        deps: List[str] = []
        first_classification: Optional[ManifestClassification] = None
        first_reason: Optional[str] = None

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return [], ManifestClassification.PARSE_ERROR, f"Failed to read requirements file {file_path.name}: {e}", manifest_files

        for line_num, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Recursive inclusion: -r / --requirement
            if line.startswith("-r ") or line.startswith("--requirement ") or line == "-r" or line == "--requirement":
                target_str = line[2:].strip() if line.startswith("-r") else line[13:].strip()
                target_str = target_str.strip('"',).strip("'")
                if not target_str:
                    return deps, ManifestClassification.PARSE_ERROR, f"Empty requirement include directive at {file_path.name}:{line_num}", manifest_files

                target_path = (file_path.parent / target_str)
                sub_deps, sub_class, sub_reason, sub_files = cls._parse_requirements_file(
                    target_path, workspace_root, seen, depth + 1
                )
                manifest_files.extend(sub_files)
                deps.extend(sub_deps)
                if sub_class and not first_classification:
                    first_classification = sub_class
                    first_reason = sub_reason
                continue

            # Unsupported directives that must fail closed under offline Tier 1 policy
            if line.startswith("-c ") or line.startswith("--constraint ") or line == "-c" or line == "--constraint":
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Constraint files (-c/--constraint) are unsupported under offline Tier 1 container preflight ({file_path.name}:{line_num})."
                continue

            if any(line.startswith(prefix) for prefix in ("-i ", "--index-url ", "--extra-index-url ")):
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Remote package index options (--index-url) are prohibited under offline Tier 1 container policy ({file_path.name}:{line_num})."
                continue

            if any(line.startswith(prefix) for prefix in ("-f ", "--find-links ")):
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Find-links option (--find-links) is unsupported without verified offline cache ({file_path.name}:{line_num})."
                continue

            if any(line.startswith(prefix) for prefix in ("-e ", "--editable ")):
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Editable requirement installations (-e/--editable) are unsupported under offline Tier 1 container policy ({file_path.name}:{line_num})."
                continue

            if "--hash" in line:
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Requirement hashes (--hash) are unsupported under offline Tier 1 container policy ({file_path.name}:{line_num})."
                continue

            # Direct URL or VCS dependencies
            if any(proto in line for proto in ("@ http://", "@ https://", "git+", "hg+", "svn+", "bzr+")):
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Direct URL/VCS requirement '{line}' is prohibited under offline Tier 1 container policy ({file_path.name}:{line_num})."
                continue

            # Generic unhandled flag / option starting with '-'
            if line.startswith("-"):
                if not first_classification:
                    first_classification = ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS
                    first_reason = f"Unsupported requirement directive '{line}' under offline Tier 1 container policy ({file_path.name}:{line_num})."
                continue

            # Strip inline comments (e.g. `package >= 1.0  # comment`)
            dep_clean = line.split(" #")[0].strip()
            if dep_clean:
                deps.append(dep_clean)

        return deps, first_classification, first_reason, manifest_files

    @classmethod
    def _inspect_setup_py(
        cls,
        setup_file: Path
    ) -> Tuple[List[str], Optional[ManifestClassification], Optional[str]]:
        """
        Statically parses setup.py using AST. Extracts literal install_requires.
        Detects dynamic expressions and unrecognized patterns without executing setup code.
        """
        try:
            content = setup_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(content, filename=str(setup_file))
        except SyntaxError as e:
            return [], ManifestClassification.PARSE_ERROR, f"Syntax error in setup.py: {e}"
        except Exception as e:
            return [], ManifestClassification.PARSE_ERROR, f"Failed to parse setup.py: {e}"

        setup_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id == "setup":
                    setup_calls.append(node)
                elif isinstance(func, ast.Attribute) and func.attr == "setup":
                    setup_calls.append(node)

        if len(setup_calls) != 1:
            return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, f"setup.py exists but conventional setup() call could not be identified uniquely (found {len(setup_calls)} calls)."

        setup_call = setup_calls[0]
        kw_match = [kw for kw in setup_call.keywords if kw.arg == "install_requires"]
        if not kw_match:
            # install_requires omitted in setup() call; caller checks setup.cfg or concludes empty
            return [], None, None

        kw = kw_match[0]
        if isinstance(kw.value, (ast.List, ast.Tuple)):
            deps = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    deps.append(elt.value.strip())
                else:
                    return deps, ManifestClassification.DYNAMIC_UNVERIFIED, f"Dynamic non-string expression ({type(elt).__name__}) detected in setup.py install_requires list."
            return deps, None, None
        else:
            return [], ManifestClassification.DYNAMIC_UNVERIFIED, f"Dynamic setup.py install_requires expression ({type(kw.value).__name__}) detected."

    @classmethod
    def _inspect_setup_cfg(
        cls,
        setup_cfg_file: Path
    ) -> Tuple[List[str], Optional[ManifestClassification], Optional[str]]:
        """Parses declarative setup.cfg [options] install_requires."""
        config = configparser.ConfigParser()
        try:
            content = setup_cfg_file.read_text(encoding="utf-8", errors="replace")
            config.read_string(content)
        except Exception as e:
            return [], ManifestClassification.PARSE_ERROR, f"Malformed setup.cfg: {e}"

        if config.has_section("options") and config.has_option("options", "install_requires"):
            raw = config.get("options", "install_requires")
            deps = [line.strip() for line in raw.splitlines() if line.strip() and not line.strip().startswith("#")]
            return deps, None, None
        return [], None, None

    @classmethod
    def _inspect_pyproject_toml(
        cls,
        pyproject_file: Path
    ) -> Tuple[List[str], Optional[ManifestClassification], Optional[str]]:
        """Parses PEP 621 dependencies from pyproject.toml and flags unsupported ecosystems."""
        try:
            content = pyproject_file.read_text(encoding="utf-8", errors="replace")
            data = tomllib.loads(content)
        except Exception as e:
            return [], ManifestClassification.PARSE_ERROR, f"Malformed pyproject.toml: {e}"

        # Detect unsupported Poetry ecosystem
        if "tool" in data and isinstance(data["tool"], dict):
            if "poetry" in data["tool"] and isinstance(data["tool"]["poetry"], dict):
                if "dependencies" in data["tool"]["poetry"]:
                    return [], ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS, "Poetry dependencies in pyproject.toml are unsupported under offline Tier 1 container preflight."

        # Detect dynamic PEP 621 dependencies
        dynamic_fields = data.get("project", {}).get("dynamic", [])
        if isinstance(dynamic_fields, list) and "dependencies" in dynamic_fields:
            return [], ManifestClassification.DYNAMIC_UNVERIFIED, "PEP 621 dynamic dependencies declared in pyproject.toml cannot be verified statically."

        # Extract static PEP 621 dependencies
        deps: List[str] = []
        if "project" in data and isinstance(data["project"], dict):
            raw_deps = data["project"].get("dependencies")
            if raw_deps is not None:
                if isinstance(raw_deps, list):
                    for d in raw_deps:
                        if isinstance(d, str):
                            deps.append(d.strip())
                        else:
                            return deps, ManifestClassification.DYNAMIC_UNVERIFIED, "Non-string entry detected in project.dependencies list."
                else:
                    return [], ManifestClassification.PARSE_ERROR, "Invalid project.dependencies format (expected list of strings)."

        return deps, None, None

    @classmethod
    def inspect_manifests(cls, repo_dir: Path) -> ManifestInspectionResult:
        """
        Performs comprehensive, conservative inspection of all repository dependency manifests.
        Distinguishes validated static requirements, confirmed absence of dependencies,
        dynamic expressions, and unsupported packaging ecosystems.
        """
        repo_dir = Path(repo_dir).resolve()
        manifest_files: List[str] = []
        collected_deps: List[str] = []

        # 1. Reject unsupported packaging ecosystems
        if (repo_dir / "Pipfile").exists() or (repo_dir / "Pipfile.lock").exists():
            fname = "Pipfile" if (repo_dir / "Pipfile").exists() else "Pipfile.lock"
            return ManifestInspectionResult(
                has_manifest=True,
                classification=ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS,
                failure_reason="Pipenv packaging (Pipfile/Pipfile.lock) is unsupported under offline Tier 1 container preflight.",
                manifest_files=[fname]
            )

        if (repo_dir / "poetry.lock").exists():
            return ManifestInspectionResult(
                has_manifest=True,
                classification=ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS,
                failure_reason="Poetry packaging (poetry.lock) is unsupported under offline Tier 1 container preflight.",
                manifest_files=["poetry.lock"]
            )

        if (repo_dir / "environment.yml").exists() or (repo_dir / "environment.yaml").exists():
            fname = "environment.yml" if (repo_dir / "environment.yml").exists() else "environment.yaml"
            return ManifestInspectionResult(
                has_manifest=True,
                classification=ManifestClassification.UNSUPPORTED_OR_AMBIGUOUS,
                failure_reason="Conda packaging (environment.yml/yaml) is unsupported under offline Tier 1 container preflight.",
                manifest_files=[fname]
            )

        # 2. pyproject.toml
        pyproject_file = repo_dir / "pyproject.toml"
        if pyproject_file.exists():
            manifest_files.append("pyproject.toml")
            p_deps, p_class, p_reason = cls._inspect_pyproject_toml(pyproject_file)
            collected_deps.extend(p_deps)
            if p_class:
                return ManifestInspectionResult(
                    has_manifest=True,
                    dependencies=list(dict.fromkeys(collected_deps)),
                    classification=p_class,
                    failure_reason=p_reason,
                    manifest_files=manifest_files
                )

        # 3. requirements.txt
        req_file = repo_dir / "requirements.txt"
        if req_file.exists():
            r_deps, r_class, r_reason, r_files = cls._parse_requirements_file(req_file, repo_dir, set(), 0)
            manifest_files.extend(r_files)
            collected_deps.extend(r_deps)
            if r_class:
                return ManifestInspectionResult(
                    has_manifest=True,
                    dependencies=list(dict.fromkeys(collected_deps)),
                    classification=r_class,
                    failure_reason=r_reason,
                    manifest_files=list(dict.fromkeys(manifest_files))
                )

        # 4. setup.py and setup.cfg
        setup_file = repo_dir / "setup.py"
        setup_cfg_file = repo_dir / "setup.cfg"
        if setup_file.exists():
            manifest_files.append("setup.py")
            s_deps, s_class, s_reason = cls._inspect_setup_py(setup_file)
            collected_deps.extend(s_deps)
            if s_class:
                return ManifestInspectionResult(
                    has_manifest=True,
                    dependencies=list(dict.fromkeys(collected_deps)),
                    classification=s_class,
                    failure_reason=s_reason,
                    manifest_files=list(dict.fromkeys(manifest_files))
                )
            if not s_deps and setup_cfg_file.exists():
                manifest_files.append("setup.cfg")
                cfg_deps, cfg_class, cfg_reason = cls._inspect_setup_cfg(setup_cfg_file)
                collected_deps.extend(cfg_deps)
                if cfg_class:
                    return ManifestInspectionResult(
                        has_manifest=True,
                        dependencies=list(dict.fromkeys(collected_deps)),
                        classification=cfg_class,
                        failure_reason=cfg_reason,
                        manifest_files=list(dict.fromkeys(manifest_files))
                    )
        elif setup_cfg_file.exists():
            manifest_files.append("setup.cfg")
            cfg_deps, cfg_class, cfg_reason = cls._inspect_setup_cfg(setup_cfg_file)
            collected_deps.extend(cfg_deps)
            if cfg_class:
                return ManifestInspectionResult(
                    has_manifest=True,
                    dependencies=list(dict.fromkeys(collected_deps)),
                    classification=cfg_class,
                    failure_reason=cfg_reason,
                    manifest_files=list(dict.fromkeys(manifest_files))
                )

        unique_deps = list(dict.fromkeys(collected_deps))
        manifest_files = list(dict.fromkeys(manifest_files))
        has_manifest = len(manifest_files) > 0

        classification = (
            ManifestClassification.SUPPORTED_VALIDATED
            if unique_deps
            else ManifestClassification.CONFIRMED_NO_DEPENDENCIES
        )

        return ManifestInspectionResult(
            has_manifest=has_manifest,
            dependencies=unique_deps,
            classification=classification,
            manifest_files=manifest_files
        )

    @classmethod
    def detect_dependencies(cls, repo_dir: Path) -> Tuple[bool, List[str]]:
        """
        Inspects repository manifest files for declared dependencies.
        Maintains backward compatibility with (has_manifest, detected_deps) callers.
        """
        inspection = cls.inspect_manifests(repo_dir)
        return inspection.has_manifest, inspection.dependencies

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
