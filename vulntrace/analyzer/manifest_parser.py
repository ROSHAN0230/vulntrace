"""
Repository Manifest & Dependency Inspector
Inspects project manifests (requirements.txt, pyproject.toml, package.json)
and extracts active dependencies and Git metadata.
"""

from pathlib import Path
from typing import List, Optional, Tuple
import subprocess
import json
import re
from vulntrace.models import DependencyItem, RepoInspectResponse

class ManifestParser:
    @staticmethod
    def get_git_info(repo_path: Path) -> Tuple[Optional[str], Optional[str]]:
        branch = None
        commit = None
        try:
            r_branch = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=3.0
            )
            if r_branch.returncode == 0:
                branch = r_branch.stdout.strip()
                
            r_commit = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                cwd=str(repo_path),
                capture_output=True,
                text=True,
                timeout=3.0
            )
            if r_commit.returncode == 0:
                commit = r_commit.stdout.strip()
        except Exception:
            pass
        return branch, commit

    @staticmethod
    def parse_requirements_txt(file_path: Path) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        if not file_path.exists():
            return items
            
        for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            
            # Split package and constraint e.g. PyYAML>=5.3.1, flask==2.0.1
            match = re.split(r"(==|>=|<=|>|<|~=|!=)", line, maxsplit=1)
            if len(match) == 3:
                name = match[0].strip()
                spec = match[1] + match[2].strip()
            else:
                name = line.strip()
                spec = "*"
                
            items.append(DependencyItem(
                name=name,
                version_spec=spec,
                manifest_source="requirements.txt",
                ecosystem="PyPI"
            ))
        return items

    @staticmethod
    def parse_pyproject_toml(file_path: Path) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        if not file_path.exists():
            return items
            
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            # Parse [project.dependencies] or [tool.poetry.dependencies]
            in_deps = False
            for line in text.splitlines():
                stripped = line.strip()
                if stripped.startswith("[project.dependencies]") or stripped.startswith("dependencies = ["):
                    in_deps = True
                    continue
                elif stripped.startswith("[") and in_deps:
                    in_deps = False
                    
                if in_deps:
                    if stripped == "]":
                        in_deps = False
                        continue
                    m = re.match(r'["\']([^"\']+)["\']', stripped)
                    if m:
                        dep_str = m.group(1)
                        match = re.split(r"(==|>=|<=|>|<|~=|!=)", dep_str, maxsplit=1)
                        if len(match) == 3:
                            items.append(DependencyItem(
                                name=match[0].strip(),
                                version_spec=match[1] + match[2].strip(),
                                manifest_source="pyproject.toml",
                                ecosystem="PyPI"
                            ))
                        else:
                            items.append(DependencyItem(
                                name=dep_str,
                                version_spec="*",
                                manifest_source="pyproject.toml",
                                ecosystem="PyPI"
                            ))
        except Exception:
            pass
        return items

    @staticmethod
    def parse_package_json(file_path: Path) -> List[DependencyItem]:
        items: List[DependencyItem] = []
        if not file_path.exists():
            return items
            
        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
            for section in ["dependencies", "devDependencies"]:
                for pkg, ver in data.get(section, {}).items():
                    items.append(DependencyItem(
                        name=pkg,
                        version_spec=str(ver),
                        manifest_source="package.json",
                        ecosystem="npm"
                    ))
        except Exception:
            pass
        return items

    @classmethod
    def inspect_repository(cls, repo_path_str: str) -> RepoInspectResponse:
        repo_path = Path(repo_path_str).resolve()
        if not repo_path.exists():
            return RepoInspectResponse(
                repo_path=str(repo_path),
                exists=False,
                error=f"Repository path does not exist on disk: {repo_path}"
            )
            
        if not repo_path.is_dir():
            return RepoInspectResponse(
                repo_path=str(repo_path),
                exists=False,
                error=f"Specified path is a file, not a directory: {repo_path}"
            )

        branch, commit = cls.get_git_info(repo_path)
        manifest_files: List[str] = []
        deps: List[DependencyItem] = []

        # Check requirements.txt
        req_file = repo_path / "requirements.txt"
        if req_file.exists():
            manifest_files.append("requirements.txt")
            deps.extend(cls.parse_requirements_txt(req_file))

        # Check pyproject.toml
        pyproject_file = repo_path / "pyproject.toml"
        if pyproject_file.exists():
            manifest_files.append("pyproject.toml")
            deps.extend(cls.parse_pyproject_toml(pyproject_file))

        # Check package.json
        pkg_file = repo_path / "package.json"
        if pkg_file.exists():
            manifest_files.append("package.json")
            deps.extend(cls.parse_package_json(pkg_file))

        # Count python files
        py_files = list(repo_path.rglob("*.py"))
        py_files_filtered = [
            f for f in py_files 
            if not any(part in f.parts for part in [".venv", "venv", "__pycache__", "node_modules", ".git"])
        ]

        return RepoInspectResponse(
            repo_path=str(repo_path),
            exists=True,
            git_branch=branch,
            git_commit=commit,
            manifest_files=manifest_files,
            python_files_count=len(py_files_filtered),
            dependencies=deps,
            error=None
        )
