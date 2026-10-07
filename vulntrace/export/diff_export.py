"""
VulnTrace Unified Diff Export Engine (Spec §4.12 / §6 AC5)
Produces standard Git-compatible unified diff files verified against `git apply --check`.
"""

import subprocess
from pathlib import Path


class DiffExportError(ValueError):
    """Raised when diff export or validation fails."""
    pass


class DiffExporter:
    """Exports and validates unified diff files for clean repository patching."""

    @classmethod
    def format_git_diff(cls, raw_diff: str) -> str:
        """
        Normalizes unified diff text to strict git format with trailing newline and LF.
        """
        lines = [line.rstrip("\r\n") for line in raw_diff.strip().splitlines()]
        if not lines:
            return ""
        return "\n".join(lines) + "\n"

    @classmethod
    def export_diff_file(cls, diff_content: str, output_path: Path) -> Path:
        """
        Writes formatted diff to output_path.
        """
        output_path = Path(output_path).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        formatted = cls.format_git_diff(diff_content)
        # Always write with LF line endings
        with open(output_path, "wb") as f:
            f.write(formatted.encode("utf-8"))
        return output_path

    @classmethod
    def verify_git_apply_check(cls, diff_path: Path, repo_root: Path) -> bool:
        """
        Executes `git apply --check <diff_path>` in repo_root to verify clean patch applicability.
        """
        diff_path = Path(diff_path).resolve()
        repo_root = Path(repo_root).resolve()

        if not diff_path.exists():
            raise DiffExportError(f"Diff file does not exist: {diff_path}")
        if not repo_root.exists():
            raise DiffExportError(f"Repository root does not exist: {repo_root}")

        cmd = ["git", "apply", "--check", str(diff_path)]
        try:
            res = subprocess.run(
                cmd,
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False
            )
            return res.returncode == 0
        except Exception:
            return False
