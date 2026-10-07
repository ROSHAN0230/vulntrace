"""
VulnTrace Workspace Zip Export Engine (Spec §4.12)
Archives patched disposable workspaces into clean, portable zip distributions.
"""

import os
import zipfile
from pathlib import Path
from typing import List, Optional


class ZipExporter:
    """Safely archives workspace directory into a clean distribution zip."""

    DEFAULT_EXCLUDES = [
        ".git",
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".venv",
        "venv",
        "build",
        "dist",
        "*.egg-info",
        ".DS_Store"
    ]

    @classmethod
    def export_workspace_zip(
        cls,
        workspace_dir: Path,
        output_zip: Path,
        excludes: Optional[List[str]] = None
    ) -> Path:
        """
        Creates a zip archive of workspace_dir excluding ephemeral files.
        """
        workspace_dir = Path(workspace_dir).resolve()
        output_zip = Path(output_zip).resolve()
        output_zip.parent.mkdir(parents=True, exist_ok=True)

        exclude_patterns = excludes if excludes is not None else cls.DEFAULT_EXCLUDES

        def is_excluded(rel_path: Path) -> bool:
            parts = rel_path.parts
            for p in parts:
                for pat in exclude_patterns:
                    if pat.startswith("*") and p.endswith(pat[1:]):
                        return True
                    if p == pat:
                        return True
            return False

        with zipfile.ZipFile(output_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(workspace_dir):
                root_path = Path(root)
                rel_root = root_path.relative_to(workspace_dir)

                if is_excluded(rel_root):
                    dirs[:] = []
                    continue

                for file in files:
                    file_path = root_path / file
                    rel_file = file_path.relative_to(workspace_dir)
                    if is_excluded(rel_file):
                        continue
                    zf.write(file_path, arcname=str(rel_file).replace("\\", "/"))

        return output_zip
