"""
VulnTrace Reviewed Path-Traversal Sink-Class Oracle (Spec §4.3, M7)

Provides reviewed, deterministic behavioral oracles for path traversal vulnerabilities:
1. Tarfile: unsafe tarfile.extractall, tarfile.extract without destination containment checks.
2. Safe ZIP Control: Documents and verifies that standard library zipfile.ZipFile.extractall
   automatically sanitizes and normalizes ordinary '..' member paths, serving as a safe control.

Safety Policy:
- Behavioral probes only. No shells, no network callbacks, no destructive actions.
- Disposable workspace canary: Canary resides outside the target extraction root,
  but strictly INSIDE the disposable sandbox workspace parent directory.
  Never writes to the host or outside the disposable sandbox workspace.
- Case-specific expected block signal: ValueError, PermissionError, or FilterError.
- Multi-input positive controls verify legitimate archive extraction succeeds.
- Compatible with Python >= 3.11.
"""

import io
import tarfile
import time
from pathlib import Path
from typing import Dict, List, Optional
from vulntrace.sinks.base import (
    BaseSinkOracle,
    SinkClass,
    BenignProbe,
    ExpectedBlockSignature,
    SafePattern,
    BenignContract,
)


class TarPathTraversalOracle(BaseSinkOracle):
    """
    Reviewed sink oracle for tarfile path traversal (e.g. Trellix CVE-2007-4559 / PEP 706).
    Evaluates whether archive extraction allows path traversal escaping the destination root.
    """

    TAR_SINK_PATTERNS = (
        "tarfile.extractall",
        "tarfile.TarFile.extractall",
        "tarfile.extract",
        "tarfile.TarFile.extract",
        "tarfile.open",
        "extractall",
    )

    @property
    def sink_class(self) -> SinkClass:
        return SinkClass.PATH_TRAVERSAL

    @property
    def name(self) -> str:
        return "Tarfile Path Traversal Oracle"

    def matches(self, symbol_or_call: str) -> bool:
        sym = (symbol_or_call or "").lower()
        if "zip" in sym:
            return False
        return any(p.lower() in sym for p in self.TAR_SINK_PATTERNS) or "tarfile" in sym or "tar" in sym

    def get_probe(self, canary_filename: str) -> BenignProbe:
        """
        Returns a benign behavioral probe specification.
        The canary file will be created by extracting a relative member '../<canary_filename>'
        into '<workspace>/extracted/'. The escaped canary is written to '<workspace>/<canary_filename>',
        which is strictly inside the disposable sandbox workspace parent.
        """
        payload = f'tar_traversal:member_escape:../{canary_filename}'
        return BenignProbe(
            payload_expr=payload,
            canary_filename=canary_filename,
            description=(
                f"Benign tar traversal probe writing canary '{canary_filename}' outside "
                f"extraction root but strictly inside disposable workspace parent."
            ),
            is_destructive=False,
            requires_network=False,
            requires_shell=False,
        )

    @staticmethod
    def create_traversal_archive(
        archive_path: Path,
        canary_filename: str,
        safe_filename: str = "benign_payload.txt",
    ) -> Path:
        """
        Generates a controlled tar archive containing:
        1. An escaping traversal member '../<canary_filename>'
        2. A benign in-root file '<safe_filename>'
        """
        archive_path = Path(archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        canary_data = b"VULNTRACE_CANARY_PATH_TRAVERSAL_ESCAPE\n"
        safe_data = b"VULNTRACE_BENIGN_CONTENT_PRESERVED\n"

        with tarfile.open(archive_path, "w") as tar:
            # Traversal member
            t_canary = tarfile.TarInfo(name=f"../{canary_filename}")
            t_canary.size = len(canary_data)
            t_canary.mtime = int(time.time())
            t_canary.mode = 0o644
            tar.addfile(t_canary, io.BytesIO(canary_data))

            # Benign member
            t_safe = tarfile.TarInfo(name=safe_filename)
            t_safe.size = len(safe_data)
            t_safe.mtime = int(time.time())
            t_safe.mode = 0o644
            tar.addfile(t_safe, io.BytesIO(safe_data))

        return archive_path

    @staticmethod
    def create_absolute_escape_archive(
        archive_path: Path,
        canary_filename: str,
        workspace_dir: Path,
    ) -> Path:
        """
        Generates a tar archive with an absolute member path targeting workspace_dir/<canary_filename>.
        Used to verify that absolute member names are rejected or normalized.
        """
        archive_path = Path(archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        canary_target = (Path(workspace_dir) / canary_filename).as_posix()

        canary_data = b"VULNTRACE_CANARY_ABSOLUTE_PATH_ESCAPE\n"
        with tarfile.open(archive_path, "w") as tar:
            t_canary = tarfile.TarInfo(name=canary_target)
            t_canary.size = len(canary_data)
            t_canary.mtime = int(time.time())
            t_canary.mode = 0o644
            tar.addfile(t_canary, io.BytesIO(canary_data))

        return archive_path

    @staticmethod
    def create_symlink_escape_archive(
        archive_path: Path,
        canary_filename: str,
        symlink_name: str = "escape_link",
    ) -> Path:
        """
        Generates a tar archive with a symlink member pointing outside the extraction root.
        """
        archive_path = Path(archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        with tarfile.open(archive_path, "w") as tar:
            t_link = tarfile.TarInfo(name=symlink_name)
            t_link.type = tarfile.SYMTYPE
            t_link.linkname = f"../{canary_filename}"
            t_link.mtime = int(time.time())
            tar.addfile(t_link)

        return archive_path

    @staticmethod
    def create_benign_archive(
        archive_path: Path,
        files: Optional[Dict[str, bytes]] = None,
    ) -> Path:
        """
        Generates a completely safe tar archive containing legitimate files and subdirectories.
        """
        archive_path = Path(archive_path)
        archive_path.parent.mkdir(parents=True, exist_ok=True)

        if files is None:
            files = {
                "config.json": b'{"service": "vulntrace", "version": "1.0", "active": true}\n',
                "static/app.css": b'body { font-family: sans-serif; }\n',
                "data/README.txt": b'Benign test archive content.\n',
            }

        with tarfile.open(archive_path, "w") as tar:
            for rel_name, data in files.items():
                t = tarfile.TarInfo(name=rel_name)
                t.size = len(data)
                t.mtime = int(time.time())
                t.mode = 0o644
                tar.addfile(t, io.BytesIO(data))

        return archive_path

    def get_expected_block_signature(self) -> ExpectedBlockSignature:
        return ExpectedBlockSignature(
            exception_class_names=(
                "ValueError",
                "PermissionError",
                "FilterError",
                "OutsideDestinationError",
                "SecurityError",
                "PathTraversalError",
                "TarError",
            ),
            exception_module_names=("tarfile", "builtins"),
            message_keywords=(),
        )

    def get_safe_patterns(self) -> List[SafePattern]:
        return [
            SafePattern(
                pattern_id="tarfile_member_containment_check",
                description=(
                    "Inspect each TarInfo member before extraction, resolving target path "
                    "and verifying that destination directory is a common ancestor."
                ),
                example_snippet=(
                    "dest = Path(extract_to).resolve()\n"
                    "for member in tar.getmembers():\n"
                    "    member_path = (dest / member.name).resolve()\n"
                    "    if not (str(member_path) == str(dest) or str(member_path).startswith(str(dest) + os.sep)):\n"
                    "        raise ValueError(f'Path traversal detected: {member.name}')\n"
                    "tar.extractall(path=dest)"
                ),
            ),
            SafePattern(
                pattern_id="tarfile_filter_data_or_custom",
                description=(
                    "Use tarfile extraction filters (Python 3.12+ filter='data' or a "
                    "backported custom filter callable on Python 3.11)."
                ),
                example_snippet=(
                    "def safe_filter(member, dest_path):\n"
                    "    target = (Path(dest_path) / member.name).resolve()\n"
                    "    if not str(target).startswith(str(Path(dest_path).resolve()) + os.sep):\n"
                    "        raise ValueError('Unsafe member path')\n"
                    "    return member\n"
                    "tar.extractall(path=dest, members=[safe_filter(m, dest) for m in tar.getmembers()])"
                ),
            ),
        ]

    def get_benign_contracts(self) -> List[BenignContract]:
        return [
            BenignContract(
                case_id="safe_relative_config",
                description="Valid relative files in archive extract cleanly to destination directory",
                raw_input="benign_config.tar",
                required_type_name="dict",
                required_keys=["extracted_files", "status"],
                nested_invariants={"status": "OK"},
            ),
            BenignContract(
                case_id="nested_assets_tree",
                description="Nested directory hierarchy in archive extracts without corruption",
                raw_input="benign_nested.tar",
                required_type_name="dict",
                required_keys=["extracted_files", "root_dir"],
                nested_invariants={"root_dir": "data"},
            ),
        ]

    def get_harness_import_block(self) -> str:
        return (
            "import tarfile\n"
            "sec_block_types = (\n"
            "    ValueError,\n"
            "    PermissionError,\n"
            "    getattr(tarfile, 'FilterError', ValueError),\n"
            ")\n"
        )


class ZipSafeControlOracle(BaseSinkOracle):
    """
    Safe control oracle for zipfile.ZipFile.extractall.
    Per Spec §4.3 and Amendment A.4, Python standard library zipfile automatically normalizes
    away '..' path components to prevent path traversal outside extraction root.
    """

    ZIP_SINK_PATTERNS = (
        "zipfile.extractall",
        "zipfile.ZipFile.extractall",
        "zipfile.extract",
    )

    @property
    def sink_class(self) -> SinkClass:
        return SinkClass.PATH_TRAVERSAL

    @property
    def name(self) -> str:
        return "Zipfile Safe Control Oracle"

    def matches(self, symbol_or_call: str) -> bool:
        sym = (symbol_or_call or "").lower()
        return any(p.lower() in sym for p in self.ZIP_SINK_PATTERNS) or "zipfile" in sym

    def get_probe(self, canary_filename: str) -> BenignProbe:
        return BenignProbe(
            payload_expr=f'zip_control:{canary_filename}',
            canary_filename=canary_filename,
            description="Zipfile safe control probe demonstrating standard library path normalization.",
            is_destructive=False,
            requires_network=False,
            requires_shell=False,
        )

    def get_expected_block_signature(self) -> ExpectedBlockSignature:
        return ExpectedBlockSignature(
            exception_class_names=("ValueError", "PermissionError"),
            exception_module_names=("builtins", "zipfile"),
        )

    def get_safe_patterns(self) -> List[SafePattern]:
        return [
            SafePattern(
                pattern_id="zipfile_standard_extractall",
                description="Standard zipfile.ZipFile.extractall sanitizes relative paths by default.",
                example_snippet="with zipfile.ZipFile(archive) as z: z.extractall(dest)",
            )
        ]

    def get_benign_contracts(self) -> List[BenignContract]:
        return [
            BenignContract(
                case_id="zip_safe_extraction",
                description="Zipfile standard extraction extracts files inside destination root",
                raw_input="benign.zip",
                required_type_name="dict",
                required_keys=["extracted_files"],
            )
        ]

    def get_harness_import_block(self) -> str:
        return "import zipfile\nsec_block_types = (ValueError, PermissionError)\n"


__all__ = [
    "TarPathTraversalOracle",
    "ZipSafeControlOracle",
]
