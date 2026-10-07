"""
VulnTrace Ingest Guard — Secure Archive Upload Handling (Spec §4.14)
Enforces:
1. Zip-slip and absolute path traversal rejection.
2. Symlink escape rejection / neutralization.
3. Decompression bomb detection (compression ratio & total size limits).
4. Maximum file count and archive size limits.
"""

import zipfile
from pathlib import Path
from typing import Optional, List


class IngestSecurityError(ValueError):
    """Base class for repository ingest security violations."""
    pass


class ZipSlipError(IngestSecurityError):
    """Raised when an archive contains paths that escape the target root."""
    pass


class DecompressionBombError(IngestSecurityError):
    """Raised when an archive exceeds safe decompression ratios or sizes."""
    pass


class SymlinkEscapeError(IngestSecurityError):
    """Raised when an archive contains a symlink pointing outside the workspace."""
    pass


class ZipUploadGuard:
    """Security validator and safe extractor for uploaded repository zip archives."""

    MAX_ARCHIVE_BYTES: int = 50 * 1024 * 1024       # 50 MB
    MAX_UNCOMPRESSED_BYTES: int = 200 * 1024 * 1024 # 200 MB
    MAX_FILE_COUNT: int = 5000
    MAX_COMPRESSION_RATIO: float = 100.0             # 100:1 ratio limit

    @classmethod
    def validate_and_extract(
        cls,
        zip_path: Path,
        destination_dir: Path,
        max_archive_bytes: Optional[int] = None,
        max_uncompressed_bytes: Optional[int] = None,
        max_file_count: Optional[int] = None,
        max_ratio: Optional[float] = None
    ) -> List[Path]:
        """
        Validates zip archive against security rules and safely extracts contents.
        Raises IngestSecurityError sub-types on any malicious pattern.
        """
        zip_path = Path(zip_path).resolve()
        dest_dir = Path(destination_dir).resolve()
        dest_dir.mkdir(parents=True, exist_ok=True)

        limit_archive = max_archive_bytes or cls.MAX_ARCHIVE_BYTES
        limit_uncompressed = max_uncompressed_bytes or cls.MAX_UNCOMPRESSED_BYTES
        limit_count = max_file_count or cls.MAX_FILE_COUNT
        limit_ratio = max_ratio or cls.MAX_COMPRESSION_RATIO

        # 1. Archive file size check
        archive_size = zip_path.stat().st_size
        if archive_size > limit_archive:
            raise IngestSecurityError(
                f"Archive size {archive_size} exceeds maximum limit of {limit_archive} bytes."
            )

        if archive_size == 0:
            raise IngestSecurityError("Archive is empty (0 bytes).")

        extracted_files: List[Path] = []
        total_uncompressed = 0
        total_count = 0

        with zipfile.ZipFile(zip_path, "r") as zf:
            infolist = zf.infolist()
            total_count = len(infolist)

            # 2. File count check
            if total_count > limit_count:
                raise IngestSecurityError(
                    f"Archive file count {total_count} exceeds maximum limit of {limit_count} files."
                )

            # 3. Pre-scan for zip-slip, decompression bomb, and symlink escapes
            for info in infolist:
                # Zip-slip check: raw filename traversal
                raw_name = info.filename
                if ".." in raw_name.replace("\\", "/").split("/"):
                    raise ZipSlipError(f"Zip-slip detected in member name: '{raw_name}'")

                if raw_name.startswith("/") or raw_name.startswith("\\"):
                    raise ZipSlipError(f"Absolute path member detected: '{raw_name}'")

                # Drive letter check (e.g. C:\ or C:/)
                if len(raw_name) > 2 and raw_name[1] == ":" and raw_name[0].isalpha():
                    raise ZipSlipError(f"Absolute drive path detected in member: '{raw_name}'")

                # Decompression ratio check per file
                compressed_size = max(info.compress_size, 1)
                file_ratio = info.file_size / compressed_size
                if info.file_size > 1024 and file_ratio > limit_ratio:
                    raise DecompressionBombError(
                        f"Decompression bomb ratio ({file_ratio:.1f}:1) exceeded in '{raw_name}'"
                    )

                total_uncompressed += info.file_size
                if total_uncompressed > limit_uncompressed:
                    raise DecompressionBombError(
                        f"Total uncompressed size {total_uncompressed} exceeds limit of {limit_uncompressed} bytes."
                    )

                # Destination path resolution check
                target_path = (dest_dir / raw_name).resolve()
                try:
                    # Check if target_path is within dest_dir
                    target_path.relative_to(dest_dir)
                except ValueError:
                    raise ZipSlipError(f"Member '{raw_name}' resolves outside destination directory.")

            # Overall archive compression ratio check
            overall_ratio = total_uncompressed / max(archive_size, 1)
            if archive_size > 512 and overall_ratio > limit_ratio:
                raise DecompressionBombError(
                    f"Overall archive decompression ratio ({overall_ratio:.1f}:1) exceeded limit {limit_ratio}:1."
                )

            # 4. Extract entries safely
            for info in infolist:
                raw_name = info.filename
                target_path = (dest_dir / raw_name).resolve()

                # Check for symlink attribute (UNIX mode)
                mode = info.external_attr >> 16
                is_symlink = (mode & 0o120000) == 0o120000

                if is_symlink:
                    # Read link target
                    link_target_bytes = zf.read(info)
                    link_target = link_target_bytes.decode("utf-8", errors="replace").strip()
                    # Resolve link destination relative to target directory
                    resolved_link = (target_path.parent / link_target).resolve()
                    try:
                        resolved_link.relative_to(dest_dir)
                    except ValueError:
                        raise SymlinkEscapeError(
                            f"Symlink in '{raw_name}' points outside destination: '{link_target}'"
                        )
                    # For safety across platforms, do not create live host symlinks; write harmless reference
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    target_path.write_text(f"[SAFE_SYMLINK_NEUTRALIZED: {link_target}]\n", encoding="utf-8")
                    extracted_files.append(target_path)
                    continue

                if info.is_dir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, open(target_path, "wb") as dst:
                    chunk_size = 64 * 1024
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(chunk)
                extracted_files.append(target_path)

        return extracted_files
