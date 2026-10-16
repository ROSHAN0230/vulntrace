"""
Fixed Tarfile Extractor (Fixture)
Defends against directory traversal by verifying destination containment.
Compatible with Python >= 3.11.
"""
import os
import tarfile
from pathlib import Path


def extract_archive(archive_path: str, extract_to: str = "extracted") -> None:
    """Extracts archive members safely, rejecting path traversal and symlink escapes."""
    dest = Path(extract_to).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            # Resolve target path
            member_path = (dest / member.name).resolve()
            # Reject members that escape destination directory (Python >= 3.11 safe check)
            if not (str(member_path) == str(dest) or str(member_path).startswith(str(dest) + os.sep)):
                raise ValueError(f"Unsafe path traversal detected in member: {member.name}")

            # Reject symlinks and hardlinks pointing outside destination
            if member.issym() or member.islnk():
                link_target = (dest / member.linkname).resolve()
                if not (str(link_target) == str(dest) or str(link_target).startswith(str(dest) + os.sep)):
                    raise ValueError(f"Unsafe link target detected in member: {member.name} -> {member.linkname}")

        tar.extractall(path=dest)
