"""
Vulnerable Tarfile Extractor (Fixture)
Vulnerable to directory traversal via unvalidated TarInfo member names.
Compatible with Python >= 3.11.
"""
import tarfile
from pathlib import Path


def extract_archive(archive_path: str, extract_to: str = "extracted") -> None:
    """Extracts all members of an archive without path sanitization."""
    dest = Path(extract_to)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive_path, "r:*") as tar:
        # In Python >= 3.12/3.14, fully_trusted preserves pre-PEP 706 unvalidated extraction behavior
        kwargs = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}
        tar.extractall(path=dest, **kwargs)
