"""
VulnTrace Repository Ingest Security Package (Spec §4.14)
"""

from vulntrace.ingest.upload import (
    ZipUploadGuard,
    IngestSecurityError,
    ZipSlipError,
    DecompressionBombError,
    SymlinkEscapeError
)
from vulntrace.ingest.clone import (
    GitCloneGuard,
    CloneSecurityError
)

__all__ = [
    "ZipUploadGuard",
    "GitCloneGuard",
    "IngestSecurityError",
    "ZipSlipError",
    "DecompressionBombError",
    "SymlinkEscapeError",
    "CloneSecurityError",
]
