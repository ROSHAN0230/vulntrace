"""
Regression test suite for archive extractor.
"""
import tarfile
import io
import time
from pathlib import Path
from archive_extractor import extract_archive


def test_extract_valid_archive(tmp_path: Path):
    tar_path = tmp_path / "valid.tar"
    dest_path = tmp_path / "out"

    with tarfile.open(tar_path, "w") as tar:
        data = b'{"status": "ok"}\n'
        ti = tarfile.TarInfo(name="app_config.json")
        ti.size = len(data)
        ti.mtime = int(time.time())
        ti.mode = 0o644
        tar.addfile(ti, io.BytesIO(data))

    extract_archive(str(tar_path), str(dest_path))
    assert (dest_path / "app_config.json").exists()
    assert (dest_path / "app_config.json").read_bytes() == b'{"status": "ok"}\n'
