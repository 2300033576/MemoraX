from __future__ import annotations

import hashlib
from pathlib import Path


def file_sha256(path: str | Path, chunk_size: int = 1024 * 1024) -> str:
    file_path = Path(path)
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def file_size(path: str | Path) -> int:
    return Path(path).stat().st_size
