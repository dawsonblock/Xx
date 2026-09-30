"""Content-addressed storage for exact candidate source files."""

import hashlib
import re
import stat
from pathlib import Path

from aide.utils.atomic import replace_bytes

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def candidate_digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def store_candidate(code: str, artifact_root: str | Path) -> str:
    """Store source by digest, verifying both existing and newly written objects."""
    digest = candidate_digest(code)
    path = Path(artifact_root) / "sha256" / digest[:2] / f"{digest}.py"
    data = code.encode("utf-8")
    if path.exists():
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"candidate artifact digest mismatch: {path}")
        return digest
    path.parent.mkdir(parents=True, exist_ok=True)
    replace_bytes(path, data)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ValueError(f"candidate artifact digest mismatch after write: {path}")
    return digest


def load_candidate(digest: str, artifact_root: str | Path) -> str:
    if not _SHA256_RE.fullmatch(str(digest)):
        raise ValueError("invalid candidate SHA-256")
    path = Path(artifact_root) / "sha256" / digest[:2] / f"{digest}.py"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"candidate artifact digest mismatch: {path}")
    return data.decode("utf-8")


def store_evaluation_artifact(
    data: bytes, artifact_root: str | Path, *, kind: str, suffix: str
) -> str:
    """Persist evaluator evidence by content hash and verify every reuse."""
    if kind not in {"predictions", "evaluations"}:
        raise ValueError("unsupported evaluation artifact kind")
    if suffix not in {".jsonl", ".json"}:
        raise ValueError("unsupported evaluation artifact suffix")
    digest = hashlib.sha256(data).hexdigest()
    path = Path(artifact_root) / kind / "sha256" / digest[:2] / f"{digest}{suffix}"
    if path.exists():
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"evaluation artifact is not a regular file: {path}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"evaluation artifact digest mismatch: {path}")
        return digest
    path.parent.mkdir(parents=True, exist_ok=True)
    replace_bytes(path, data)
    path.chmod(0o444)
    if (
        path.is_symlink()
        or not stat.S_ISREG(path.lstat().st_mode)
        or hashlib.sha256(path.read_bytes()).hexdigest() != digest
    ):
        raise ValueError(f"evaluation artifact digest mismatch after write: {path}")
    return digest
