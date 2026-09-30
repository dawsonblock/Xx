from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


VALID_PHASES = {
    "IDLE",
    "CANARY_RUNNING",
    "LIVE_RUNNING",
    "WORLD_COMMITTED",
    "POLICY_EVALUATING",
    "CANDIDATE_PENDING",
    "COMPLETED",
}


class RSIStateStore:
    """Atomically persisted round state used for deterministic crash recovery."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"schema_version": 1, "phase": "IDLE", "next_round": 0}
        raw = json.loads(self.path.read_text())
        if raw.get("phase") not in VALID_PHASES:
            raise ValueError(f"invalid RSI phase: {raw.get('phase')}")
        return raw

    def write(self, **updates: Any) -> dict[str, Any]:
        raw = self.load()
        raw.update(updates)
        raw.setdefault("schema_version", 1)
        if raw.get("phase") not in VALID_PHASES:
            raise ValueError(f"invalid RSI phase: {raw.get('phase')}")
        data = (json.dumps(raw, indent=2, sort_keys=True, default=str) + "\n").encode()
        fd, tmp = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            try:
                dfd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        return raw
