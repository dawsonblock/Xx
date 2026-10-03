from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .types import ReplayWorld


@dataclass(frozen=True)
class WorldSplit:
    development: list[ReplayWorld]
    validation: list[ReplayWorld]
    qualification: list[ReplayWorld]


class PersistentSplitManager:
    """Assign replay worlds to immutable development/validation/qualification sets.

    Assignments are persisted per evaluation epoch.  Adding new worlds never moves
    an existing qualification world into development, eliminating holdout leakage.
    """

    def __init__(self, manifest_path: str | Path, *, epoch: str = "0001"):
        self.path = Path(manifest_path)
        self.epoch = str(epoch)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict:
        if not self.path.exists():
            return {
                "schema_version": 1,
                "epoch": self.epoch,
                "assignments": {},
                "retired_qualification": [],
            }
        raw = json.loads(self.path.read_text())
        if int(raw.get("schema_version", 0)) != 1:
            raise ValueError("unsupported split manifest schema")
        if str(raw.get("epoch")) != self.epoch:
            raise ValueError(
                f"split manifest epoch mismatch: {raw.get('epoch')} != {self.epoch}"
            )
        assignments = raw.get("assignments")
        if not isinstance(assignments, dict):
            raise ValueError("invalid split manifest assignments")
        if any(
            v not in {"development", "validation", "qualification"}
            for v in assignments.values()
        ):
            raise ValueError("invalid split manifest bucket")
        retired = raw.setdefault("retired_qualification", [])
        if not isinstance(retired, list) or any(
            not isinstance(world_id, str) for world_id in retired
        ):
            raise ValueError("invalid retired qualification list")
        if any(assignments.get(world_id) != "qualification" for world_id in retired):
            raise ValueError("only qualification worlds can be retired")
        return raw

    def _save(self, raw: dict) -> None:
        data = json.dumps(raw, indent=2, sort_keys=True).encode()
        fd, tmp_name = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.path)
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
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _bucket(world_id: str) -> str:
        n = int(hashlib.sha256(world_id.encode()).hexdigest()[:8], 16) % 100
        if n < 60:
            return "development"
        if n < 80:
            return "validation"
        return "qualification"

    def split(self, worlds: list[ReplayWorld]) -> WorldSplit:
        raw = self._load()
        assignments: dict[str, str] = dict(raw.get("assignments", {}))
        # Bootstrap two development, one validation, and three qualification
        # worlds before allowing a policy decision. With the default seven rounds,
        # six discovery worlds are available before one canary opportunity.
        # Preserve replay-pool insertion order. This matters after round 9 (plain
        # lexical world-id order would place round 10 before round 2).
        ordered_new = [w for w in worlds if w.world_id not in assignments]
        counts = {
            k: sum(1 for v in assignments.values() if v == k)
            for k in ("development", "validation", "qualification")
        }
        for world in ordered_new:
            if counts["development"] < 2:
                bucket = "development"
            elif counts["validation"] < 1:
                bucket = "validation"
            elif counts["qualification"] < 3:
                bucket = "qualification"
            else:
                bucket = self._bucket(world.world_id)
            assignments[world.world_id] = bucket
            counts[bucket] += 1
        raw["assignments"] = assignments
        self._save(raw)

        groups = {"development": [], "validation": [], "qualification": []}
        retired = set(raw.get("retired_qualification", []))
        for world in worlds:
            bucket = assignments.get(world.world_id)
            if bucket not in groups:
                raise ValueError(
                    f"invalid or missing split assignment for {world.world_id}: {bucket}"
                )
            if bucket != "qualification" or world.world_id not in retired:
                groups[bucket].append(world)
        return WorldSplit(
            groups["development"], groups["validation"], groups["qualification"]
        )

    def retire_qualification(self, world_ids: list[str]) -> None:
        """Consume a qualification shard so later candidates cannot tune to it."""
        raw = self._load()
        assignments = raw["assignments"]
        retired = set(raw.get("retired_qualification", []))
        for world_id in world_ids:
            if assignments.get(world_id) != "qualification":
                raise ValueError(f"world is not assigned to qualification: {world_id}")
            retired.add(world_id)
        raw["retired_qualification"] = sorted(retired)
        self._save(raw)


def split_worlds(worlds: list[ReplayWorld]) -> WorldSplit:
    """Backwards-compatible one-shot split for offline tooling/tests.

    Do not use this for a growing live pool: the runner uses PersistentSplitManager
    so held-out assignments can never migrate.
    """
    worlds = list(worlds)
    if not worlds:
        return WorldSplit([], [], [])
    if len(worlds) == 1:
        return WorldSplit(worlds, [], [])
    if len(worlds) == 2:
        return WorldSplit([worlds[0]], [worlds[1]], [])
    ordered = sorted(
        worlds, key=lambda w: hashlib.sha256(w.world_id.encode()).hexdigest()
    )
    n = len(ordered)
    n_q = max(1, round(n * 0.2))
    n_v = max(1, round(n * 0.2))
    if n_q + n_v >= n:
        n_q = n_v = 1
    qualification = ordered[-n_q:]
    validation = ordered[-(n_q + n_v) : -n_q]
    development = ordered[: -(n_q + n_v)]
    if not development:
        development = [validation.pop(0)]
    return WorldSplit(development, validation, qualification)
