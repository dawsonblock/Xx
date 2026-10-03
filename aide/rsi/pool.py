from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path

from .types import ReplayWorld


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


class ReplayWorldPool:
    """Append-only, content-addressed, fail-closed replay-world store."""

    SCHEMA_VERSION = 3

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)
        self.objects = self.directory / "sha256"
        self.manifest_path = self.directory / "manifest.json"
        self.objects.mkdir(parents=True, exist_ok=True)
        if not self.manifest_path.exists():
            legacy = list(self.directory.glob("*.world.json"))
            self._write_manifest(
                {"schema_version": self.SCHEMA_VERSION, "worlds": {}, "order": []}
            )
            if legacy:
                # v1.0 stored flat world files + sidecars. Import them fail-closed
                # into the content-addressed store instead of silently starting an
                # empty pool. Preserve chronological order when round metadata exists.
                worlds = [self.load_flat_strict(path) for path in legacy]
                worlds.sort(key=self._migration_sort_key)
                for world in worlds:
                    self.add(world)

    @staticmethod
    def _digest_bytes(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _canonical_bytes(world: ReplayWorld) -> bytes:
        return (
            json.dumps(world.to_dict(), sort_keys=True, separators=(",", ":")) + "\n"
        ).encode()

    @staticmethod
    def _migration_sort_key(world: ReplayWorld) -> tuple[int, int, str]:
        round_no = world.metadata.get("round")
        try:
            return (0, int(round_no), world.world_id)
        except (TypeError, ValueError):
            return (1, 0, world.world_id)

    def _read_manifest(self) -> dict:
        raw = json.loads(self.manifest_path.read_text())
        version = int(raw.get("schema_version", 0))
        if version == 2:
            # v1.0/v1.1-pre manifests did not preserve insertion order. Migrate
            # deterministically using recorded round metadata when possible.
            worlds = raw.get("worlds")
            if not isinstance(worlds, dict):
                raise ValueError("invalid replay pool manifest")
            ordered_ids = list(worlds)

            def key(wid: str):
                try:
                    w = self._load_digest_unchecked_id(wid, worlds[wid])
                    r = w.metadata.get("round")
                    return (0, int(r), wid) if r is not None else (1, 0, wid)
                except Exception:
                    return (2, 0, wid)

            ordered_ids.sort(key=key)
            raw = {
                "schema_version": self.SCHEMA_VERSION,
                "worlds": worlds,
                "order": ordered_ids,
            }
            self._write_manifest(raw)
            return raw
        if version != self.SCHEMA_VERSION:
            raise ValueError("unsupported replay pool manifest schema")
        if not isinstance(raw.get("worlds"), dict) or not isinstance(
            raw.get("order"), list
        ):
            raise ValueError("invalid replay pool manifest")
        worlds = raw["worlds"]
        order = raw["order"]
        if len(order) != len(set(order)) or set(order) != set(worlds):
            raise ValueError("replay pool manifest order/world mapping mismatch")
        return raw

    def _write_manifest(self, raw: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(raw, indent=2, sort_keys=True) + "\n").encode()
        fd, tmp_name = tempfile.mkstemp(
            prefix="manifest.", suffix=".tmp", dir=self.directory
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, self.manifest_path)
            _fsync_dir(self.directory)
        finally:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass

    def _object_path(self, digest: str) -> Path:
        return self.objects / digest[:2] / f"{digest}.world.json"

    def add(self, world: ReplayWorld) -> Path:
        world.validate(require_chain_branches=True)
        data = self._canonical_bytes(world)
        digest = self._digest_bytes(data)
        path = self._object_path(digest)
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            fd, tmp_name = tempfile.mkstemp(
                prefix=digest + ".", suffix=".tmp", dir=path.parent
            )
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_name, path)
                _fsync_dir(path.parent)
            finally:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
        elif self._digest_bytes(path.read_bytes()) != digest:
            raise ValueError(f"content-addressed replay object corrupted: {path}")

        manifest = self._read_manifest()
        worlds = manifest["worlds"]
        previous = worlds.get(world.world_id)
        if previous is not None and previous != digest:
            raise ValueError(
                f"world_id is immutable and already points to another digest: {world.world_id}"
            )
        worlds[world.world_id] = digest
        order = manifest.setdefault("order", [])
        if world.world_id not in order:
            order.append(world.world_id)
        self._write_manifest(manifest)
        return path

    def _load_digest_unchecked_id(self, world_id: str, digest: str) -> ReplayWorld:
        if len(digest) != 64 or any(
            c not in "0123456789abcdef" for c in digest.lower()
        ):
            raise ValueError(f"invalid replay digest for {world_id}")
        path = self._object_path(digest)
        if not path.exists():
            raise ValueError(f"replay object missing for {world_id}: {digest}")
        data = path.read_bytes()
        actual = self._digest_bytes(data)
        if actual != digest:
            raise ValueError(f"replay world integrity check failed: {path}")
        return ReplayWorld.from_dict(json.loads(data))

    def _load_digest(self, world_id: str, digest: str) -> ReplayWorld:
        world = self._load_digest_unchecked_id(world_id, digest)
        if world.world_id != world_id:
            raise ValueError(
                f"manifest/world id mismatch: {world_id} != {world.world_id}"
            )
        world.validate(require_chain_branches=True)
        return world

    def load_all(self) -> list[ReplayWorld]:
        manifest = self._read_manifest()
        return [
            self._load_digest(wid, manifest["worlds"][wid]) for wid in manifest["order"]
        ]

    def manifest(self) -> dict[str, object]:
        raw = self._read_manifest()
        worlds = self.load_all()
        return {
            "schema_version": self.SCHEMA_VERSION,
            "count": len(worlds),
            "world_ids": [w.world_id for w in worlds],
            "digests": dict(raw["worlds"]),
            "order": list(raw["order"]),
            "node_count": sum(w.node_count for w in worlds),
        }

    @staticmethod
    def load_flat_strict(path: str | Path) -> ReplayWorld:
        """Load a legacy standalone world only when its SHA-256 sidecar exists."""
        path = Path(path)
        sidecar = path.with_suffix(path.suffix + ".sha256")
        if not sidecar.exists():
            raise ValueError(f"missing integrity sidecar for replay world: {path}")
        expected = sidecar.read_text().strip().split()[0]
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(f"replay world integrity check failed: {path}")
        return ReplayWorld.load(path)
