from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

REGISTRY_VERSION = 5
CHECKPOINT_VERSION = 1


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def question_signature(question: Mapping[str, Any]) -> str:
    """Exact SystemOne question signature for specialist routing."""
    return hashlib.sha256(canonical_json(question).encode("utf-8")).hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_sha256_digest(value: str | None) -> bool:
    if not value or not value.startswith("sha256:"):
        return False
    raw = value[7:]
    return len(raw) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in raw)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def atomic_write_json(path: str | Path, value: Mapping[str, Any], *, mode: int = 0o600) -> None:
    """Durably replace a JSON file instead of truncating it in place.

    This protects registry/checkpoint files from partial writes if the process or machine dies between
    opening and writing. The parent directory is fsync'd after rename where the platform permits it.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        try:
            os.fchmod(fd, mode)
        except (AttributeError, OSError):
            pass
        with os.fdopen(fd, "wb", closefd=True) as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
        try:
            dfd = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


@dataclass(frozen=True)
class RouteBinding:
    backend: str
    task_id: str | None = None
    note: str | None = None
    backend_model: str | None = None
    artifact_digest: str | None = None
    backend_fingerprint: str | None = None
    calibration_digest: str | None = None
    qualification_digest: str | None = None
    independent_qualification_digest: str | None = None
    artifact_attestation_digest: str | None = None
    promotion_id: str | None = None
    min_score: float | None = None
    fallback_policy: str = "generalist"  # generalist | fail_closed
    direct_authorized: bool = False
    not_before: str | None = None
    expires_at: str | None = None
    deployment_stage: str = "stable"  # stable | shadow | canary
    baseline_backend: str | None = None
    canary_percent: float = 0.0

    def __post_init__(self) -> None:
        if self.fallback_policy not in {"generalist", "fail_closed"}:
            raise ValueError("fallback_policy must be generalist or fail_closed")
        if self.deployment_stage not in {"stable", "shadow", "canary"}:
            raise ValueError("deployment_stage must be stable, shadow or canary")
        if not 0.0 <= float(self.canary_percent) <= 100.0:
            raise ValueError("canary_percent must be in [0,100]")
        if self.deployment_stage in {"shadow", "canary"} and not self.baseline_backend:
            raise ValueError("shadow/canary deployments require baseline_backend")
        if self.deployment_stage == "shadow" and float(self.canary_percent) != 0.0:
            raise ValueError("shadow deployments must use canary_percent=0")
        if self.deployment_stage == "canary" and not 0.0 < float(self.canary_percent) < 100.0:
            raise ValueError("canary deployments require 0 < canary_percent < 100")
        if self.deployment_stage != "stable" and self.direct_authorized:
            raise ValueError("only stable deployments may be direct_authorized")
        if self.min_score is not None and not 0.0 <= float(self.min_score) <= 1.0:
            raise ValueError("min_score must be in [0,1]")
        if self.direct_authorized and self.fallback_policy != "fail_closed":
            raise ValueError("direct_authorized tasks must use fallback_policy=fail_closed")
        if self.direct_authorized and self.min_score is None:
            raise ValueError("direct_authorized tasks require an explicit min_score operating threshold")
        if self.direct_authorized and (not self.artifact_digest or not self.backend_fingerprint or not self.calibration_digest or not self.qualification_digest or not self.independent_qualification_digest or not self.artifact_attestation_digest or not self.promotion_id):
            raise ValueError("direct_authorized tasks require artifact_digest, backend_fingerprint, calibration_digest, qualification_digest, independent_qualification_digest, artifact_attestation_digest and promotion_id")
        if self.direct_authorized and not all(_is_sha256_digest(x) for x in (self.artifact_digest, self.backend_fingerprint, self.calibration_digest, self.qualification_digest, self.independent_qualification_digest, self.artifact_attestation_digest)):
            raise ValueError("direct_authorized evidence digests must use sha256:<64 hex chars>")
        if self.not_before and self.expires_at:
            a, b = _parse_time(self.not_before), _parse_time(self.expires_at)
            if a is not None and b is not None and a >= b:
                raise ValueError("not_before must be before expires_at")

    def active(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(timezone.utc)
        start, end = _parse_time(self.not_before), _parse_time(self.expires_at)
        return (start is None or now >= start) and (end is None or now < end)


class TaskRegistry:
    def __init__(self, routes: Mapping[str, RouteBinding] | None = None, *, revision: int = 0,
                 updated_at: str | None = None, integrity_verified: bool = False):
        self.routes = dict(routes or {})
        self.revision = int(revision)
        self.updated_at = updated_at or _utcnow()
        self.integrity_verified = bool(integrity_verified)

    def lookup_any(self, question: Mapping[str, Any]) -> RouteBinding | None:
        return self.routes.get(question_signature(question))

    def lookup(self, question: Mapping[str, Any]) -> RouteBinding | None:
        binding = self.lookup_any(question)
        return binding if binding is not None and binding.active() else None

    def payload(self) -> dict[str, Any]:
        return {
            "version": REGISTRY_VERSION,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "routes": {
                k: {kk: vv for kk, vv in vars(v).items() if vv is not None}
                for k, v in sorted(self.routes.items())
            },
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()

    def to_dict(self, *, hmac_key: str | None = None) -> dict[str, Any]:
        out = self.payload()
        integrity: dict[str, Any] = {"payload_sha256": self.digest}
        if hmac_key:
            integrity.update({
                "algorithm": "hmac-sha256",
                "mac": hmac.new(hmac_key.encode("utf-8"), canonical_json(out).encode("utf-8"), hashlib.sha256).hexdigest(),
            })
        out["integrity"] = integrity
        return out

    @classmethod
    def load(cls, path: str | None, *, hmac_key: str | None = None,
             require_hmac: bool = False) -> "TaskRegistry":
        if not path:
            if require_hmac:
                raise ValueError("FABRIC_REGISTRY_REQUIRE_HMAC requires FABRIC_REGISTRY")
            return cls()
        data = json.loads(Path(path).read_text())
        version = int(data.get("version", 0))
        if version not in {1, 2, 3, 4, REGISTRY_VERSION}:
            raise ValueError(f"unsupported task registry version {data.get('version')}")
        raw = data.get("routes", {})
        if not isinstance(raw, dict):
            raise ValueError("registry routes must be an object")

        # v1 is migrated in memory. It is never considered integrity-verified.
        if version == 1:
            if require_hmac:
                raise ValueError("registry v1 has no authenticated integrity; migrate/sign it first")
            return cls({k: RouteBinding(**v) for k, v in raw.items()}, revision=0,
                       updated_at=data.get("updated_at") or _utcnow(), integrity_verified=False)

        integrity = data.get("integrity")
        payload = {k: data[k] for k in ("version", "revision", "updated_at", "routes") if k in data}
        payload_digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        if not isinstance(integrity, Mapping) or integrity.get("payload_sha256") != payload_digest:
            raise ValueError("registry payload digest mismatch or missing integrity block")

        verified = False
        mac = integrity.get("mac")
        if mac is not None:
            if integrity.get("algorithm") != "hmac-sha256":
                raise ValueError("unsupported registry integrity algorithm")
            if hmac_key:
                expected = hmac.new(hmac_key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(mac), expected):
                    raise ValueError("registry HMAC verification failed")
                verified = True
            elif require_hmac:
                raise ValueError("registry is HMAC-signed but FABRIC_REGISTRY_HMAC_KEY is missing")
        elif require_hmac:
            raise ValueError("registry HMAC is required but registry is unsigned")

        if version == 2:
            for sig, value in raw.items():
                if isinstance(value, Mapping) and value.get("direct_authorized") and not value.get("qualification_digest"):
                    raise ValueError(
                        f"registry v2 direct-authorized route {sig} lacks qualification evidence; "
                        "requalify it with the v1.3 promotion pipeline before migration"
                    )
        if version == 4:
            for sig, value in raw.items():
                if isinstance(value, Mapping) and value.get("direct_authorized") and (not value.get("independent_qualification_digest") or not value.get("artifact_attestation_digest")):
                    raise ValueError(
                        f"registry v4 direct-authorized route {sig} lacks v1.5 independent qualification/supply-chain evidence; rebind it before migration"
                    )
        return cls({k: RouteBinding(**v) for k, v in raw.items()},
                   revision=int(data.get("revision", 0)), updated_at=data.get("updated_at") or _utcnow(),
                   integrity_verified=verified)

    def register(self, question: Mapping[str, Any], backend: str, *, task_id: str | None = None,
                 note: str | None = None, backend_model: str | None = None,
                 artifact_digest: str | None = None, backend_fingerprint: str | None = None, calibration_digest: str | None = None,
                 qualification_digest: str | None = None, independent_qualification_digest: str | None = None,
                 artifact_attestation_digest: str | None = None, promotion_id: str | None = None,
                 min_score: float | None = None, fallback_policy: str = "generalist",
                 direct_authorized: bool = False, not_before: str | None = None,
                 expires_at: str | None = None, deployment_stage: str = "stable",
                 baseline_backend: str | None = None, canary_percent: float = 0.0) -> str:
        sig = question_signature(question)
        self.routes[sig] = RouteBinding(
            backend=backend, task_id=task_id, note=note, backend_model=backend_model,
            artifact_digest=artifact_digest, backend_fingerprint=backend_fingerprint, calibration_digest=calibration_digest,
            qualification_digest=qualification_digest, independent_qualification_digest=independent_qualification_digest,
            artifact_attestation_digest=artifact_attestation_digest, promotion_id=promotion_id,
            min_score=min_score, fallback_policy=fallback_policy,
            direct_authorized=direct_authorized, not_before=not_before, expires_at=expires_at,
            deployment_stage=deployment_stage, baseline_backend=baseline_backend, canary_percent=canary_percent,
        )
        self.revision += 1
        self.updated_at = _utcnow()
        self.integrity_verified = False
        return sig

    def revoke(self, signature: str) -> bool:
        existed = signature in self.routes
        if existed:
            del self.routes[signature]
            self.revision += 1
            self.updated_at = _utcnow()
            self.integrity_verified = False
        return existed


def _checkpoint_payload(registry: TaskRegistry) -> dict[str, Any]:
    return {
        "version": CHECKPOINT_VERSION,
        "revision": registry.revision,
        "registry_sha256": registry.digest,
        "updated_at": _utcnow(),
    }


def _checkpoint_mac(payload: Mapping[str, Any], hmac_key: str) -> str:
    return hmac.new(hmac_key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def enforce_registry_checkpoint(registry: TaskRegistry, path: str | None, *, hmac_key: str | None,
                                min_revision: int = 0) -> dict[str, Any] | None:
    """Reject stale/equivocated registries and advance an HMAC-sealed monotonic checkpoint.

    This protects against accidental or single-file rollback. A full machine snapshot rollback can
    still restore both registry and checkpoint; production deployments should also pin
    ``FABRIC_REGISTRY_MIN_REVISION`` in external deployment state when rollback resistance matters.
    """
    if registry.revision < int(min_revision):
        raise ValueError(
            f"registry revision {registry.revision} is below configured minimum {int(min_revision)}"
        )
    if not path:
        return None
    if not hmac_key:
        raise ValueError("FABRIC_REGISTRY_CHECKPOINT requires FABRIC_REGISTRY_HMAC_KEY")
    target = Path(path)
    if target.exists():
        raw = json.loads(target.read_text())
        if int(raw.get("version", 0)) != CHECKPOINT_VERSION:
            raise ValueError("unsupported registry checkpoint version")
        payload = {k: raw.get(k) for k in ("version", "revision", "registry_sha256", "updated_at")}
        integrity = raw.get("integrity")
        if not isinstance(integrity, Mapping) or integrity.get("algorithm") != "hmac-sha256":
            raise ValueError("registry checkpoint is missing HMAC integrity")
        expected = _checkpoint_mac(payload, hmac_key)
        if not hmac.compare_digest(str(integrity.get("mac") or ""), expected):
            raise ValueError("registry checkpoint HMAC verification failed")
        old_revision = int(payload.get("revision") or 0)
        old_digest = str(payload.get("registry_sha256") or "")
        if registry.revision < old_revision:
            raise ValueError(
                f"registry rollback detected: revision {registry.revision} < checkpoint {old_revision}"
            )
        if registry.revision == old_revision and registry.digest != old_digest:
            raise ValueError("registry equivocation detected: same revision has a different digest")
        if registry.revision == old_revision:
            return raw
    payload = _checkpoint_payload(registry)
    out = {
        **payload,
        "integrity": {"algorithm": "hmac-sha256", "mac": _checkpoint_mac(payload, hmac_key)},
    }
    atomic_write_json(target, out)
    return out
