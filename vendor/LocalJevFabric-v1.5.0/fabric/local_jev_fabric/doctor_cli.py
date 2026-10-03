from __future__ import annotations

import argparse
import json
from typing import Any, Mapping

import httpx

from .audit import AuditLog
from .config import BackendConfig, load_config
from .registry import RouteBinding, TaskRegistry, enforce_registry_checkpoint
from .drift import load_profile
from .capabilities import CapabilityRegistry


def check_binding_manifest(binding: RouteBinding, backend: BackendConfig, manifest: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_artifact = str(binding.artifact_digest or "").removeprefix("sha256:")
    expected_fingerprint = str(binding.backend_fingerprint or "").removeprefix("sha256:")
    expected_calibration = str(binding.calibration_digest or "").removeprefix("sha256:")
    if manifest.get("served_model") != backend.model:
        errors.append("served_model mismatch")
    if manifest.get("artifact_bundle_sha256") != expected_artifact:
        errors.append("artifact_bundle_sha256 mismatch")
    if manifest.get("backend_fingerprint_sha256") != expected_fingerprint:
        errors.append("backend_fingerprint_sha256 mismatch")
    if manifest.get("calibration_evidence_sha256") != expected_calibration:
        errors.append("calibration_evidence_sha256 mismatch")
    if manifest.get("score_semantics") != "calibrated":
        errors.append("specialist does not attest calibrated score semantics")
    if manifest.get("legacy_artifacts_enabled"):
        errors.append("legacy artifacts are enabled")
    return errors


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Preflight a LocalJevFabric deployment and its authority chain")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = p.parse_args(argv)

    report: dict[str, Any] = {"ok": True, "checks": {}, "errors": []}
    try:
        cfg = load_config()
        reg = TaskRegistry.load(
            cfg.registry_path, hmac_key=cfg.registry_hmac_key, require_hmac=cfg.require_registry_hmac
        )
        enforce_registry_checkpoint(
            reg, cfg.registry_checkpoint_path, hmac_key=cfg.registry_hmac_key, min_revision=cfg.registry_min_revision
        )
        report["checks"]["registry"] = {
            "version": 5,
            "revision": reg.revision,
            "sha256": reg.digest,
            "integrity_verified": reg.integrity_verified,
            "routes": len(reg.routes),
        }
        if cfg.capability_manifest_path:
            caps = CapabilityRegistry.load(cfg.capability_manifest_path)
            report["checks"]["capabilities"] = {"backends": len(caps.profiles), "path": cfg.capability_manifest_path}
    except Exception as exc:
        report["ok"] = False
        report["errors"].append(f"registry/config: {exc}")
        cfg = None
        reg = None

    if cfg is not None and cfg.audit_log_path:
        ok, count, error = AuditLog.verify(
            cfg.audit_log_path,
            checkpoint_path=cfg.audit_checkpoint_path,
            hmac_key=cfg.audit_hmac_key,
        )
        report["checks"]["audit"] = {"ok": ok, "records": count, "error": error}
        if not ok:
            report["ok"] = False
            report["errors"].append(f"audit: {error}")


        if cfg.drift_profile_path:
            try:
                profile = load_profile(cfg.drift_profile_path)
                report["checks"]["drift_profile"] = {"profiles": len(profile.get("profiles", {})), "path": cfg.drift_profile_path}
            except Exception as exc:
                report["ok"] = False
                report["errors"].append(f"drift profile: {exc}")

    manifests: dict[str, Mapping[str, Any]] = {}
    if cfg is not None:
        with httpx.Client(timeout=5.0) as client:
            for backend in cfg.backends:
                headers = {"authorization": f"Bearer {backend.api_key}"} if backend.api_key else {}
                item: dict[str, Any] = {"url": backend.url, "model": backend.model, "role": backend.role}
                try:
                    health = client.get(backend.url.rstrip("/") + "/health", headers=headers)
                    item["health_status"] = health.status_code
                except Exception as exc:
                    item["health_error"] = str(exc)
                    report["ok"] = False
                    report["errors"].append(f"backend {backend.name} unreachable: {exc}")
                try:
                    response = client.get(backend.url.rstrip("/") + "/v1/fabric/manifest", headers=headers)
                    item["manifest_status"] = response.status_code
                    if response.is_success:
                        data = response.json()
                        if isinstance(data, Mapping):
                            manifests[backend.name] = data
                except Exception as exc:
                    item["manifest_error"] = str(exc)
                report["checks"].setdefault("backends", {})[backend.name] = item

    if cfg is not None and reg is not None:
        by_name = cfg.by_name
        authority_checks: dict[str, Any] = {}
        for signature, binding in reg.routes.items():
            if not binding.direct_authorized:
                continue
            if binding.deployment_stage != "stable":
                report["ok"] = False
                report["errors"].append(f"authority {binding.task_id or signature}: direct authority requires stable rollout")
            backend = by_name.get(binding.backend)
            manifest = manifests.get(binding.backend)
            errors: list[str] = []
            if not binding.active():
                errors.append("direct-authorized binding is inactive or expired")
            if backend is None:
                errors.append("configured backend is missing")
            elif manifest is None:
                errors.append("live specialist manifest is unavailable")
            else:
                errors.extend(check_binding_manifest(binding, backend, manifest))
            authority_checks[signature] = {"task_id": binding.task_id, "backend": binding.backend, "errors": errors}
            if errors:
                report["ok"] = False
                report["errors"].append(f"authority {binding.task_id or signature}: " + "; ".join(errors))
        report["checks"]["direct_authority"] = authority_checks

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("OK" if report["ok"] else "FAILED")
        for name, value in report["checks"].items():
            print(f"{name}: {json.dumps(value, sort_keys=True)}")
        for error in report["errors"]:
            print(f"ERROR: {error}")
    if not report["ok"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
