from __future__ import annotations

import argparse
import secrets
import uuid
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Response

from .audit import AuditLog
from .client import BackendError
from .config import FabricConfig, is_loopback_host, load_config
from .registry import TaskRegistry, enforce_registry_checkpoint
from .router import FabricRouter
from .promotion import PromotionJournal
from .shadow import ShadowJournal
from .outcomes import OutcomeStore
from .drift import DriftMonitor, load_profile
from .replay import ReplayStore
from .telemetry import TelemetrySink


def create_app(config: FabricConfig | None = None, registry: TaskRegistry | None = None,
               router: FabricRouter | None = None, audit: AuditLog | None = None,
               promotion_journal: PromotionJournal | None = None, shadow_journal: ShadowJournal | None = None,
               outcome_store: OutcomeStore | None = None, drift_monitor: DriftMonitor | None = None,
               replay_store: ReplayStore | None = None, telemetry_sink: TelemetrySink | None = None) -> FastAPI:
    cfg = config or load_config()
    reg = registry or TaskRegistry.load(
        cfg.registry_path, hmac_key=cfg.registry_hmac_key, require_hmac=cfg.require_registry_hmac
    )
    enforce_registry_checkpoint(
        reg, cfg.registry_checkpoint_path, hmac_key=cfg.registry_hmac_key, min_revision=cfg.registry_min_revision
    )
    drift = drift_monitor or DriftMonitor(
        load_profile(cfg.drift_profile_path), window=cfg.drift_window, min_samples=cfg.drift_min_samples,
        degraded_z=cfg.drift_degraded_z, disabled_z=cfg.drift_disabled_z,
        degraded_js=cfg.drift_degraded_js, disabled_js=cfg.drift_disabled_js,
    )
    rt = router or FabricRouter(cfg, reg, drift=drift)
    audit_log = audit or AuditLog(
        cfg.audit_log_path, checkpoint_path=cfg.audit_checkpoint_path, hmac_key=cfg.audit_hmac_key
    )
    promo_log = promotion_journal or PromotionJournal(cfg.promotion_journal_path)
    shadow_log = shadow_journal or ShadowJournal(cfg.shadow_journal_path)
    outcomes = outcome_store or OutcomeStore(cfg.outcome_store_path)
    replays = replay_store or ReplayStore(cfg.replay_store_path)
    telemetry = telemetry_sink or TelemetrySink(cfg.telemetry_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        try:
            yield
        finally:
            close = getattr(rt.client, "close", None)
            if close is not None:
                await close()

    app = FastAPI(title="Local Jev Fabric", version="1.5.0", lifespan=lifespan)

    async def authorize(authorization: str | None = Header(default=None)) -> None:
        if cfg.api_key is None:
            return
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(token, cfg.api_key):
            raise HTTPException(status_code=401, detail="Invalid API key", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "version": "1.5.0",
            "model": cfg.model,
            "backends": rt.breaker.snapshot(),
            "registered_tasks": len(reg.routes),
            "registry": {
                "revision": reg.revision,
                "sha256": reg.digest,
                "integrity_verified": reg.integrity_verified,
                "hmac_required": cfg.require_registry_hmac,
                "min_revision": cfg.registry_min_revision,
                "checkpoint_enabled": cfg.registry_checkpoint_path is not None,
            },
            "audit_enabled": audit_log.path is not None,
            "audit_checkpoint_enabled": audit_log.checkpoint_path is not None,
            "promotion_journal_enabled": promo_log.path is not None,
            "shadow_journal_enabled": shadow_log.path is not None,
            "outcome_store_enabled": outcomes.path is not None,
            "drift_profile_enabled": cfg.drift_profile_path is not None,
            "capability_manifest_enabled": cfg.capability_manifest_path is not None,
            "capabilities": rt.capabilities.snapshot(),
            "replay_store_enabled": cfg.replay_store_path is not None,
            "telemetry_enabled": cfg.telemetry_path is not None,
            "drift": rt.drift.snapshot(),
        }

    @app.get("/v1/models", dependencies=[Depends(authorize)])
    async def models() -> dict[str, Any]:
        return {"object": "list", "data": [{"id": cfg.model, "object": "model", "created": 0,
                                               "owned_by": "local-jev-fabric"}]}

    @app.get("/v1/fabric/manifest", dependencies=[Depends(authorize)])
    async def manifest() -> dict[str, Any]:
        return {
            "version": "1.5.0",
            "model": cfg.model,
            "registry_revision": reg.revision,
            "registry_sha256": reg.digest,
            "registry_integrity_verified": reg.integrity_verified,
            "registry_min_revision": cfg.registry_min_revision,
            "registry_checkpoint_enabled": cfg.registry_checkpoint_path is not None,
            "audit_checkpoint_enabled": cfg.audit_checkpoint_path is not None,
            "promotion_journal_enabled": cfg.promotion_journal_path is not None,
            "shadow_journal_enabled": cfg.shadow_journal_path is not None,
            "outcome_store_enabled": cfg.outcome_store_path is not None,
            "drift_profile_enabled": cfg.drift_profile_path is not None,
            "capability_manifest_enabled": cfg.capability_manifest_path is not None,
            "capabilities": rt.capabilities.snapshot(),
            "replay_store_enabled": cfg.replay_store_path is not None,
            "telemetry_enabled": cfg.telemetry_path is not None,
            "backends": [
                {
                    "name": b.name,
                    "model": b.model,
                    "role": b.role,
                    "score_semantics": b.score_semantics,
                    "failure_threshold": b.failure_threshold,
                    "cooldown_s": b.cooldown_s,
                }
                for b in cfg.backends
            ],
        }

    @app.post("/v1/fabric/route", dependencies=[Depends(authorize)])
    async def route(payload: Any = Body(...), x_request_id: str | None = Header(default=None)) -> dict[str, Any]:
        if not isinstance(payload, dict) or not isinstance(payload.get("questions"), dict):
            raise HTTPException(status_code=422, detail="questions must be an object")
        try:
            plan = rt.plan(payload["questions"], request_id=(x_request_id or "preview")[:128])
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "registry_sha256": reg.digest,
            "routes": [
                {
                    "question_id": x.question_id,
                    "signature": x.signature,
                    "preferred": x.preferred,
                    "registered": x.registered,
                    "task_id": x.task_id,
                    "fallback_policy": x.binding.fallback_policy if x.binding else "generalist",
                    "direct_authorized": x.binding.direct_authorized if x.binding else False,
                    "deployment_stage": x.deployment_stage,
                    "candidate_backend": x.candidate_backend,
                    "baseline_backend": x.baseline_backend,
                    "shadow_backend": x.shadow_backend,
                    "canary_selected": x.canary_selected,
                    "drift_status": x.drift_status,
                }
                for x in plan
            ],
        }

    @app.post("/v1/systemone", dependencies=[Depends(authorize)])
    async def systemone(response: Response, payload: Any = Body(...),
                        x_request_id: str | None = Header(default=None)) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="request body must be an object")
        if "state" not in payload or "questions" not in payload:
            raise HTTPException(status_code=422, detail="state and questions are required")
        requested = payload.get("model")
        if requested not in (None, cfg.model, "auto"):
            raise HTTPException(status_code=404, detail="The requested model does not exist")
        body = dict(payload)
        body["model"] = cfg.model
        started = time.perf_counter()
        request_id = (x_request_id or "").strip()[:128] or str(uuid.uuid4())
        try:
            result, trace = await rt.evaluate_detailed(body, request_id=request_id)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except BackendError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        audit_log.append(
            request_id=request_id,
            request=body,
            response=result,
            trace=trace,
            registry_digest=reg.digest,
        )
        promo_log.append(request_id=request_id, questions=body["questions"], trace=trace)
        shadow_log.append(request_id=request_id, shadow_rows=list(trace.get("shadow") or []), evidence_sha256=trace.get("evidence_sha256"))
        replays.append(request_id=request_id, request=body, response=result, trace=trace, registry_payload=reg.payload())
        telemetry.emit_request(request_id=request_id, duration_ms=(time.perf_counter()-started)*1000.0, trace=trace)
        provenance = trace["provenance"]
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Jev-Fabric-Backends"] = ",".join(sorted(set(provenance.values())))
        response.headers["X-Jev-Fabric-Registry"] = reg.digest
        response.headers["X-Jev-Fabric-Direct-Authorized"] = "true" if trace["direct_authorized"] else "false"
        response.headers["X-Jev-Fabric-Evidence"] = str(trace.get("evidence_sha256") or "")
        return result


    @app.post("/v1/fabric/outcomes", dependencies=[Depends(authorize)])
    async def record_outcome(payload: Any = Body(...)) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="outcome must be an object")
        try:
            row = outcomes.append(payload)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {"stored": True, "outcome": row}

    @app.get("/v1/fabric/replay/{request_id}", dependencies=[Depends(authorize)])
    async def replay_record(request_id: str) -> dict[str, Any]:
        row = replays.get(request_id[:128])
        if row is None:
            raise HTTPException(status_code=404, detail="replay record not found")
        return row

    @app.get("/v1/fabric/drift", dependencies=[Depends(authorize)])
    async def drift_status() -> dict[str, Any]:
        return {"version": 1, "tasks": rt.drift.snapshot()}

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the local Jev decision fabric")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--allow-unauthenticated-network", action="store_true",
                        help="permit a non-loopback CLI bind without FABRIC_API_KEY (unsafe)")
    args = parser.parse_args(argv)
    cfg = load_config()
    host = args.host or cfg.host
    if not is_loopback_host(host) and not cfg.api_key and not args.allow_unauthenticated_network:
        parser.error("non-loopback --host requires FABRIC_API_KEY; use --allow-unauthenticated-network only for deliberate insecure exposure")
    import uvicorn
    uvicorn.run(create_app(cfg), host=host, port=args.port or cfg.port)


if __name__ == "__main__":
    main()
