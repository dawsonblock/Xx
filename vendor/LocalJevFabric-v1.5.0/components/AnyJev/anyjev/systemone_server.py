from __future__ import annotations

import argparse
import hashlib
import secrets
from pathlib import Path
from typing import Any, Mapping

from anyjev import Decider
from anyjev.artifact_binding import backend_fingerprint
from anyjev.backends.hf import HFBackend
from anyjev.result import LevelError
from anyjev.systemone import SystemOneEngine


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def create_app(engine: SystemOneEngine, *, api_key: str | None = None,
               manifest: Mapping[str, Any] | None = None):
    try:
        from fastapi import Body, Depends, FastAPI, Header, HTTPException
    except ImportError as exc:
        raise RuntimeError("Install AnyJev with the server extra: pip install '.[hf,server]'") from exc

    attestation = dict(manifest or {})
    app = FastAPI(title="AnyJev SystemOne", version="0.4.0-hardened")

    async def authorize(authorization: str | None = Header(default=None)) -> None:
        if api_key is None:
            return
        scheme, _, token = (authorization or "").partition(" ")
        if scheme.lower() != "bearer" or not secrets.compare_digest(token, api_key):
            raise HTTPException(status_code=401, detail="Invalid API key", headers={"WWW-Authenticate": "Bearer"})

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "version": "0.4.0-hardened", "model": engine.model, "level": engine.level,
                "require_level": engine.require_level, "attestation": attestation}

    @app.get("/v1/fabric/manifest", dependencies=[Depends(authorize)])
    async def fabric_manifest() -> dict[str, Any]:
        return {
            "component": "AnyJev",
            "version": "0.4.0-hardened",
            "served_model": engine.model,
            "level": engine.level,
            "require_level": engine.require_level,
            **attestation,
        }

    @app.get("/v1/models", dependencies=[Depends(authorize)])
    async def models() -> dict[str, Any]:
        return {"object": "list", "data": [{"id": engine.model, "object": "model", "created": 0,
                                               "owned_by": "anyjev"}]}

    @app.post("/v1/systemone", dependencies=[Depends(authorize)])
    async def systemone(payload: Any = Body(...)) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="request body must be an object")
        try:
            return engine.evaluate(payload)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except LevelError as exc:
            # A specialist endpoint must fail closed if the exact L2 artifact is not available.
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Serve hardened AnyJev behind a Jev-compatible /v1/systemone API")
    p.add_argument("--model", required=True, help="Hugging Face model/checkpoint")
    p.add_argument("--served-model-name", default="anyjev")
    p.add_argument("--artifacts", required=True, help="AnyJev artifact bundle containing exact L2 heads")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8101)
    p.add_argument("--device", default="cuda")
    p.add_argument("--dtype", default="bfloat16")
    p.add_argument("--revision", default=None, help="Pin this in production")
    p.add_argument("--level", choices=("raw", "L0", "L1", "L2", "auto"), default="auto")
    p.add_argument("--require-level", choices=("raw", "L0", "L1", "L2", "none"), default="L2")
    p.add_argument("--api-key", default=None)
    p.add_argument("--calibration-report", default=None,
                   help="immutable held-out calibration/evaluation report; its SHA-256 is attested live")
    p.add_argument("--allow-unauthenticated-network", action="store_true",
                   help="permit a non-loopback bind without an API key (unsafe)")
    p.add_argument("--allow-legacy-artifacts", action="store_true",
                   help="unsafe compatibility switch for old unbound artifacts")
    args = p.parse_args(argv)
    host = args.host.strip().lower().strip("[]")
    loopback = host in {"localhost", "::1", "0:0:0:0:0:0:0:1"} or (host.startswith("127.") and len(host.split(".")) == 4)
    if not loopback and not args.api_key and not args.allow_unauthenticated_network:
        p.error("non-loopback --host requires --api-key; use --allow-unauthenticated-network only for deliberate insecure exposure")

    backend = HFBackend(args.model, device=args.device, dtype=args.dtype, revision=args.revision)
    decider = Decider(backend, level=args.level, allow_legacy_artifacts=args.allow_legacy_artifacts)
    decider.load_artifacts(args.artifacts)
    engine = SystemOneEngine(decider, model=args.served_model_name, level=args.level,
                             require_level=None if args.require_level == "none" else args.require_level)
    fingerprint = backend_fingerprint(backend)
    calibration_sha256 = file_sha256(args.calibration_report) if args.calibration_report else None
    required_level = None if args.require_level == "none" else args.require_level
    manifest = {
        "artifact_bundle_sha256": file_sha256(args.artifacts),
        "backend_fingerprint_sha256": fingerprint.get("fingerprint_sha256"),
        "calibration_evidence_sha256": calibration_sha256,
        "score_semantics": "calibrated" if calibration_sha256 and required_level in {"L1", "L2"} else "concentration",
        "backend_name": getattr(backend, "name", args.model),
        "revision": args.revision,
        "legacy_artifacts_enabled": bool(args.allow_legacy_artifacts),
    }
    import uvicorn
    uvicorn.run(create_app(engine, api_key=args.api_key, manifest=manifest), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
