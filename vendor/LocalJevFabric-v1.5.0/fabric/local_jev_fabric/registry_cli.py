from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .registry import TaskRegistry, atomic_write_json


def _key(args) -> str | None:
    if args.hmac_key_env:
        value = os.environ.get(args.hmac_key_env)
        if not value:
            raise SystemExit(f"environment variable {args.hmac_key_env} is empty/missing")
        return value
    return os.environ.get("FABRIC_REGISTRY_HMAC_KEY")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Register an exact SystemOne question for a specialist backend")
    p.add_argument("registry")
    p.add_argument("question_json", help="JSON file containing one question object")
    p.add_argument("--backend", default="anyjev")
    p.add_argument("--task-id")
    p.add_argument("--note")
    p.add_argument("--backend-model")
    p.add_argument("--artifact-digest")
    p.add_argument("--backend-fingerprint")
    p.add_argument("--calibration-digest")
    p.add_argument("--min-score", type=float)
    p.add_argument("--fallback-policy", choices=("generalist", "fail_closed"), default="generalist")
    p.add_argument("--direct-authorized", action="store_true")
    p.add_argument("--deployment-stage", choices=("stable","shadow","canary"), default="stable")
    p.add_argument("--baseline-backend")
    p.add_argument("--canary-percent", type=float, default=0.0)
    p.add_argument("--not-before")
    p.add_argument("--expires-at")
    p.add_argument("--hmac-key-env", help="environment variable holding registry HMAC secret")
    args = p.parse_args(argv)
    if args.direct_authorized:
        raise SystemExit(
            "v1.5 forbids direct authority through jev-fabric-register; use jev-fabric-bind-specialist with authenticated qualification and supply-chain evidence"
        )
    path = Path(args.registry)
    key = _key(args)
    if path.exists():
        existing = json.loads(path.read_text())
        signed = isinstance(existing.get("integrity"), dict) and bool(existing["integrity"].get("mac"))
        if signed and not key:
            raise SystemExit("registry is HMAC-signed; provide its HMAC key before editing")
    if args.direct_authorized and not key:
        raise SystemExit("--direct-authorized requires an HMAC key so the authority-bearing registry is authenticated")
    reg = TaskRegistry.load(str(path), hmac_key=key) if path.exists() else TaskRegistry()
    question = json.loads(Path(args.question_json).read_text())
    if not isinstance(question, dict):
        raise SystemExit("question_json must contain one JSON object")
    sig = reg.register(
        question, args.backend, task_id=args.task_id, note=args.note,
        backend_model=args.backend_model, artifact_digest=args.artifact_digest, backend_fingerprint=args.backend_fingerprint,
        calibration_digest=args.calibration_digest, min_score=args.min_score,
        fallback_policy=args.fallback_policy, direct_authorized=args.direct_authorized,
        not_before=args.not_before, expires_at=args.expires_at, deployment_stage=args.deployment_stage,
        baseline_backend=args.baseline_backend, canary_percent=args.canary_percent,
    )
    atomic_write_json(path, reg.to_dict(hmac_key=key))
    print(sig)
    print(f"revision={reg.revision}")
    print(f"registry_sha256={reg.digest}")


if __name__ == "__main__":
    main()
