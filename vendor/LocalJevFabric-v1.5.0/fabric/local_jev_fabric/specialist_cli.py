from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import httpx

from .registry import TaskRegistry, atomic_write_json, question_signature
from .promotion import qualification_digest, verify_qualification
from .artifact_signing import verify_attestation, attestation_digest
from .independent_qualification import verify as verify_independent_qualification, digest as independent_qualification_digest


def _sha(value: object) -> str | None:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        return None
    return f"sha256:{value.lower()}"


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description="Bind an exact question to a live-attested AnyJev specialist")
    p.add_argument("registry")
    p.add_argument("question_json")
    p.add_argument("--url", required=True, help="AnyJev server root, e.g. http://127.0.0.1:8101")
    p.add_argument("--backend", default="anyjev")
    p.add_argument("--task-id", required=True)
    p.add_argument("--note")
    p.add_argument("--api-key")
    p.add_argument("--min-score", type=float)
    p.add_argument("--calibration-digest", help="optional expected digest; must match the server's live calibration attestation")
    p.add_argument("--direct-authorized", action="store_true")
    p.add_argument("--deployment-stage", choices=("stable","shadow","canary"), default="stable")
    p.add_argument("--baseline-backend")
    p.add_argument("--canary-percent", type=float, default=0.0)
    p.add_argument("--qualification", help="HMAC qualification artifact; required for direct authority")
    p.add_argument("--independent-qualification", help="Ed25519 independent qualification artifact; required for direct authority")
    p.add_argument("--evaluator-public-key", help="trusted Ed25519 evaluator public key PEM")
    p.add_argument("--artifact-attestation", help="Ed25519 attestation for the live AnyJev artifact bundle")
    p.add_argument("--artifact-public-key", help="trusted Ed25519 artifact signer public key PEM")
    p.add_argument("--promotion-hmac-key-env", default="FABRIC_PROMOTION_HMAC_KEY")
    p.add_argument("--expires-at")
    p.add_argument("--hmac-key-env", default="FABRIC_REGISTRY_HMAC_KEY")
    args = p.parse_args(argv)

    headers = {"authorization": f"Bearer {args.api_key}"} if args.api_key else {}
    response = httpx.get(args.url.rstrip("/") + "/v1/fabric/manifest", headers=headers, timeout=5.0)
    response.raise_for_status()
    manifest = response.json()
    if manifest.get("component") != "AnyJev":
        raise SystemExit("backend manifest is not an AnyJev attestation")
    artifact = _sha(manifest.get("artifact_bundle_sha256"))
    fingerprint = _sha(manifest.get("backend_fingerprint_sha256"))
    calibration = _sha(manifest.get("calibration_evidence_sha256"))
    served_model = manifest.get("served_model")
    if artifact is None or fingerprint is None or not isinstance(served_model, str):
        raise SystemExit("AnyJev manifest lacks valid artifact/backend fingerprint/served model attestation")
    if manifest.get("legacy_artifacts_enabled"):
        raise SystemExit("refusing to bind a specialist server running with legacy artifacts enabled")
    if args.calibration_digest:
        expected = args.calibration_digest.lower()
        if calibration != expected:
            raise SystemExit(
                f"--calibration-digest does not match live server attestation ({expected!r} != {calibration!r})"
            )
    qualification_sha = None
    qualification_payload = None
    independent_sha = None
    independent_payload = None
    artifact_attestation_sha = None
    if args.direct_authorized and args.deployment_stage != "stable":
        raise SystemExit("direct authority is forbidden during shadow/canary rollout")
    if args.deployment_stage in {"shadow", "canary"} and not args.baseline_backend:
        raise SystemExit("shadow/canary deployment requires --baseline-backend")
    if args.direct_authorized:
        if args.min_score is None:
            p.error("--direct-authorized requires --min-score to pin the validated operating threshold")
        if calibration is None:
            raise SystemExit("--direct-authorized requires AnyJev to run with --calibration-report")
        if manifest.get("score_semantics") != "calibrated":
            raise SystemExit("--direct-authorized requires the AnyJev manifest to attest calibrated score semantics")
        if not args.qualification:
            raise SystemExit("--direct-authorized requires --qualification")
        if not args.independent_qualification or not args.evaluator_public_key:
            raise SystemExit("--direct-authorized requires --independent-qualification and --evaluator-public-key in v1.5")
        if not args.artifact_attestation or not args.artifact_public_key:
            raise SystemExit("--direct-authorized requires --artifact-attestation and --artifact-public-key in v1.5")
        promo_key = os.environ.get(args.promotion_hmac_key_env)
        if not promo_key:
            raise SystemExit(f"{args.promotion_hmac_key_env} must contain the promotion HMAC key")
        raw_qualification = json.loads(Path(args.qualification).read_text())
        qualification_payload = verify_qualification(raw_qualification, hmac_key=promo_key, require_qualified=True)
        qualification_sha = qualification_digest(raw_qualification)
        raw_independent = json.loads(Path(args.independent_qualification).read_text())
        independent_payload = verify_independent_qualification(raw_independent, args.evaluator_public_key, require_qualified=True)
        independent_sha = independent_qualification_digest(raw_independent)
        raw_artifact_attestation = json.loads(Path(args.artifact_attestation).read_text())
        artifact_payload = verify_attestation(raw_artifact_attestation, args.artifact_public_key, expected_kind="anyjev-artifact-bundle")
        artifact_attestation_sha = attestation_digest(raw_artifact_attestation)
        if artifact_payload.get("digest") != artifact:
            raise SystemExit("artifact supply-chain attestation does not match the live AnyJev artifact digest")

    key = os.environ.get(args.hmac_key_env) if args.hmac_key_env else None
    path = Path(args.registry)
    if path.exists():
        existing = json.loads(path.read_text())
        signed = isinstance(existing.get("integrity"), dict) and bool(existing["integrity"].get("mac"))
        if signed and not key:
            raise SystemExit("registry is HMAC-signed; provide its HMAC key before editing")
    if args.direct_authorized and not key:
        raise SystemExit("--direct-authorized requires the registry HMAC key")
    reg = TaskRegistry.load(str(path), hmac_key=key) if path.exists() else TaskRegistry()
    question = json.loads(Path(args.question_json).read_text())
    if not isinstance(question, dict):
        raise SystemExit("question_json must contain one JSON object")
    if qualification_payload is not None:
        if qualification_payload.get("question_signature") != question_signature(question):
            raise SystemExit("qualification is for a different exact question")
        expected = {
            "backend_model": served_model,
            "artifact_digest": artifact,
            "backend_fingerprint": fingerprint,
            "calibration_digest": calibration,
        }
        for field, value in expected.items():
            if qualification_payload.get(field) != value:
                raise SystemExit(f"qualification no longer matches live specialist field {field}")
        if independent_payload is not None:
            if independent_payload.get("question_signature") != question_signature(question):
                raise SystemExit("independent qualification is for a different exact question")
            if independent_payload.get("task_id") != args.task_id:
                raise SystemExit("independent qualification task_id does not match")
            for field, value in expected.items():
                if independent_payload.get(field) != value:
                    raise SystemExit(f"independent qualification no longer matches live specialist field {field}")
        operating = float(qualification_payload["policy"]["operating_threshold"])
        if independent_payload is not None:
            operating = max(operating, float(independent_payload["policy"]["operating_threshold"]))
        if args.min_score is not None and args.min_score < operating:
            raise SystemExit("--min-score cannot be below the qualification operating threshold")
    sig = reg.register(
        question,
        args.backend,
        task_id=args.task_id,
        note=args.note,
        backend_model=served_model,
        artifact_digest=artifact,
        backend_fingerprint=fingerprint,
        calibration_digest=calibration,
        qualification_digest=qualification_sha,
        independent_qualification_digest=independent_sha,
        artifact_attestation_digest=artifact_attestation_sha,
        promotion_id=qualification_sha,
        min_score=args.min_score,
        fallback_policy="fail_closed",
        direct_authorized=args.direct_authorized,
        expires_at=args.expires_at,
        deployment_stage=args.deployment_stage, baseline_backend=args.baseline_backend, canary_percent=args.canary_percent,
    )
    atomic_write_json(path, reg.to_dict(hmac_key=key))
    print(sig)
    print(f"backend_model={served_model}")
    print(f"artifact_digest={artifact}")
    print(f"backend_fingerprint={fingerprint}")
    print(f"calibration_digest={calibration or 'none'}")
    print(f"qualification_digest={qualification_sha or 'none'}")
    print(f"independent_qualification_digest={independent_sha or 'none'}")
    print(f"artifact_attestation_digest={artifact_attestation_sha or 'none'}")
    print(f"registry_sha256={reg.digest}")


if __name__ == "__main__":
    main()
