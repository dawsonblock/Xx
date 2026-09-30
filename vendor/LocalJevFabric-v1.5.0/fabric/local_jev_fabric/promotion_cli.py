from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import httpx

from .promotion import (
    QualificationPolicy,
    load_eval_records,
    mine_candidates,
    qualification_digest,
    qualification_payload,
    sign_qualification,
    verify_qualification,
    write_json,
)
from .registry import TaskRegistry, atomic_write_json, question_signature


def _sha(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdefABCDEF' for c in value):
        return None
    return 'sha256:' + value.lower()


def _manifest(url: str, api_key: str | None) -> dict[str, Any]:
    headers = {'authorization': f'Bearer {api_key}'} if api_key else {}
    r = httpx.get(url.rstrip('/') + '/v1/fabric/manifest', headers=headers, timeout=5.0)
    r.raise_for_status()
    value = r.json()
    if value.get('component') != 'AnyJev':
        raise SystemExit('live specialist manifest is not AnyJev')
    return value


def _attestation(manifest: dict[str, Any]) -> dict[str, Any]:
    artifact = _sha(manifest.get('artifact_bundle_sha256'))
    fingerprint = _sha(manifest.get('backend_fingerprint_sha256'))
    calibration = _sha(manifest.get('calibration_evidence_sha256'))
    model = manifest.get('served_model')
    if artifact is None or fingerprint is None or not isinstance(model, str):
        raise SystemExit('AnyJev manifest lacks artifact/backend/model attestation')
    if manifest.get('legacy_artifacts_enabled'):
        raise SystemExit('refusing a specialist with legacy artifacts enabled')
    return {
        'backend_model': model,
        'artifact_digest': artifact,
        'backend_fingerprint': fingerprint,
        'calibration_digest': calibration,
        'score_semantics': manifest.get('score_semantics'),
    }


def cmd_mine(args: argparse.Namespace) -> None:
    candidates = mine_candidates(args.journal, min_observations=args.min_observations)
    result = {'version': 1, 'candidates': candidates}
    if args.output:
        write_json(args.output, result)
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_qualify(args: argparse.Namespace) -> None:
    key = os.environ.get(args.hmac_key_env)
    if not key:
        raise SystemExit(f'{args.hmac_key_env} must contain the promotion HMAC key')
    question = json.loads(Path(args.question_json).read_text())
    if not isinstance(question, dict):
        raise SystemExit('question_json must contain one object')
    att = _attestation(_manifest(args.url, args.api_key))
    records, eval_digest = load_eval_records(args.eval_jsonl)
    policy = QualificationPolicy(
        min_samples=args.min_samples,
        min_accuracy=args.min_accuracy,
        max_ece=args.max_ece,
        max_brier=args.max_brier,
        max_wilson_error_upper=args.max_wilson_error_upper,
        operating_threshold=args.operating_threshold,
    )
    payload = qualification_payload(
        question=question,
        task_id=args.task_id,
        backend=args.backend,
        backend_model=att['backend_model'],
        artifact_digest=att['artifact_digest'],
        backend_fingerprint=att['backend_fingerprint'],
        calibration_digest=att['calibration_digest'],
        eval_records=records,
        eval_digest=eval_digest,
        policy=policy,
    )
    signed = sign_qualification(payload, key)
    write_json(args.output, signed)
    print(f"qualified={str(payload['qualified']).lower()}")
    print(f"samples={payload['metrics']['samples']}")
    print(f"accuracy={payload['metrics']['accuracy']:.6f}")
    print(f"ece={payload['metrics']['ece_10bin']:.6f}")
    print(f"qualification_digest={qualification_digest(signed)}")
    if not payload['qualified']:
        raise SystemExit(2)


def _snapshot_registry(path: Path, reg: TaskRegistry, key: str | None, history_dir: Path) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    snapshot = history_dir / f'registry-revision-{reg.revision:08d}.json'
    if snapshot.exists():
        existing = TaskRegistry.load(str(snapshot), hmac_key=key, require_hmac=bool(key))
        if existing.digest != reg.digest:
            raise SystemExit(f'history snapshot collision at revision {reg.revision}')
        return snapshot
    atomic_write_json(snapshot, reg.to_dict(hmac_key=key))
    return snapshot


def cmd_promote(args: argparse.Namespace) -> None:
    if not args.approve:
        raise SystemExit('promotion is a registry mutation; pass --approve explicitly')
    promo_key = os.environ.get(args.promotion_hmac_key_env)
    if not promo_key:
        raise SystemExit(f'{args.promotion_hmac_key_env} must contain the promotion HMAC key')
    reg_key = os.environ.get(args.registry_hmac_key_env)
    path = Path(args.registry)
    if not path.exists():
        raise SystemExit('registry does not exist')
    raw_qualification = json.loads(Path(args.qualification).read_text())
    qualification = verify_qualification(raw_qualification, hmac_key=promo_key, require_qualified=True)
    question = json.loads(Path(args.question_json).read_text())
    if not isinstance(question, dict):
        raise SystemExit('question_json must contain one object')
    sig = question_signature(question)
    if qualification.get('question_signature') != sig:
        raise SystemExit('qualification is for a different exact question signature')
    if args.task_id and qualification.get('task_id') != args.task_id:
        raise SystemExit('qualification task_id does not match --task-id')
    manifest = _manifest(args.url, args.api_key)
    att = _attestation(manifest)
    for key in ('backend_model', 'artifact_digest', 'backend_fingerprint', 'calibration_digest'):
        if qualification.get(key) != att.get(key):
            raise SystemExit(f'live specialist no longer matches qualification field {key}')
    deployment_stage = getattr(args, 'deployment_stage', 'stable')
    baseline_backend = getattr(args, 'baseline_backend', None)
    if deployment_stage in {'shadow', 'canary'} and not baseline_backend:
        raise SystemExit('shadow/canary promotion requires --baseline-backend')
    if args.direct_authorized:
        raise SystemExit('v1.5 promotion never grants direct authority; complete shadow/canary rollout, move stable, then use jev-fabric-bind-specialist with the signed qualification')
    min_score = float(args.min_score if args.min_score is not None else qualification['policy']['operating_threshold'])
    if min_score < float(qualification['policy']['operating_threshold']):
        raise SystemExit('min-score cannot be below the qualified operating threshold')

    existing_raw = json.loads(path.read_text())
    existing_signed = isinstance(existing_raw.get('integrity'), dict) and bool(existing_raw['integrity'].get('mac'))
    if existing_signed and not reg_key:
        raise SystemExit('registry is signed; registry HMAC key is required to mutate it')
    reg = TaskRegistry.load(str(path), hmac_key=reg_key, require_hmac=existing_signed)
    history = Path(args.history_dir) if args.history_dir else path.parent / 'registry-history'
    snap = _snapshot_registry(path, reg, reg_key, history)
    q_digest = qualification_digest(raw_qualification)
    task_id = str(qualification['task_id'])
    new_sig = reg.register(
        question,
        args.backend,
        task_id=task_id,
        note=args.note or f'Promoted from qualification {q_digest}',
        backend_model=att['backend_model'],
        artifact_digest=att['artifact_digest'],
        backend_fingerprint=att['backend_fingerprint'],
        calibration_digest=att['calibration_digest'],
        min_score=min_score,
        fallback_policy='fail_closed',
        direct_authorized=args.direct_authorized,
        expires_at=args.expires_at,
        qualification_digest=q_digest,
        promotion_id=q_digest,
        deployment_stage=deployment_stage,
        baseline_backend=baseline_backend,
        canary_percent=float(getattr(args, 'canary_percent', 0.0) or 0.0),
    )
    atomic_write_json(path, reg.to_dict(hmac_key=reg_key))
    print(f'signature={new_sig}')
    print(f'qualification_digest={q_digest}')
    print(f'previous_snapshot={snap}')
    print(f'new_revision={reg.revision}')
    print(f'registry_sha256={reg.digest}')


def cmd_rollback(args: argparse.Namespace) -> None:
    if not args.approve:
        raise SystemExit('rollback mutates authority state; pass --approve explicitly')
    reg_key = os.environ.get(args.registry_hmac_key_env)
    if not reg_key:
        raise SystemExit('rollback requires the registry HMAC key')
    path = Path(args.registry)
    current = TaskRegistry.load(str(path), hmac_key=reg_key, require_hmac=True)
    snapshot = Path(args.snapshot)
    target = TaskRegistry.load(str(snapshot), hmac_key=reg_key, require_hmac=True)
    # Rollback is represented as a new monotonic revision; revision numbers never move backward.
    target.revision = current.revision + 1
    from datetime import datetime, timezone
    target.updated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')
    target.integrity_verified = False
    history = Path(args.history_dir) if args.history_dir else path.parent / 'registry-history'
    snap = _snapshot_registry(path, current, reg_key, history)
    atomic_write_json(path, target.to_dict(hmac_key=reg_key))
    print(f'rollback_source={snapshot}')
    print(f'previous_snapshot={snap}')
    print(f'new_revision={target.revision}')
    print(f'registry_sha256={target.digest}')


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description='Controlled specialist promotion pipeline')
    sub = p.add_subparsers(dest='command', required=True)

    mine = sub.add_parser('mine', help='mine repeated unregistered exact tasks from the opt-in promotion journal')
    mine.add_argument('journal')
    mine.add_argument('--min-observations', type=int, default=10)
    mine.add_argument('--output')
    mine.set_defaults(func=cmd_mine)

    qualify = sub.add_parser('qualify', help='produce an HMAC-authenticated held-out qualification artifact')
    qualify.add_argument('question_json')
    qualify.add_argument('eval_jsonl', help='JSONL rows: {"correct": bool, "confidence": 0..1}')
    qualify.add_argument('--url', required=True, help='live AnyJev server root')
    qualify.add_argument('--backend', default='anyjev')
    qualify.add_argument('--task-id', required=True)
    qualify.add_argument('--api-key')
    qualify.add_argument('--output', required=True)
    qualify.add_argument('--hmac-key-env', default='FABRIC_PROMOTION_HMAC_KEY')
    qualify.add_argument('--min-samples', type=int, default=100)
    qualify.add_argument('--min-accuracy', type=float, default=0.95)
    qualify.add_argument('--max-ece', type=float, default=0.08)
    qualify.add_argument('--max-brier', type=float, default=0.10)
    qualify.add_argument('--max-wilson-error-upper', type=float, default=0.10)
    qualify.add_argument('--operating-threshold', type=float, default=0.80)
    qualify.set_defaults(func=cmd_qualify)

    promote = sub.add_parser('promote', help='promote a qualified exact task into the specialist registry')
    promote.add_argument('registry')
    promote.add_argument('question_json')
    promote.add_argument('qualification')
    promote.add_argument('--url', required=True)
    promote.add_argument('--backend', default='anyjev')
    promote.add_argument('--task-id')
    promote.add_argument('--api-key')
    promote.add_argument('--min-score', type=float)
    promote.add_argument('--note')
    promote.add_argument('--expires-at')
    promote.add_argument('--direct-authorized', action='store_true')
    promote.add_argument('--deployment-stage', choices=('shadow','stable'), default='shadow',
                         help='v1.5 defaults newly promoted specialists to non-authoritative shadow mode')
    promote.add_argument('--baseline-backend', help='required for shadow rollout; backend that remains production')
    promote.add_argument('--approve', action='store_true')
    promote.add_argument('--history-dir')
    promote.add_argument('--promotion-hmac-key-env', default='FABRIC_PROMOTION_HMAC_KEY')
    promote.add_argument('--registry-hmac-key-env', default='FABRIC_REGISTRY_HMAC_KEY')
    promote.set_defaults(func=cmd_promote)

    rollback = sub.add_parser('rollback', help='restore routes from a signed snapshot as a new monotonic revision')
    rollback.add_argument('registry')
    rollback.add_argument('snapshot')
    rollback.add_argument('--approve', action='store_true')
    rollback.add_argument('--history-dir')
    rollback.add_argument('--registry-hmac-key-env', default='FABRIC_REGISTRY_HMAC_KEY')
    rollback.set_defaults(func=cmd_rollback)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == '__main__':
    main()
