# Runbook

## 1. Start one generalist

Use LLM2Jev with MLX, Transformers, or SGLang. Keep its host on `127.0.0.1` unless a bearer token is configured.

Example MLX:

```bash
llm2jev-serve --backend mlx --model-path /models/qwen-mlx \
  --served-model-name qwen-local --host 127.0.0.1 --port 30000
```

## 2. Start the fabric

```bash
export LLM2JEV_URL=http://127.0.0.1:30000
export LLM2JEV_MODEL=qwen-local
export FABRIC_GENERALIST_ORDER=llm2jev
export FABRIC_REGISTRY="$PWD/config/tasks.registry.json"
export FABRIC_AUDIT_LOG="$PWD/logs/jev-fabric-audit.jsonl"
local-jev-fabric
```

Health check:

```bash
curl http://127.0.0.1:8090/health
```

Before a production rollout, run:

```bash
jev-fabric-doctor
```

## 3. Enable authenticated registry + anti-rollback

```bash
export FABRIC_REGISTRY_HMAC_KEY='<long-random-secret>'
export FABRIC_REGISTRY_REQUIRE_HMAC=true
export FABRIC_REGISTRY_CHECKPOINT="$PWD/state/tasks.registry.checkpoint.json"
export FABRIC_REGISTRY_MIN_REVISION=0
```

Sign an existing registry once:

```bash
jev-fabric-sign-registry "$FABRIC_REGISTRY"
```

Raise `FABRIC_REGISTRY_MIN_REVISION` in deployment state after deliberate promotions if rollback resistance across filesystem snapshots matters.

## 4. Add AnyJev specialization

Fit the **exact** SystemOne question with `scripts/train_anyjev_systemone_head.py` and evaluate it on held-out data. Do not infer equivalence because two questions share `Yes/No` or the same choice set.

Start AnyJev with the exact immutable evaluation report used for authority:

```bash
anyjev-serve \
  --model Qwen/Qwen3-4B \
  --revision <PINNED_REVISION> \
  --served-model-name anyjev \
  --artifacts ./artifacts/anyjev-heads.json \
  --calibration-report ./evidence/verify-targeted-heldout.json \
  --host 127.0.0.1 --port 8101 \
  --require-level L2
```

Bind/qualify the running specialist without direct authority first, or use the v1.4 promotion pipeline so it enters shadow mode. Do **not** enable direct authority before staged rollout evidence. After shadow -> canary -> stable has passed, an R0 task may be separately rebound with `--qualification ... --direct-authorized` if policy allows it.

The binder pulls the live artifact hash, backend fingerprint and calibration report digest. If `--calibration-digest` is supplied as an extra assertion, it must match the live server exactly.

When wording changes, treat it as a new signature. Retrain or deliberately validate/register an AnyJev alias. Do not add fuzzy runtime matching.

## 5. Seal the audit head

Use a separate secret from the registry HMAC:

```bash
export FABRIC_AUDIT_HMAC_KEY='<different-random-secret>'
export FABRIC_AUDIT_CHECKPOINT="$PWD/logs/jev-fabric-audit.checkpoint.json"
```

Verify later with:

```bash
jev-fabric-audit-verify "$FABRIC_AUDIT_LOG" \
  --checkpoint "$FABRIC_AUDIT_CHECKPOINT"
```

## 6. Connect the gateway

Point `JEV_URL` at the fabric and classify tools with `JEV_TOOL_RISK_JSON`.

```bash
export JEV_URL=http://127.0.0.1:8090/v1/systemone
export JEV_MODEL=local-jev-fabric
export JEV_DIRECT_REQUIRE_AUTHORITY=true
```

The gateway's direct path validates the v1.5 authority envelope v4. Fabric also refuses direct authority for shadow/canary or drift-degraded specialists before the gateway sees the envelope. Envelope v4 additionally requires independent evaluator and artifact-supply-chain evidence.

## 7. Rollout sequence

1. Run gateway in observation/passthrough mode and record decisions.
2. Measure tool-choice error by tool/risk class.
3. HMAC-sign the registry and run `jev-fabric-doctor`.
4. Enable R0 direct execution only after empirical validation.
5. Keep R2/R3 non-autonomous.
6. Promote AnyJev heads task-by-task after held-out validation, entering shadow first.
7. Move shadow -> canary -> stable with `jev-fabric-rollout` only after live evidence.
8. Raise the external registry revision floor after approved promotions.
9. Revalidate whenever model revision, tokenizer, chat template, question contract, calibration report or tool schema changes.

## 8. Failure behavior

- AnyJev head unavailable/mismatch: `fallback_policy=generalist` may fall through; `fail_closed` tasks stop instead.
- Direct-authority calibration/artifact/fingerprint drift: answer may still exist, but fabric authority is false and the gateway cannot use the direct path.
- Generalist unavailable: next configured generalist is attempted.
- Open circuit: fallback proceeds; after cooldown exactly one half-open probe is admitted.
- All decision backends fail: fabric returns HTTP 503.
- Fabric/Jev unavailable to jev-gateway: the gateway fails open to the original upstream LLM request rather than taking the agent offline.

The last behavior is an availability policy, not a security policy. Environments where ordinary LLM fallback is unsafe should change the gateway policy to fail closed for those routes.


## Promotion

Use `docs/PROMOTION_PIPELINE.md`. Repeated traffic only nominates candidates; independent held-out evidence and explicit authenticated promotion are required before registry mutation.

## 9. v1.4 rollout evidence

```bash
export FABRIC_SHADOW_JOURNAL="$PWD/logs/jev-fabric-shadow.jsonl"
export FABRIC_OUTCOMES="$PWD/logs/jev-fabric-outcomes.jsonl"
```

Use `jev-fabric-rollout` for staged traffic, `jev-fabric-drift` for observable-behavior drift references, `jev-fabric-dataset snapshot` for immutable labeled datasets, and `jev-fabric-benchmark` as a release gate. See `ROLLOUT_AND_DRIFT.md` and `BENCHMARK_AND_DATASETS.md`.


## 10. v1.5 evidence and replay

For direct authority, generate independent evaluator and artifact signer keys outside the repository. Use `jev-fabric-artifact` and `jev-fabric-independent-qualify`, then pass both signed artifacts and their trusted public keys to `jev-fabric-bind-specialist`.

Enable `FABRIC_REPLAY_STORE` for sanitized replay evidence and `FABRIC_TELEMETRY_JSONL` for content-free request spans. Use `jev-fabric-replay verify` or `jev-fabric-replay incident` during an investigation.
