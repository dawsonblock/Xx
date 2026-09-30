# Controlled Specialist Promotion Pipeline

LocalJevFabric v1.4.0 adds a controlled path for turning repeated generalist decisions into AnyJev specialists without allowing traffic, model confidence, or self-generated labels to mutate authority.

## Invariant

```text
generalist observation -> candidate -> human/owner-selected labels -> held-out evaluation
    -> HMAC-authenticated qualification -> live specialist attestation -> explicit approval
    -> HMAC-authenticated registry mutation
```

No earlier stage can grant direct execution authority.

## 1. Opt-in candidate journal

Set:

```bash
export FABRIC_PROMOTION_JOURNAL="$PWD/logs/jev-fabric-promotion.jsonl"
```

The journal records only **unregistered** exact SystemOne question definitions plus routing metadata. It does not store request `state` and it is non-authoritative. A modified journal can at worst nominate bad work for evaluation; it cannot promote a head.

Mine repeated tasks:

```bash
jev-fabric-promotion mine logs/jev-fabric-promotion.jsonl \
  --min-observations 100 \
  --output evidence/promotion-candidates.json
```

Candidate frequency is not correctness evidence. Do not train from generalist predictions as labels unless that is a deliberate distillation experiment with separate evaluation labels.

## 2. Fit the exact AnyJev head

Use the existing exact-task trainer with independently prepared labels:

```bash
python scripts/train_anyjev_systemone_head.py \
  --model Qwen/Qwen3-4B \
  --revision <PINNED_REVISION> \
  --question ./candidate-question.json \
  --question-id verify_targeted \
  --labels ./data/train.jsonl \
  --output ./artifacts/anyjev-heads.json
```

Training data and qualification data must be disjoint.

## 3. Run the live specialist

```bash
anyjev-serve \
  --model Qwen/Qwen3-4B \
  --revision <PINNED_REVISION> \
  --served-model-name anyjev \
  --artifacts ./artifacts/anyjev-heads.json \
  --calibration-report ./evidence/calibration.json \
  --host 127.0.0.1 --port 8101 \
  --require-level L2
```

The qualification artifact is bound to the live artifact bundle, backend fingerprint and calibration evidence reported by this server.

## 4. Create held-out qualification evidence

The qualification evaluator consumes JSONL records with an independently determined correctness bit and the specialist's calibrated confidence:

```json
{"correct": true, "confidence": 0.991}
{"correct": false, "confidence": 0.873}
```

Set a promotion secret separate from the registry secret:

```bash
export FABRIC_PROMOTION_HMAC_KEY='<random promotion authority key>'
```

Qualify:

```bash
jev-fabric-promotion qualify \
  ./candidate-question.json \
  ./evidence/heldout-results.jsonl \
  --url http://127.0.0.1:8101 \
  --task-id verify_targeted.v1 \
  --min-samples 500 \
  --min-accuracy 0.98 \
  --max-ece 0.03 \
  --max-brier 0.04 \
  --max-wilson-error-upper 0.04 \
  --operating-threshold 0.95 \
  --output ./evidence/verify_targeted.qualification.json
```

The output is HMAC-authenticated and contains the exact question signature, live artifact/fingerprint/calibration digests, evaluation-set digest, metrics, gates and operating threshold.

## 5. Explicit promotion into shadow

Set the independently held registry key:

```bash
export FABRIC_REGISTRY_HMAC_KEY='<registry authority key>'
```

Promote the qualified candidate. In v1.4 the CLI defaults new promotions to **shadow** mode, so provide the production baseline explicitly:

```bash
jev-fabric-promotion promote \
  config/tasks.registry.json \
  ./candidate-question.json \
  ./evidence/verify_targeted.qualification.json \
  --url http://127.0.0.1:8101 \
  --task-id verify_targeted.v1 \
  --baseline-backend llm2jev \
  --approve
```

Promotion verifies the qualification HMAC, exact question signature, qualification status, live artifact identity, live backend fingerprint, live calibration evidence and operating threshold before mutating the registry. A pre-mutation signed registry snapshot is written to `registry-history/`. The baseline remains production while the candidate is mirrored. Use `jev-fabric-rollout` to move from shadow to canary and then stable after live evidence is sufficient.

Direct authority is intentionally unavailable during shadow/canary. First accumulate live evidence, move the binding to `stable`, then use the attested specialist binder with the signed qualification artifact if that R0 task is separately approved for direct authority. The gateway still independently applies its R0/R1/R2/R3 policy. Specialist promotion never makes R2/R3 side effects directly executable.

## 6. Rollback without revision rollback

Authority revisions never move backward. To restore a historical route set:

```bash
jev-fabric-promotion rollback \
  config/tasks.registry.json \
  registry-history/registry-revision-00000017.json \
  --approve
```

The selected historical routes are emitted as `current_revision + 1`, preserving the anti-rollback monotonicity invariant.

## What is intentionally not automatic

v1.4.0 does **not** automatically generate labels, train heads, accept a candidate, sign qualification evidence, promote a route, enable direct authority, or lower operating thresholds. Those are distinct authority transitions by design.

## 7. Live rollout evidence

See `ROLLOUT_AND_DRIFT.md`. Shadow comparisons are non-authoritative; canary assignment is deterministic; severe drift can remove a specialist from service; labeled canary regressions can trigger a monotonic rollback.
