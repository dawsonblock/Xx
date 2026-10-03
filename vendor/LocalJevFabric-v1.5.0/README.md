# LocalJevFabric v1.5.0

A hardened local System One / Jev-compatible decision stack assembled from the supplied **AnyJev**, **LLM2Jev**, and **jev-gateway** source trees.

This archive does **not** contain TypeSafe Jev weights and does not claim to be TypeSafe Jev. It exposes one local `/v1/systemone` front door that can send exact, validated tasks to AnyJev specialists and unseen tasks to Jev-compatible generalists such as LLM2Jev or an optional external Laya server.

v1.5.0 adds capability-aware generalist routing, cost-aware escalation, independent Ed25519 qualification, signed artifact-supply-chain evidence, sanitized replay/incident bundles, and privacy-minimized observability. It retains v1.4 shadow/canary, drift, outcome, dataset and benchmark controls. The central rule remains:

> A model score can select a decision. It cannot grant execution authority by itself.

## Architecture

```text
coding agent / OpenAI-compatible client
                 |
                 v
            jev-gateway
       R0/R1/R2/R3 policy
                 |
                 v
      POST /v1/systemone
                 |
                 v
         LocalJevFabric
   exact + authenticated registry
        /                 \
       /                   \
validated specialist    unseen/general task
       |                    |
       v                    v
    AnyJev L2          LLM2Jev / Laya
       |                    |
       +---------+----------+
                 |
      schema + score gates
                 |
     tamper-evident audit log
```

For direct execution, v1.5 uses the following authority chain:

```text
HMAC-verified registry
        AND
exact task signature
        AND
fail-closed binding
        AND
calibrated backend declaration
        AND
live AnyJev artifact attestation
        AND
live held-out calibration evidence attestation
        AND
HMAC-authenticated held-out qualification binding
        AND
independent Ed25519 evaluator qualification
        AND
Ed25519 artifact-bundle supply-chain attestation
        AND
stable rollout + normal drift state
        AND
anti-rollback registry policy
        AND
gateway R0 tool policy
        -> direct execution eligible
```

If any link is missing, the gateway downgrades to ordinary LLM-mediated execution rather than treating confidence as permission.

## What changed in v1.5.0

### Capability-aware generalist routing

- `FABRIC_CAPABILITY_MANIFEST` can declare which question types each generalist supports, benchmarked expected accuracy, P95 latency, cost units, and optional state-size limits.
- Unknown tasks are ranked by expected error cost + compute cost + latency cost instead of blindly using one fixed global order.
- Capability metadata is explicitly non-authoritative: it may select or sequence generalists but cannot grant direct execution.
- `config/capabilities.example.json` provides a starting schema.

### Cost-aware escalation

- `EscalationPolicy` compares the expected reduction in decision error against incremental compute/latency cost.
- Calibrated scores can drive per-request uncertainty; uncalibrated backends use benchmarked capability accuracy instead of pretending concentration is correctness probability.
- A valid cheaper answer is retained provisionally, so failure of the stronger backend does not erase an otherwise acceptable answer.

### Independent qualification + signed supply chain

- `jev-fabric-artifact` creates and verifies Ed25519 attestations over artifact digests.
- `jev-fabric-independent-qualify` evaluates one exact task against a frozen held-out case set and signs the result with a separate evaluator key.
- Registry schema v5 adds `independent_qualification_digest` and `artifact_attestation_digest`.
- Direct authority now requires both forms of evidence in addition to the existing qualification/calibration/live-attestation chain.
- The gateway requires authority envelope v4 and rejects v3 or incomplete v4 direct-authority metadata.

### Deterministic replay and incident bundles

- `FABRIC_REPLAY_STORE` records question schemas, answers, authority evidence and cryptographic hashes while storing only a hash of request state.
- `jev-fabric-replay verify` checks record integrity and can verify a separately supplied original state against its hash.
- `jev-fabric-replay incident` builds a portable ZIP containing the sanitized replay record, verification report and optional registry/manifest evidence.

### Observability

- `FABRIC_TELEMETRY_JSONL` emits OpenTelemetry-style structured spans without prompt/state content.
- Spans include request/plan/evidence hashes, backend set, duration, question count, direct-authority result and escalation count.
- The JSONL format can be tailed directly or adapted to an OTLP collector without coupling the hot path to a telemetry vendor.

## What changed in v1.4.0

### Shadow and canary rollout

- Registry schema v4 adds `deployment_stage`, `baseline_backend`, and `canary_percent`.
- Newly promoted specialists default to **shadow** mode when using the v1.4 CLI.
- Shadow specialists receive mirrored questions but can never control the production answer or carry direct authority.
- Canary assignment is deterministic from request ID + exact task signature, so retries remain on the same arm.
- A selected canary can fall back to its baseline; a baseline request never falls forward into an experimental candidate.
- `jev-fabric-rollout` stages shadow/canary/stable deployments and can evaluate labeled canary evidence and perform a monotonic signed rollback.

### Drift gating

- `jev-fabric-drift` builds observable-behavior reference profiles from score/output telemetry.
- Runtime drift monitoring uses score-mean deviation plus Jensen-Shannon divergence of answer distributions.
- Degraded drift immediately removes direct authority. Severe drift disables fail-closed specialists rather than silently weakening them to a generalist.
- Drift is explicitly an observable decision-behavior detector; it does not claim hidden-state drift unless a backend exposes those features.

### Outcome feedback and frozen datasets

- `/v1/fabric/outcomes` records externally supplied outcome labels without storing request state.
- `jev-fabric-dataset snapshot` joins promotion observations with outcome labels into a new immutable snapshot directory.
- Every example receives a deterministic `train`, `validation`, `qualification`, or `audit_holdout` split.
- Qualification/audit holdouts are declared non-training partitions in the snapshot manifest. Existing snapshots are never overwritten.

### Qualification benchmark

- `jev-fabric-benchmark` drives real `/v1/systemone` requests and measures question accuracy, request accuracy, false-direct authorization rate, backend use and P50/P95/P99 latency.
- The CLI can enforce release gates such as minimum question accuracy and a zero false-direct rate.

### Existing authority protections retained

The authenticated registry, exact task binding, qualification evidence, live AnyJev attestation, audit chain, anti-rollback revision checkpoint, circuit breakers and gateway R0/R1/R2/R3 policy remain intact. Shadow/canary traffic is deliberately non-authoritative.

## v1.5 authority setup example

Create independent signer/evaluator keys (keep private PEM files outside the source tree):

```bash
jev-fabric-artifact keygen artifact-signing.pem artifact-signing.pub.pem
jev-fabric-artifact keygen evaluator.pem evaluator.pub.pem
```

Sign the exact AnyJev artifact-bundle digest reported by its live manifest:

```bash
jev-fabric-artifact sign-digest sha256:<artifact-bundle-digest> \
  --kind anyjev-artifact-bundle \
  --private-key artifact-signing.pem \
  --output artifact.attestation.json
```

Run the evaluator from a frozen held-out case set:

```bash
jev-fabric-independent-qualify run heldout.jsonl \
  --url http://127.0.0.1:8101 --model anyjev \
  --task-id verification-required.v1 --evaluator-id lab-A \
  --private-key evaluator.pem --output independent.qual.json
```

After shadow/canary rollout reaches stable, `jev-fabric-bind-specialist --direct-authorized` additionally requires the artifact attestation + public key and independent qualification + evaluator public key.

## Directory layout

```text
components/AnyJev/        hardened AnyJev source
components/LLM2Jev/       hardened LLM2Jev source
components/jev-gateway/    hardened agent/tool gateway
fabric/                    federated SystemOne service
config/                    example fabric/gateway/task configs
scripts/                   verification, smoke test, AnyJev head training
docs/                      architecture, security, authority chain, runbook, promotion pipeline, audit report
```

## Fastest usable setup: LLM2Jev generalist

Apple Silicon / MLX:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e "./components/LLM2Jev[mlx]" -e "./fabric[dev]"

llm2jev-serve --backend mlx \
  --model-path /path/to/local-mlx-model \
  --served-model-name qwen-local \
  --host 127.0.0.1 --port 30000
```

Transformers / CUDA or CPU:

```bash
pip install -e "./components/LLM2Jev[transformers]" -e "./fabric[dev]"

llm2jev-serve --backend transformers \
  --model-path /path/to/local-hf-model \
  --served-model-name qwen-local \
  --host 127.0.0.1 --port 30000
```

Start the fabric:

```bash
source .venv/bin/activate
export LLM2JEV_URL=http://127.0.0.1:30000
export LLM2JEV_MODEL=qwen-local
export FABRIC_GENERALIST_ORDER=llm2jev
export FABRIC_REGISTRY="$PWD/config/tasks.registry.json"
export FABRIC_AUDIT_LOG="$PWD/logs/jev-fabric-audit.jsonl"
local-jev-fabric
```

Smoke test:

```bash
python scripts/smoke_systemone.py
```

The front door is:

```text
http://127.0.0.1:8090/v1/systemone
```

## HMAC-authenticate the task registry

For a registry capable of granting direct authority, use a strong secret outside the repository:

```bash
export FABRIC_REGISTRY_HMAC_KEY='replace-with-a-long-random-secret'
export FABRIC_REGISTRY_REQUIRE_HMAC=true
```

`jev-fabric-register` and `jev-fabric-bind-specialist` will use `FABRIC_REGISTRY_HMAC_KEY` when writing the registry. Startup fails if HMAC verification is required and the registry cannot be authenticated.

## Add an AnyJev L2 specialist

Install AnyJev:

```bash
pip install -e "./components/AnyJev[hf,server]"
```

Fit an exact head:

```bash
python scripts/train_anyjev_systemone_head.py \
  --model Qwen/Qwen3-4B \
  --revision <PINNED_REVISION> \
  --question config/example-question.json \
  --question-id verify_targeted \
  --labels ./data/verify_targeted.jsonl \
  --output ./artifacts/anyjev-heads.json
```

Start the specialist:

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

For a normal fail-closed specialist binding, the new helper reads the running server's attestation instead of making you copy hashes manually:

```bash
jev-fabric-bind-specialist \
  config/tasks.registry.json \
  config/example-question.json \
  --url http://127.0.0.1:8101 \
  --backend anyjev \
  --task-id verify_targeted.v1 \
  --min-score 0.85
```

For direct authority, start AnyJev with `--calibration-report` and opt in explicitly. The binder reads and stores that **live** report digest automatically:

```bash
export FABRIC_REGISTRY_HMAC_KEY='replace-with-secret'
export FABRIC_PROMOTION_HMAC_KEY='replace-with-a-separate-secret'
jev-fabric-bind-specialist \
  config/tasks.registry.json \
  config/example-question.json \
  --url http://127.0.0.1:8101 \
  --backend anyjev \
  --task-id verify_targeted.v1 \
  --min-score 0.90 \
  --qualification ./evidence/verify_targeted.qualification.json \
  --direct-authorized
```

A direct-authorized route is always fail closed. In v1.4 the signed qualification artifact must match the exact question and the live specialist artifact/fingerprint/calibration attestation; `--min-score` cannot be lower than its qualified operating threshold.

## Controlled promotion of repeated tasks

Enable the non-authoritative journal if you want to discover recurring unregistered questions:

```bash
export FABRIC_PROMOTION_JOURNAL="$PWD/logs/jev-fabric-promotion.jsonl"
```

Then follow [`docs/PROMOTION_PIPELINE.md`](docs/PROMOTION_PIPELINE.md) to mine candidates, fit an exact AnyJev head, create independently labeled held-out evaluation results, HMAC-sign qualification evidence and explicitly promote the task. Direct authority cannot be obtained from candidate frequency or model confidence.

## Connect jev-gateway

```bash
cd components/jev-gateway
pnpm install --frozen-lockfile
pnpm test
pnpm build

export JEV_URL=http://127.0.0.1:8090/v1/systemone
export JEV_MODEL=local-jev-fabric
export JEV_UNKNOWN_TOOL_RISK=R1
export JEV_DIRECT_REQUIRE_AUTHORITY=true
npm start
```

Use `config/gateway.local.env.example` as the safer starting configuration.

## Verify the audit chain

```bash
jev-fabric-audit-verify ./logs/jev-fabric-audit.jsonl
# With an HMAC-sealed head:
jev-fabric-audit-verify ./logs/jev-fabric-audit.jsonl \
  --checkpoint ./logs/jev-fabric-audit.checkpoint.json
```

The audit log stores hashes and routing evidence, not raw prompt/state. With `FABRIC_AUDIT_CHECKPOINT` + `FABRIC_AUDIT_HMAC_KEY`, end-of-log truncation is detected relative to the sealed head. External anchoring is still required to resist rollback of an entire machine/filesystem snapshot.

## Verification performed on this release

At packaging time in the provided environment:

- AnyJev: **93 passed, 7 skipped**.
- LocalJevFabric: **50 passed**.
- LLM2Jev: Python source compilation succeeds; the complete pytest suite still cannot start in this offline environment because its declared `openai` dependency is not installed.
- jev-gateway: all TypeScript source/test files pass syntax/transpile validation; its full Vitest suite cannot be installed/run in this offline environment because pnpm dependencies are unavailable.

Run `scripts/verify.sh` after installing all development dependencies for a complete local verification pass.

## Important limitations

- No official TypeSafe Jev weights are bundled.
- HMAC registry authentication protects against undetected edits only while the secret remains secret.
- AnyJev's compatibility fingerprint is not a byte-for-byte hash of multi-gigabyte model weights; immutable model revisions should still be pinned.
- A calibration evidence digest proves which report was authorized, not that the report itself is scientifically adequate. Evaluation quality remains your responsibility.
- Generalist concentration is not permission. v1.4 keeps generalists unable to grant fabric direct authority and additionally requires signed specialist qualification evidence.
