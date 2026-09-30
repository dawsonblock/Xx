# Changelog

## 1.5.0 — 2026-09-29

- Added capability-aware generalist routing from an external, non-authoritative capability manifest.
- Added cost-aware escalation that distinguishes calibrated probability from raw concentration and retains a provisional cheaper answer if escalation fails.
- Added Ed25519 artifact-bundle attestations (`jev-fabric-artifact`).
- Added independent held-out qualification signed by a separate evaluator key (`jev-fabric-independent-qualify`).
- Registry schema v5/direct authority now requires independent qualification and signed artifact provenance in addition to v1.4 evidence.
- Gateway authority envelope requirement raised to v4 and now validates both new evidence bindings.
- Added privacy-minimized replay records, replay verification and portable incident bundles (`jev-fabric-replay`).
- Added OpenTelemetry-style JSONL request spans with hashes/latency/backend/escalation metadata and no prompt/state content.
- Added v1.4→v1.5 migration and production-evidence documentation.

## 1.4.0 — 2026-09-28

Evidence-driven rollout and qualification release.

- Upgraded task registry schema to v4 with stable/shadow/canary deployment stages.
- Added deterministic canary assignment and non-interfering shadow execution.
- Shadow/canary bindings cannot carry direct authority.
- Added `jev-fabric-rollout` for staged deployment, labeled canary evaluation and monotonic rollback.
- Added observable-behavior drift profiles and runtime drift gating using score deviation + Jensen-Shannon divergence.
- Degraded drift denies direct authority; severe drift disables fail-closed specialist use.
- Added privacy-minimized shadow journal and outcome-label endpoint/store.
- Added immutable decision dataset snapshots with deterministic train/validation/qualification/audit-holdout splits.
- Added `jev-fabric-benchmark` with accuracy, false-direct, backend-use and latency metrics.
- Changed CLI promotion default to shadow mode; stable/direct deployment is now a later explicit transition.
- Added v1.3→v1.4 migration, rollout/drift, and benchmark/dataset documentation.

## 1.3.0 — 2026-09-28

Controlled-specialization and qualification-authority release.

- Added an opt-in, state-free promotion journal for repeated **unregistered** exact tasks.
- Added candidate mining that groups only exact task signatures and treats frequency as nomination, not correctness.
- Added HMAC-authenticated held-out qualification artifacts with sample count, accuracy, ECE, Brier score and Wilson error-bound gates.
- Qualification artifacts are bound to the exact question, live AnyJev artifact bundle, backend fingerprint, calibration evidence and evaluation-set digest.
- Added explicit `jev-fabric-promotion promote` with live re-attestation, operating-threshold enforcement, registry snapshots and an explicit `--approve` mutation gate.
- Added monotonic rollback: historical routes are restored as a new higher registry revision rather than rolling revision numbers backward.
- Upgraded task registry schema to v3. v2 direct-authorized routes without qualification evidence are rejected and must be requalified.
- Upgraded fabric/gateway direct authority envelope to v3; gateway direct execution requires a bound qualification digest and promotion identity.
- Generic `jev-fabric-register` can no longer create direct authority.
- `jev-fabric-bind-specialist --direct-authorized` now requires a signed qualification artifact.
- Added promotion and v1.2→v1.3 migration documentation.

## 1.2.0 — 2026-09-28

Calibration-attestation, rollback-resistance and replay-evidence release.

- Added live AnyJev `--calibration-report` SHA-256 attestation and live calibrated-score semantics.
- Direct authority now verifies calibration evidence in addition to artifact and backend fingerprint, and requires an explicit task-specific `min_score` threshold.
- Added HMAC-sealed registry checkpoints, same-revision equivocation detection and `FABRIC_REGISTRY_MIN_REVISION`.
- Changed registry/signing helpers to atomic fsync + rename writes.
- Added optional HMAC-sealed audit head checkpoints with tail-truncation detection.
- Added request, route-plan and authority-evidence SHA-256 identities to fabric v2 metadata.
- jev-gateway now validates the complete v2 authority envelope instead of trusting a boolean.
- Circuit breakers use a single half-open recovery probe after cooldown.
- Added `jev-fabric-doctor` deployment preflight.
- Expanded integrated tests and direct-authority end-to-end coverage.

## 1.1.0 — 2026-09-28

Authority-integrity and reliability release.

- Upgraded task registry to v2 with deterministic SHA-256 integrity metadata and optional HMAC-SHA256 authentication.
- Added exact task binding fields for backend model, specialist artifact, backend fingerprint, calibration evidence, validity window and minimum score.
- Added per-task `generalist` vs `fail_closed` fallback policy.
- Registered tasks with inactive/expired bindings now fail closed instead of silently becoming generalist work.
- Direct-authorized task bindings require fail-closed policy plus artifact, backend-fingerprint and calibration evidence.
- AnyJev server now exposes a live specialist attestation manifest.
- Fabric verifies running AnyJev artifact/fingerprint against the authenticated route binding before emitting direct authority.
- Direct authority also requires a calibrated backend declaration and authenticated registry integrity.
- Added strict backend answer/schema validation.
- Added concurrent cross-backend evaluation, backend bulkheads and circuit breakers.
- Added per-decision provenance metadata and richer health/manifest endpoints.
- Added tamper-evident hash-chained audit logging and verification CLI.
- Added `jev-fabric-bind-specialist` to bind a running attested AnyJev server without manual artifact-hash copying.
- jev-gateway now preserves fabric authority metadata and requires it for direct calls by default.
- Added gateway authority/registry response headers and configuration range validation.

## 1.0.0 — 2026-09-28

- Integrated AnyJev, LLM2Jev, and jev-gateway behind LocalJevFabric.
- Removed unsafe implicit AnyJev L2 semantic reuse.
- Added explicit aliases and artifact compatibility bindings.
- Added AnyJev SystemOne server and exact-task training workflow.
- Added federated exact routing, backend batching, failover, and connection pooling.
- Hardened LLM2Jev prompts, ordering, CI, and network auth defaults.
- Added gateway local Jev support, state-budget correction, network auth enforcement, and R0-R3 tool-risk policy.
