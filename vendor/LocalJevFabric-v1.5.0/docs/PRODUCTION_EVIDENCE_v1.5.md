# v1.5 production evidence plane

v1.5 separates four evidence domains:

1. **Prediction evidence** — answer, score semantics, backend identity.
2. **Qualification evidence** — HMAC qualification plus an independent Ed25519 evaluator artifact.
3. **Supply-chain evidence** — Ed25519 signature over the exact AnyJev artifact-bundle digest.
4. **Operational evidence** — rollout stage, drift status, replay hashes, audit chain, telemetry and incident bundle.

None of these alone grants execution authority.

## Capability routing

The capability manifest is an optimization hint, not an authority source. Fabric may use benchmarked accuracy, P95 latency and abstract compute cost to order generalists. Unsupported question types are filtered. Missing capability data falls back to operator-configured order.

Do not populate expected accuracy from model self-reports. Populate it from a frozen benchmark representative of the deployment population.

## Cost-aware escalation

For calibrated backends, Fabric can treat `1-score` as an error estimate. For concentration-only backends, it uses benchmarked expected accuracy instead. Escalation occurs only when the expected reduction in decision error outweighs configured incremental cost/latency.

A valid lower-tier answer is retained provisionally. If the stronger backend fails, Fabric can return the retained answer rather than converting an optimization attempt into an outage.

## Independent qualification

The evaluator must use a key not available to the trainer/promotion process in a high-assurance deployment. The held-out case set should be immutable and its digest is included in the signed artifact.

The evaluator artifact binds:

- exact task signature
- task id
- evaluation-set digest
- live specialist model
- live artifact bundle digest
- live backend fingerprint
- live calibration evidence digest
- qualification policy and metrics
- evaluator key id

## Artifact supply chain

The artifact signer attests the exact SHA-256 artifact-bundle identity served by AnyJev. Direct binding verifies the signature against a trusted public key and compares the attested digest to the live server manifest.

Private signing keys are intentionally not stored in this archive.

## Replay and incidents

The replay store keeps question definitions, decisions, answer metadata and evidence hashes. It never stores raw `state`. Instead it stores `state_sha256` so an operator can later supply the original state and verify that it matches the historical request.

`jev-fabric-replay incident` creates a ZIP containing the replay record, verification result and optional registry/manifest evidence. Treat incident bundles as sensitive metadata even though raw state is excluded.

## Telemetry

`FABRIC_TELEMETRY_JSONL` records OTel-style request spans. It contains hashes, durations, backend names, question count, direct-authority outcome and escalation count. It does not contain prompt/state content.

A production deployment can tail/transform this JSONL into OTLP or replace `TelemetrySink` with an organization's collector adapter without changing decision semantics.
