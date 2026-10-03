# Authority chain

LocalJevFabric v1.5 separates **prediction**, **qualification**, and **execution authority**. A specialist can be accurate without being authorized, and frequent traffic can nominate a candidate without changing authority.

## Direct-authority conditions

The fabric sets `fabric.direct_authorized=true` only when every answered question satisfies all of these:

1. Exact canonical SystemOne question signature is registered.
2. Binding is active, unexpired and `fail_closed`.
3. Binding explicitly enables direct authority and pins a `min_score`.
4. Registry was HMAC-authenticated and passes anti-rollback policy.
5. Binding contains expected specialist artifact, backend fingerprint and calibration evidence digests.
6. Binding contains an HMAC-qualified `qualification_digest` plus a `promotion_id`.
7. Configured backend declares calibrated score semantics.
8. Answer passes the greater of backend and task score floors.
9. Live AnyJev manifest matches the expected served model.
10. Live artifact bundle, backend fingerprint and calibration-evidence hashes match the binding.
11. Live specialist attests calibrated semantics and legacy artifacts are disabled.
12. Binding deployment stage is `stable`; shadow/canary routes are never authoritative.
13. Runtime drift state is `normal`; degraded/disabled drift removes direct authority.
14. The v3 authority envelope records `qualification_bound=true`.

The gateway then independently requires authority envelope v4 and limits direct execution to configured R0 tools. R1 can at most be forced through the upstream model, R2 remains advisory/passthrough, and R3 is never directly authorized by System One.

## Qualification authority

A v1.4 deployment still uses the v1 qualification artifact format is produced offline from independently labeled held-out results. It binds:

- exact question signature,
- task ID,
- live AnyJev artifact digest,
- live backend fingerprint,
- live calibration evidence digest,
- held-out evaluation-set digest,
- sample count, accuracy, ECE, Brier score, Wilson upper error bound,
- required operating threshold,
- pass/fail gates.

The artifact is HMAC-authenticated with `FABRIC_PROMOTION_HMAC_KEY`, which should be separate from the registry HMAC key. Candidate frequency, self-generated labels, raw confidence, or journal contents are not qualification evidence.

Generic `jev-fabric-register` cannot create direct authority. v1.4 promotion also refuses to grant direct authority; direct authority is a separate post-rollout transition. Direct authority must enter through a qualification-aware workflow.

## Replay evidence

Every authority-v3 fabric result can include `request_sha256`, `plan_sha256`, `evidence_sha256`, exact per-question routing/attestation metadata, and the qualification/promotion IDs carried by the authenticated registry binding. These are correlation identities; the registry HMAC and audit checkpoint provide authenticated integrity.

## Registry anti-rollback

Registry schema v4 retains HMAC integrity, revision checkpoints and `FABRIC_REGISTRY_MIN_REVISION`. Promotion snapshots are signed registry copies. A rollback restores historical routes as a **new revision**, so legitimate rollback never moves the authority counter backward.

## Audit evidence

The primary audit log remains SHA-256 hash chained and can use an HMAC-sealed tail checkpoint. The optional promotion journal is intentionally non-authoritative and stores no request state; it only helps find repeated unregistered exact tasks.

See `PROMOTION_PIPELINE.md` for the complete lifecycle.

## Rollout authority boundary

Registry v4 adds `deployment_stage`. `shadow` and `canary` are evidence-gathering states and cannot carry direct authority. A shadow candidate cannot control production output. Canary assignment is deterministic and a candidate failure may fall back to the baseline. Only a later explicit stable transition can become eligible for direct authority.

## Drift authority boundary

Observable-behavior drift is evaluated from score distribution and answer mix. `degraded` removes direct authority. `disabled` prevents fail-closed/direct specialists from being used at all, avoiding silent authority downgrade.


## v1.5 independent evidence

Direct authority now requires registry-bound SHA-256 identities for both an independently signed evaluator qualification and an Ed25519 artifact-bundle attestation. jev-gateway requires authority envelope v4 and validates the presence of both bindings for every answered question before allowing an R0 direct call.
