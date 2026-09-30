# Migration: v1.4 -> v1.5

v1.5 deliberately tightens direct authority. Non-authoritative v1.4 routes continue to load, but a **v1.4 direct-authorized route is rejected** until it is rebound with the new independent-evaluator and artifact-supply-chain evidence.

## Registry

Registry schema is now version 5. The two new authority fields are:

- `independent_qualification_digest`
- `artifact_attestation_digest`

They are required only when `direct_authorized=true`.

## Direct-authority migration

1. Keep the specialist stable and fail closed.
2. Generate an Ed25519 artifact signer key pair outside the repository.
3. Sign the exact live `artifact_bundle_sha256` with `jev-fabric-artifact sign-digest --kind anyjev-artifact-bundle`.
4. Generate a separate Ed25519 evaluator key pair.
5. Run `jev-fabric-independent-qualify` on a frozen held-out set that was not used for training or threshold selection.
6. Re-run `jev-fabric-bind-specialist --direct-authorized` with the existing HMAC qualification plus the new artifact attestation/evaluator qualification and their public keys.
7. Re-sign the registry and advance the registry checkpoint.
8. Upgrade jev-gateway with this source tree. Gateway direct execution now requires authority envelope v4.

A v1.4 authority envelope is intentionally downgraded by the new gateway.

## New optional controls

`FABRIC_CAPABILITY_MANIFEST` enables capability-aware generalist ordering. The manifest is not authoritative and cannot grant execution rights.

`FABRIC_REPLAY_STORE` enables sanitized replay evidence. Only a hash of request state is retained.

`FABRIC_TELEMETRY_JSONL` enables privacy-minimized OpenTelemetry-style spans.

## Rollback

If v1.5 must be rolled back, do not roll the registry revision backward. Restore the prior route set as a new higher revision using the existing monotonic rollback workflow. v1.4 gateways will not understand v1.5's stronger authority envelope and therefore should not be used to preserve direct-authority behavior.
