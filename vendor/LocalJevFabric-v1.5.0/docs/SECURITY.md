# Security model

## Non-loopback exposure

The fabric, AnyJev SystemOne server, LLM2Jev HTTP servers, and jev-gateway all default to loopback. Hardened entry points reject unauthenticated non-loopback binds unless an explicit insecure override is supplied. Do not use that override on a machine reachable by untrusted clients.

## Prompt injection

LLM2Jev instructs the model that both state and candidate/tool descriptions are untrusted data, not instructions. This lowers one injection path but does not make arbitrary third-party tool metadata trustworthy. Tool schemas should still come from an allowlisted registry where possible.

## AnyJev head confusion

Implicit head reuse based only on question kind/options is disabled. This specifically closes the `noul` failure mode where every unrelated yes/no task has the same `Yes/No` option set.

Paraphrases require explicit alias registration and should be authorized only after held-out evaluation demonstrates that the existing head remains valid under the alternate wording.

## Artifact and calibration binding

Legacy AnyJev artifacts without a compatibility binding are refused by default. The compatibility fingerprint is not a cryptographic digest of all weight bytes; pin immutable revisions and retain external weight checksums for high-assurance deployments.

For direct authority, the running AnyJev specialist must also attest the exact held-out calibration/evaluation report hash via `--calibration-report`. The live report digest, artifact digest and backend fingerprint must all match the HMAC-authenticated registry binding. Direct-authorized routes also require an explicit task-specific `min_score` operating threshold.

## Registry rollback

Registry HMAC authentication detects unauthorized content edits but does not by itself prevent replacement with an older, still-valid signed registry. v1.2+ adds an optional HMAC-sealed revision checkpoint and `FABRIC_REGISTRY_MIN_REVISION`.

A local checkpoint prevents ordinary stale/single-file rollback and same-revision equivocation. A complete machine/filesystem snapshot rollback can restore both old registry and old checkpoint, so high-assurance deployments should also pin the minimum revision in external deployment state or a separate monotonic store.

## Audit durability

The JSONL audit chain detects in-chain modification and reordering. With `FABRIC_AUDIT_CHECKPOINT` + `FABRIC_AUDIT_HMAC_KEY`, the latest record count/hash is sealed and end-of-log truncation is detected relative to that head. This still does not survive rollback/deletion of the entire log + checkpoint storage snapshot without an external anchor.

## Adaptation

AnyJev's label-free adaptation remains useful but runtime traffic can influence its statistics. Treat adaptation state as mutable model state. For high-assurance tasks, use controlled traffic, monitor drift, preserve prior snapshots, and require evaluation before promoting large distribution changes.

## Confidence vs authorization

Never map `confidence >= X` directly to permission for a side effect. Numerical confidence is evidence about a model decision. Authorization is policy. The gateway's R0-R3 gate enforces this separation for supported routing modes.

The gateway now validates the complete LocalJevFabric v3 authority envelope. A naked `direct_authorized=true` is insufficient; authenticated registry state, valid SHA-256 evidence fields and calibrated per-question live attestations plus qualification provenance are required.

## Recommended production defaults

- Loopback-only services behind an authenticated local control plane.
- Immutable model revisions.
- Exact task registry under version control; require HMAC verification for authority-bearing deployments.
- Enable registry checkpointing and pin a deployment minimum revision.
- `AnyJev require_level=L2` plus `--calibration-report` for direct-authority specialist endpoints.
- Unknown tool risk at least `R1`; use `R2` or `R3` for stricter environments.
- Direct calls only for explicit R0 tools **and** a complete authenticated fabric v3 authority envelope.
- No legacy AnyJev artifacts after migration.
- Enable the audit log; for truncation detection also enable the HMAC-sealed audit checkpoint.
- Run `jev-fabric-doctor` before promotion/restart after authority-bearing changes.


## Promotion boundary

`FABRIC_PROMOTION_JOURNAL` is non-authoritative and excludes request state. Treat it as candidate telemetry, not evidence. `FABRIC_PROMOTION_HMAC_KEY` authenticates held-out qualification artifacts and should be separated from `FABRIC_REGISTRY_HMAC_KEY`. v1.5 direct authority requires qualification provenance, independent evaluator evidence, signed artifact provenance, stable rollout and normal drift; generic registry editing cannot grant it.


## Shadow/canary isolation

Experimental candidates are not an authority source. Shadow answers cannot replace production answers. Canary routes cannot be direct-authorized. A selected canary may fall back to its known baseline, while baseline traffic is never allowed to fall forward into an experimental candidate.

## Outcome poisoning boundary

Outcome records are non-authoritative training/evaluation inputs. Duplicate keys are idempotent and conflicting labels for the same request/question/signature are rejected. Dataset snapshots are new immutable directories with source and payload SHA-256 identities. Promotion still requires independent qualification; outcome telemetry alone cannot mutate authority.
