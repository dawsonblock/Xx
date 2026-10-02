# Security and statistical qualification status

## Release status

**Unreleased; qualification incomplete.** Package metadata remains `1.3.5`. The code-qualified source is commit `f4fe8b4a543fdf60a0b8f008e1ba6a3f5e5f3c60`, source snapshot SHA-256 `e89492654bc9c9ebe04b2f221c0800d4feccffbc7bad78fb561e4842936f9bf4`. Current authority and source identities are recorded in [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json), [`SOURCE_TREE_MANIFEST.json`](SOURCE_TREE_MANIFEST.json), and [`TCB_MANIFEST.json`](TCB_MANIFEST.json). Pre-repair and V5 evidence are retained under `qualification/history/` and do not qualify this source.

## Trusted evaluator process namespaces

TrustedEvaluator represents host-visible paths and sandbox-only paths separately. The first-party reference adapter runs in the host namespace because it starts a nested candidate sandbox; its request contains real host paths. Operator-supplied evaluator bundles use paths mounted in the outer Bubblewrap or Seatbelt namespace. Missing evaluator, candidate, dataset, configuration, split, or output artifacts fail closed. The reference adapter is trusted host code; candidate code runs in its own strict sandbox, receives only candidate-visible inputs, and does not receive hidden labels through the adapter contract.

The outer timeout cleanup records and kills the nested candidate process group. The repository's fresh hosted Linux Bubblewrap, native macOS Seatbelt, and nested-timeout E2E workflows passed on workflow head `60c594feb2f5636080c41b999c9d7fbd71399f9b` with the current source snapshot digest. The Windows authority-path, linter, and package workflows also passed. Exact run identities are in [`qualification/repair-1.3.6/hosted-workflow-runs.json`](qualification/repair-1.3.6/hosted-workflow-runs.json).

## Canary schedule and inference protocol

The active protocol is `MULTITASK_PROMOTION_PROTOCOL_V6` (`9f7ca2438516b911e6a3625de43b8612e8b7cfe0e717a67ec4b0b276bcdfc861`). Each task has four paired incumbent/challenger runs. Tasks are canonicalized and assigned ABBA or BAAB order before any result is observed; caller replicate IDs do not control order. The complete schedule is included in the signed transaction and checked during recovery.

Each run set reduces to one task effect; related tasks reduce to one predeclared family effect. Family clusters, not seeds or runs, are the independent units for the exact one-sided sign test. A panel needs at least 40 declared independent family clusters, minimum task and stratum coverage, practical-effect and regression constraints. The protocol fixes the 500-attempt horizon and allocation:

```text
alpha_i = family_alpha / 500
```

At family alpha 0.05, each attempt receives 0.0001. Once authoritative observations begin, an interrupted panel is burned and its allocation is not refunded. Protocol V6 binds the canonical per-sample row associations `sample_id → public_input_sha256 → full_record_sha256` through evaluator results, panel serialization, signed transaction, authenticated reservation state, and recovery. Altered, detached, or inconsistent records fail validation.

## Synthetic statistical evidence

The V6 synthetic qualification artifact uses 20,000 familywise null lineages, a fixed 500-attempt horizon, 5,000 power replicates per cell, 80 tasks across 40 declared family clusters, four paired runs per task, and 500 in-memory lineage attempts.

- Familywise null: 910/20,000 promotions (4.55%); 95% Wilson interval 4.2698%–4.8477%.
- Correlation checks: 25/25 tested seed/family-correlation cells passed.
- Sequence nuisance: 32/32 scenario/magnitude combinations passed; maximum observed rate 0.020%, maximum 95% Wilson upper bound 0.0514%.
- Power at a 0.02 effect for 20/30/40/50/60 families: 4.36% / 16.22% / 42.32% / 52.22% / 69.60%; at 0.03: 19.94% / 56.04% / 88.46% / 92.40% / 95.52%.
- The 500-attempt synthetic lineage campaign recorded 45 crashes, 30 failed panels, 346 rejections, 79 promotions, and spent the full alpha budget. It is an in-memory simulator; it is not state-store or remote-anchor crash qualification.

These results validate only the specified synthetic models. They do not demonstrate real family independence, representativeness, real-task power, or AIDE improvement. The 40-family minimum has weak power for modest effects.

## Persistent state and promotion authority

Promotion recovery verifies authenticated durable state, signed canary reservation, policy identities, panel/protocol identity, alpha allocation, journal hashes, and trusted evaluation artifacts. It recomputes the gate before changing the incumbent. An incomplete canary burns its panel and allocated alpha. Signed state records consumed panel, task, sample-ID, public-input, full-record, and row-identity digests.

A local writer lock prevents concurrent local controllers from making conflicting state transitions. Configured external anchoring is sticky and bound to its authority identity and pinned TLS certificate; the client implements monotonic compare-and-swap. The project does not deploy or independently administer an anchor service. Local anchor tests do not establish rollback-resistant deployment.

## Remaining limits

- Hosted Linux/macOS/Windows, lint, and package runs passed for this source snapshot; see the release qualification record.
- No frozen real-task null/degraded/improvement corpus has been run through the complete trusted promotion path.
- No independently administered external anchor or destructive whole-host rollback campaign has been run.
- The Python 3.12 lock covers security/statistical CI and package qualification, not all optional research/provider dependencies.
- Host-held HMAC secrets are not hardware-backed or split among independent signing services; compromise of the trusted account can expose signing authority.
- Family independence and representativeness remain assumptions requiring externally reviewable task provenance.
- A real multi-generation experiment has not established that the policy-improvement process improves itself.

No release tag or unattended-promotion claim is supported while required gates remain pending or unrun. See [`RELEASE_QUALIFICATION_MANIFEST.md`](RELEASE_QUALIFICATION_MANIFEST.md) for the authoritative gate list.
