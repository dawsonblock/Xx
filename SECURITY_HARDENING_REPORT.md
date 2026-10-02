# Security and Statistical Qualification Status

## Release status

**Unreleased; qualification incomplete.** Package metadata remains `1.3.5`. This repair closes the first-party Linux evaluator namespace mismatch and changes the canary schedule/statistical protocol. A release is not qualified until the explicit gates in [`RELEASE_QUALIFICATION_MANIFEST.md`](RELEASE_QUALIFICATION_MANIFEST.md) pass against one committed source snapshot. The machine-readable source and authority identities are in [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json), [`SOURCE_TREE_MANIFEST.json`](SOURCE_TREE_MANIFEST.json), and [`TCB_MANIFEST.json`](TCB_MANIFEST.json).

The pre-repair source and qualification artifacts are preserved under [`qualification/history/1.3.5-pre-repair/`](qualification/history/1.3.5-pre-repair/). They describe the frozen pre-repair snapshot only.

## Trusted evaluator process namespaces

The trusted evaluator now represents host-visible paths and sandbox-only paths with separate immutable path sets. The first-party reference adapter executes in the host namespace because it must start a nested candidate sandbox; every path in its request is a real host path. Operator-supplied evaluator bundles use paths mounted into the outer Bubblewrap or Seatbelt namespace. Construction fails closed if a required evaluator, candidate, dataset, config, split, or output path is missing. The reference adapter never receives `/evaluator`, `/scratch`, or other paths that exist only inside the outer Bubblewrap namespace.

The reference adapter remains trusted host code. Candidate code runs in its separate strict inner sandbox and receives only public inputs. It cannot access hidden labels through the adapter contract. The evaluator timeout cleanup records and kills the nested candidate process group. Linux Bubblewrap and macOS Seatbelt end-to-end qualification must still pass in hosted CI; local macOS checks do not establish Linux isolation.

## Canary order and inference

The active protocol is `MULTITASK_PROMOTION_PROTOCOL_V5`. Every canary task has exactly four paired incumbent/challenger runs. The scheduler canonicalizes tasks and assigns ABBA or BAAB order before any result is read. Replicate IDs are evidence labels only and cannot select order. Each task has two challenger-first and two incumbent-first pairs. The complete schedule is included in the signed transaction and checked again during recovery. Panels now require at least 40 independent task-family clusters; this floor was raised after power calibration showed weak sensitivity at 20 clusters.

Runs reduce to one median effect per task. Related tasks reduce to one median family effect. Independent task-family clusters, rather than seeds or repeated runs, are the units in the exact one-sided sign test. The protocol binds minimum task/family/stratum coverage, practical-effect and regression limits, panel identity, seed schedule, evaluator/data identities, and the fixed alpha allocation `alpha_i = family_alpha / 500`. Once observations begin, an interrupted panel is burned and its alpha allocation is not refunded.

The synthetic campaign models within-task and within-family correlation, heteroscedasticity, heavy-tailed noise, ties, shared paired environment effects, and order-sensitive first/second-run, time, load, cache, provider, and family effects. Sequence nuisance magnitudes are swept across `0.01`, `0.05`, `0.10`, and `0.25`. Synthetic calibration cannot prove that real task families are independent or representative. Real null, degraded, and planted-improvement panels remain required.

The V5 release-scale local campaign used 20,000 familywise null lineages and observed 910 false promotions (4.55%; 95% Wilson interval 4.27%–4.85%), below the configured family alpha of 5%. All 25 correlation cells and all 32 sequence-scenario/magnitude checks passed their calibration limits. The calibrated minimum panel was raised to 40 independent families because estimated power for a 0.02 effect was 4.36% at 20 families, 42.32% at 40, and 69.60% at 60. At 40 families, estimated power for a 0.03 effect was 88.46%. This remains synthetic evidence and does not establish real-task independence, real workload power, or generalization.

## Persistent state and promotion authority

Promotion recovery verifies HMAC-authenticated durable state, the signed canary reservation, policy identities, panel and protocol digests, statistical attempt and alpha records, journal content hashes, and trusted evaluation artifacts. It recomputes the gate before changing the incumbent. An incomplete canary burns its panel and abandons its pending challenger. Signed state records retired panel, task, sample-ID, public-input, and full-record identities.

The per-experiment writer lock prevents two local controllers from making conflicting state transitions. Once configured, an external state anchor is sticky and bound to its normalized authority and pinned TLS certificate. The client supports monotonic compare-and-swap; this repository does not deploy or independently administer the anchor service. A local service conformance test is not evidence of independently stored or rollback-resistant production state.

## Remaining security and deployment limits

- No independently administered anchor service or destructive whole-host snapshot rollback campaign has been run for this repair snapshot.
- Linux Bubblewrap hosted E2E and hosted macOS/Windows/linter/package runs must be recorded against the repair source digest.
- No frozen real-task qualification corpus or complete trusted-evaluator null/degraded/improvement campaign is available in this checkout.
- The CI lock pins the Python 3.12 security/statistical/packaging toolchain. It does not lock every optional AIDE research dependency or provider runtime.
- Host-held HMAC secrets are not hardware-backed or split across independent signing services. Same-account compromise can expose them.
- Task-family independence and representativeness remain operator assumptions; synthetic results do not establish real-world generalization.
- Statistical protocol changes require a new statistical epoch and fresh alpha budget. The recursive policy cannot alter the referee, evidence verifier, sandbox, protocol, or promotion code.

No release tag or unattended-promotion claim should be made while any required gate is `NOT_RUN` or `NOT_CONFIRMED`.
