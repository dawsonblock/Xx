# Validation report — RSI authority and statistical repair

## Release state

**UNRELEASED_QUALIFICATION_INCOMPLETE.** Package metadata remains `1.3.5`. The code-qualified source is commit `f4fe8b4a543fdf60a0b8f008e1ba6a3f5e5f3c60`, Git tree `4b3382db21c06f546db38b68c18306325b8afa7c`, source snapshot SHA-256 `e89492654bc9c9ebe04b2f221c0800d4feccffbc7bad78fb561e4842936f9bf4`. Protocol V6 is `MULTITASK_PROMOTION_PROTOCOL_V6` with digest `9f7ca2438516b911e6a3625de43b8612e8b7cfe0e717a67ec4b0b276bcdfc861`.

Pre-repair and superseded V5 evidence is preserved under `qualification/history/`; it is not used to qualify this source. Current manifests and V6 qualification artifacts are in [`qualification/repair-1.3.6/`](qualification/repair-1.3.6/) and at the repository root.

## Local validation

All checks below were run locally against the code-qualified source in a fresh Python 3.12.0 environment installed from the hash-locked CI toolchain:

- Full project suite: **229 passed, 1 skipped**. JUnit: [`pytest-junit.xml`](qualification/repair-1.3.6/pytest-junit.xml).
- Targeted sample-identity, canary, and recovery tests: **23 passed**.
- Ruff and Black passed on the exact file sets used by the repository workflow.
- `compileall` passed.
- `pip install --require-hashes -r requirements-rsi-ci.lock` passed; 67 distributions. The lock digest and installed inventory are in [`dependency-lock-install.json`](qualification/repair-1.3.6/dependency-lock-install.json).
- Wheel and source distribution built; `tools/verify_package.py` confirmed required runtime components. A clean wheel smoke passed. This qualification used the CI lock and did not install the full optional AIDE research/provider dependency set.

The one local skip is environment/integration dependent. Fresh hosted Linux Bubblewrap, macOS Seatbelt, nested-timeout, Windows state-lock, lint, and package workflows all passed on workflow head `60c594feb2f5636080c41b999c9d7fbd71399f9b`, which preserves the same qualified source snapshot digest. Exact run links are listed in [`RELEASE_QUALIFICATION_MANIFEST.md`](RELEASE_QUALIFICATION_MANIFEST.md).

## Protocol V6 synthetic calibration

[`multitask-statistical-qualification.json`](qualification/repair-1.3.6/multitask-statistical-qualification.json) was generated from the V6 code using 20,000 familywise null lineages, a 500-attempt horizon, 5,000 power replicates per cell, 80 tasks in 40 declared family clusters, four paired runs per task, and 500 synthetic lineage attempts.

- Familywise null: **910/20,000** promotions (**4.55%**); 95% Wilson interval **4.2698%–4.8477%**, below the 5% family-alpha boundary in the modeled campaign.
- Correlation grid: **25/25** seed-correlation × family-correlation cells passed the calibration criterion.
- Sequence nuisance: **32/32** scenario/magnitude cells passed; maximum observed false-promotion rate **0.020%**, maximum 95% Wilson upper bound **0.0514%**.
- Power at effect `0.02` for 20/30/40/50/60 families: **4.36% / 16.22% / 42.32% / 52.22% / 69.60%**. At effect `0.03`: **19.94% / 56.04% / 88.46% / 92.40% / 95.52%**.
- The minimum production panel remains 40 independent family clusters. Power for small effects is limited; larger panels are needed for subtle improvements.
- The synthetic in-memory lineage campaign used 500 unique panels across 500 attempts, with 45 simulated crashes, 30 failed panels, 346 rejections, 79 promotions, and the full 0.05 alpha budget spent. It does not exercise durable state recovery or an external anchor.

Synthetic calibration does not establish that real task-family clusters satisfy the independence assumptions, that the corpus is representative, or that AIDE improves.

## Implemented repair scope

- TrustedEvaluator keeps host-visible paths separate from outer-sandbox-only paths. The first-party reference adapter gets real host paths to launch the nested candidate sandbox; required paths/artifacts fail closed.
- Linux Bubblewrap and macOS Seatbelt hosted workflows include first-party trusted-evaluator E2E coverage; a macOS workflow tests nested candidate timeout cleanup. Fresh runs against this source are pending.
- Canary order is derived from canonical task position and replicate ordinal, never caller-selected replicate ID. Each task receives a precommitted, exactly balanced four-run ABBA or BAAB order included in the signed transaction and rechecked during recovery.
- Runs aggregate to task effects, tasks aggregate to declared task-family effects, and family clusters are the independent units for V6 inference.
- The sample-identity repair preserves the association `sample_id → public_input_sha256 → full_record_sha256` from reference evaluation through canonical panel construction, signed transaction, authenticated durable reservation, and recovery validation.

## Qualification still required

- Fresh Linux, macOS, Windows, lint, and package hosted runs bound to this source snapshot.
- Frozen real-task null, degraded, and planted-improvement controls through the complete trusted evaluator and promotion path.
- Independently administered external anchor deployment and destructive whole-directory/host rollback qualification.
- A complete dependency lock for optional AIDE research/provider runtimes.
- A real multi-generation AIDE-RSI experiment testing whether the improvement process itself improves under matched budgets and untouched meta-evaluation.

Until these gates pass against one committed source identity, this report does not support a release-qualified or recursive-self-improvement claim. See [`RELEASE_QUALIFICATION_MANIFEST.md`](RELEASE_QUALIFICATION_MANIFEST.md) and [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json).
