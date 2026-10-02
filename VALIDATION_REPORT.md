# Validation Report — RSI authority and statistical repair

## Release state

**UNRELEASED_QUALIFICATION_INCOMPLETE.** Package metadata remains `1.3.5`; this report does not authorize a release tag or unattended promotion. The repair source is on `repair/1.3.6-authority-statistics`. The qualified statistical/evaluator code snapshot is `3bebc16fc075e3d4441fd82eb3151b240161c897` before release-record updates. Its statistical artifact, test report, dependency install attestation, and complete source/TCB manifests are stored under [`qualification/repair-1.3.6/`](qualification/repair-1.3.6/) and at the repository root.

The pre-repair source, reports, manifests, dependency files, JUnit output, and statistical/hosted evidence remain preserved under [`qualification/history/1.3.5-pre-repair/`](qualification/history/1.3.5-pre-repair/). Their results do not qualify this repair.

## Local validation

Run on native arm64 macOS with a fresh Python 3.12.0 virtual environment installed using the hash-locked CI requirements:

- Full project suite: **225 passed, 1 skipped**. JUnit: [`pytest-junit.xml`](qualification/repair-1.3.6/pytest-junit.xml).
- Focused multi-task canary, alpha-budget, anchor, and calibration-tool suite: **42 passed**.
- Ruff: passed on the exact Python file set used by the repository lint workflow.
- Black: passed on the exact Python file set used by the repository lint workflow.
- `compileall` and `git diff --check`: passed.
- `pip install --require-hashes -r requirements-rsi-ci.lock`: passed in a fresh arm64 Python 3.12.0 environment; 67 installed distributions. Lock SHA-256 and inventory are in [`dependency-lock-install.json`](qualification/repair-1.3.6/dependency-lock-install.json).

The lock qualification is local to this macOS arm64 environment. Hosted Linux, Windows, and macOS CI results are not represented as passed here.

## Protocol V5 synthetic statistical calibration

[`multitask-statistical-qualification.json`](qualification/repair-1.3.6/multitask-statistical-qualification.json) was generated from the V5 source commit with 20,000 familywise lineages, a 500-attempt horizon, 5,000 power replicates per cell, an 80-task panel with 40 independent families, four paired runs per task, and 500 synthetic lineage attempts.

- Familywise null simulation: **910/20,000** lineages promoted (**4.55%**); 95% Wilson interval **4.27%–4.85%**, below the 5% family alpha.
- Correlation grid: **25/25** seed-correlation × within-family-correlation cells passed the predeclared calibration check. Highest observed null rate was **0.030%**; highest 95% Wilson upper bound was **0.065%**.
- Sequence effects: all **8** nuisance scenarios passed across 4 magnitudes each (32 scenario/magnitude checks). Highest observed false-promotion rate was **0.010%**; highest 95% Wilson upper bound was **0.020%**.
- Power at a 0.02 effect for 20/30/40/50/60 families was **4.36% / 16.22% / 42.32% / 52.22% / 69.60%**. Power at a 0.03 effect was **19.94% / 56.04% / 88.46% / 92.40% / 95.52%**.
- V5 therefore requires at least 40 independent families. Twenty- and thirty-family curves remain in the artifact as below-minimum comparisons. Power at the new minimum remains modest for a 0.02 effect; larger panels are recommended for subtle improvements.
- Synthetic lineage stress reserved and retired 500 unique panels; it recorded 45 post-reservation crashes, 346 rejected attempts, 79 promotions, zero null promotions, and zero remaining alpha. This is an in-memory simulation; it does not qualify `RSIStateStore`, external anchoring, or real crash recovery.

These simulations establish behavior under their modeled family/sign assumptions only. They do not establish that real task families are independent or representative, and they do not demonstrate AIDE improvement.

## Implemented repair scope

- TrustedEvaluator now separates real host paths from paths available only inside Bubblewrap. The first-party reference adapter receives host paths so it can launch its separately sandboxed candidate; required paths and artifacts fail closed.
- Linux and macOS workflows include first-party trusted-evaluator end-to-end tests; Windows includes canary schedule invariants. Hosted results must still be observed for this pushed source.
- Canary order is derived from canonical task order and ordinal, independent of caller replicate IDs. Each task receives a precommitted ABBA or BAAB schedule with exact within-task balance; the complete schedule is signed and rechecked during recovery.
- Statistical inference aggregates runs to a task effect and tasks to a declared independent-family effect before the exact sign test. Legacy single-task series fields are labeled and excluded from V5 panel authority.
- The repair lock, source/TCB inventory, historical baseline, and release manifests are content addressed.

## Gates still not run

- GitHub-hosted Linux Bubblewrap first-party evaluator E2E, macOS Seatbelt/nested timeout, Windows, linter, and package-completeness workflows on the final pushed source snapshot.
- Frozen real-task null, degraded, and planted-improvement controls through the complete trusted evaluator and promotion path. No real-task qualification corpus is available in this checkout.
- Independently administered external anchor deployment and destructive whole-directory rollback qualification. The local anchor client/service tests are not an independent monotonic authority.
- A real multi-generation AIDE-RSI improvement run.

Until these gates pass on matching source identities, release qualification and unattended promotion remain incomplete. See [`RELEASE_QUALIFICATION_MANIFEST.md`](RELEASE_QUALIFICATION_MANIFEST.md), [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json), and [`TCB_MANIFEST.json`](TCB_MANIFEST.json) for machine-readable status.
