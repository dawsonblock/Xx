# Repair qualification record

## Status

**UNRELEASED_QUALIFICATION_INCOMPLETE.** Package metadata remains `1.3.5`. This record tracks the repair branch and does not authorize a release tag or unattended promotion.

## Source identity

The repair starts at qualified source commit `a2bdaedd0492b98e9ab0ee1726b14008766fc512`. The pre-repair evidence head `5665eee7957e32865b390c1c001616848d711446` and its tree `1843f1e5946af1b12b0e2b20eae36032e8f84518` are retained in the local tag `pre-repair-1.3.5-5665eee`. Baseline manifests and qualification outputs were copied byte-for-byte to [`qualification/history/1.3.5-pre-repair/`](qualification/history/1.3.5-pre-repair/) and checked against their recorded SHA-256 values.

The active machine-readable identities are:

- [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json): source, dependency, TCB, and qualification status.
- [`SOURCE_TREE_MANIFEST.json`](SOURCE_TREE_MANIFEST.json): full per-file source inventory and canonical digest.
- [`TCB_MANIFEST.json`](TCB_MANIFEST.json): security and authority code, tests, workflows, config, and build inputs.
- [`BUILD_MANIFEST.json`](BUILD_MANIFEST.json): package and qualification state.

The V5 code and statistical artifact identify code commit `3bebc16fc075e3d4441fd82eb3151b240161c897`. Regenerate all manifests after the release-record commit; the freeze must report that its hashed source matches its Git commit before hosted evidence can be attached.

## Repair scope

The current change set separates host paths from outer-sandbox paths in `TrustedEvaluator`, adds first-party reference-evaluator E2E coverage to mandatory hosted Linux and macOS workflows, canonicalizes Python runtime paths for Seatbelt, and replaces caller-ID parity ordering with a signed, canonical four-run ABBA/BAAB schedule. Protocol V5 raises the minimum panel to 40 independent task-family clusters after power calibration found weak sensitivity at 20. A universal hash-locked Python 3.12 CI dependency set is installed with `--require-hashes` in the relevant workflows.

## Qualification gates

| Gate | Required evidence | Current state |
|---|---|---|
| Local focused multi-task/statistics/anchor tests | Native arm64 Python 3.12 lock environment | PASS: 42 tests |
| Full local suite | [`qualification/repair-1.3.6/pytest-junit.xml`](qualification/repair-1.3.6/pytest-junit.xml) | PASS: 225 passed, 1 skipped |
| Local wheel and source-distribution packaging | Build, `tools/verify_package.py`, clean wheel CLI/vendor/anchor smoke | PASS locally; hosted package workflow remains NOT_RUN |
| Linux Bubblewrap first-party E2E | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| macOS Seatbelt and nested candidate cleanup | Hosted runs on repair source commit | NOT_RUN until hosted CI completes |
| Windows state and order-invariant tests | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| Linter and package completeness | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| Null, nuisance-order, power, and synthetic lineage campaign | [`qualification/repair-1.3.6/multitask-statistical-qualification.json`](qualification/repair-1.3.6/multitask-statistical-qualification.json) | PASS: 20,000 familywise lineages, 25 correlation cells, 32 sequence-bias checks, 500 synthetic attempts; 4.55% null familywise rate (95% Wilson 4.27%–4.85%) |
| Frozen real-task null/degraded/improvement controls | Complete trusted evaluation and promotion path | NOT_RUN; no qualification corpus is present |
| External monotonic anchor rollback campaign | Separately administered service and destructive host rollback | NOT_RUN; no external service is deployed |

The clean hash-lock install passed in a fresh native arm64 macOS Python 3.12.0 environment with 67 distributions; see [`dependency-lock-install.json`](qualification/repair-1.3.6/dependency-lock-install.json). This qualifies only that local platform. The lock covers the security/statistical CI and packaging toolchain, not every optional AIDE research dependency. Hosted qualification is required to confirm the lock across supported CI platforms.

## Reproducible commands

```bash
python -m pip install --require-hashes -r requirements-rsi-ci.lock
python -m pytest -q --junitxml=qualification/repair-1.3.6/pytest-junit.xml
python -m compileall -q aide tests tools rsi_anchor_service.py
ruff check aide/ tools/ tests/
black --check aide/ tools/ tests/
python tools/qualify_canary_statistics.py \
  --campaigns 20000 --attempts 500 --power-replicates 5000 \
  --tasks 80 --task-families 40 --runs-per-task 4 \
  --lineage-attempts 500 \
  --output qualification/repair-1.3.6/multitask-statistical-qualification.json
python tools/generate_release_manifests.py
python tools/generate_release_manifests.py --check
```

The qualification artifact and manifests must identify the same committed code snapshot. Historical CI links, test counts, package digests, and statistics are retained under `qualification/history/1.3.5-pre-repair/` and do not qualify this repair.
