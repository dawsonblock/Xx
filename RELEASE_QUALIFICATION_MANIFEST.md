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

All manifests must be regenerated after the final source commit. The freeze must report that the hashed source matches its Git commit before hosted evidence can be attached.

## Repair scope

The current change set separates host paths from outer-sandbox paths in `TrustedEvaluator`, adds first-party reference-evaluator E2E coverage to mandatory hosted Linux and macOS workflows, canonicalizes Python runtime paths for Seatbelt, and replaces caller-ID parity ordering with a signed, canonical four-run ABBA/BAAB schedule. The task-clustered statistical protocol and calibration artifact use protocol V4. A universal hash-locked Python 3.12 CI dependency set is installed with `--require-hashes` in the relevant workflows.

## Qualification gates

| Gate | Required evidence | Current state |
|---|---|---|
| Local focused evaluator/statistics/recovery tests | Current repair JUnit artifact | See `qualification/repair-1.3.6/pytest-junit.xml` after local run |
| Full local suite | Current repair JUnit artifact | See `qualification/repair-1.3.6/pytest-junit.xml` after local run |
| Linux Bubblewrap first-party E2E | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| macOS Seatbelt and nested candidate cleanup | Hosted runs on repair source commit | NOT_RUN until hosted CI completes |
| Windows state and order-invariant tests | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| Linter and package completeness | Hosted run on repair source commit | NOT_RUN until hosted CI completes |
| Null, nuisance-order, power, and synthetic lineage campaign | Current protocol/source-matched artifact | See `qualification/repair-1.3.6/multitask-statistical-qualification.json` after run |
| Frozen real-task null/degraded/improvement controls | Complete trusted evaluation and promotion path | NOT_RUN; no qualification corpus is present |
| External monotonic anchor rollback campaign | Separately administered service and destructive host rollback | NOT_RUN; no external service is deployed |

The current clean lock install is qualified only on the local Python 3.12/macOS environment. The lock covers the security/statistical CI and packaging toolchain, not every optional AIDE research dependency. Hosted qualification is required to confirm the lock across supported CI platforms.

## Reproducible commands

```bash
python -m pip install --require-hashes -r requirements-rsi-ci.lock
python -m pytest -q --junitxml=qualification/repair-1.3.6/pytest-junit.xml
python -m compileall -q aide tests tools rsi_anchor_service.py
ruff check aide/ tools/ tests/
black --check aide/ tools/ tests/
python tools/qualify_canary_statistics.py \
  --campaigns 20000 --attempts 500 --power-replicates 5000 \
  --tasks 40 --task-families 20 --runs-per-task 4 \
  --lineage-attempts 500 \
  --output qualification/repair-1.3.6/multitask-statistical-qualification.json
python tools/generate_release_manifests.py
python tools/generate_release_manifests.py --check
```

The qualification artifact and manifests must identify the same committed code snapshot. Historical CI links, test counts, package digests, and statistics are retained under `qualification/history/1.3.5-pre-repair/` and do not qualify this repair.
