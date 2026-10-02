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

The committed code snapshot is `ca80a2b13a052e67053d2aeed37ffccf02722545`, with source-manifest SHA-256 `21916d5d99dd9716c7f1f094f13e8a84ecc71bccf2f64e7f90ffd4d61abc61f1`. The V5 statistical campaign was regenerated from this commit in the hash-locked Python 3.12 environment; its complete statistical implementation source-file manifest matches the current V5 implementation. The root freeze reports `COMMITTED_SOURCE_SNAPSHOT`. All six hosted workflows passed on workflow head `2feae7327076c7a2705730dc14fba12135a91403` and bind the same source-manifest digest. Earlier runs on a superseded digest are preserved as [`hosted-workflow-runs-superseded-510406.json`](qualification/repair-1.3.6/hosted-workflow-runs-superseded-510406.json) and are not used as qualification evidence.

## Repair scope

The current change set separates host paths from outer-sandbox paths in `TrustedEvaluator`, adds first-party reference-evaluator E2E coverage to mandatory hosted Linux and macOS workflows, canonicalizes Python runtime paths for Seatbelt, and replaces caller-ID parity ordering with a signed, canonical four-run ABBA/BAAB schedule. Protocol V5 raises the minimum panel to 40 independent task-family clusters after power calibration found weak sensitivity at 20. A universal hash-locked Python 3.12 CI dependency set is installed with `--require-hashes` in the relevant workflows.

## Qualification gates

| Gate | Required evidence | Current state |
|---|---|---|
| Local focused multi-task/statistics/anchor tests | Native arm64 Python 3.12 lock environment | PASS: 42 tests |
| Full local suite | [`qualification/repair-1.3.6/pytest-junit.xml`](qualification/repair-1.3.6/pytest-junit.xml) | PASS: 225 passed, 1 skipped |
| Linux Bubblewrap first-party E2E | [Hosted run 36992613936](https://github.com/dawsonblock/Xx/actions/runs/36992613936) | PASS on qualification head `2feae73`; evaluator, candidate isolation, and manifest checks passed |
| macOS Seatbelt first-party E2E | [Hosted run 36992613548](https://github.com/dawsonblock/Xx/actions/runs/36992613548) | PASS on qualification head `2feae73` |
| macOS nested candidate timeout cleanup | [Hosted run 36992613511](https://github.com/dawsonblock/Xx/actions/runs/36992613511) | PASS on qualification head `2feae73` |
| Windows state lock, anchor, and statistics tests | [Hosted run 36992614515](https://github.com/dawsonblock/Xx/actions/runs/36992614515) | PASS on qualification head `2feae73` |
| Linter and generated-manifest check | [Hosted run 36992602943](https://github.com/dawsonblock/Xx/actions/runs/36992602943) | PASS on qualification head `2feae73` |
| Package completeness | [Hosted run 36992603013](https://github.com/dawsonblock/Xx/actions/runs/36992603013) | PASS on qualification head `2feae73`; wheel/sdist build and clean install passed |
| Null, nuisance-order, power, and synthetic lineage campaign | [`qualification/repair-1.3.6/multitask-statistical-qualification.json`](qualification/repair-1.3.6/multitask-statistical-qualification.json) | PASS: 20,000 familywise lineages, 25 correlation cells, 32 sequence-bias checks, 500 synthetic attempts; 4.55% null familywise rate (95% Wilson 4.27%–4.85%) |
| Frozen real-task null/degraded/improvement controls | Complete trusted evaluation and promotion path | NOT_RUN; no qualification corpus is present |
| External monotonic anchor rollback campaign | Separately administered service and destructive host rollback | NOT_RUN; no external service is deployed |

The clean hash-lock install passed in a fresh native arm64 macOS Python 3.12.0 environment with 67 distributions; Linux, macOS, and Windows hosted workflows also installed the lock successfully. See [`dependency-lock-install.json`](qualification/repair-1.3.6/dependency-lock-install.json) for the local inventory. The lock covers the security/statistical CI and packaging toolchain, not every optional AIDE research dependency.

The exact run IDs, final workflow head, and bound source snapshot are recorded in [`hosted-workflow-runs.json`](qualification/repair-1.3.6/hosted-workflow-runs.json) and included in `RELEASE_FREEZE_MANIFEST.json`. These hosted passes close the platform CI gates; they do not close the independent-anchor or real-task qualification gates below.

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
