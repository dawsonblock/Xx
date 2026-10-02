# Repair qualification record

## Release status

**UNRELEASED_QUALIFICATION_INCOMPLETE.** Package metadata remains `1.3.5`. This record does not authorize a release tag or unattended promotion. Qualification claims apply only to the exact source identity below; historical results are not carried forward as current evidence.

## Source identity

- Qualified source commit: `f4fe8b4a543fdf60a0b8f008e1ba6a3f5e5f3c60`
- Qualified Git tree: `4b3382db21c06f546db38b68c18306325b8afa7c`
- Source snapshot SHA-256: `e89492654bc9c9ebe04b2f221c0800d4feccffbc7bad78fb561e4842936f9bf4`
- Package version: `1.3.5` (unreleased repair branch)
- Current statistical protocol: `MULTITASK_PROMOTION_PROTOCOL_V6`
- Protocol SHA-256: `9f7ca2438516b911e6a3625de43b8612e8b7cfe0e717a67ec4b0b276bcdfc861`

The pre-repair source and its qualification evidence remain preserved under [`qualification/history/1.3.5-pre-repair/`](qualification/history/1.3.5-pre-repair/). The superseded V5 repair artifacts are preserved under [`qualification/history/repair-1.3.6-before-row-identity-v6/`](qualification/history/repair-1.3.6-before-row-identity-v6/). Neither set qualifies V6.

The current source and authority inventories are [`SOURCE_TREE_MANIFEST.json`](SOURCE_TREE_MANIFEST.json), [`TCB_MANIFEST.json`](TCB_MANIFEST.json), [`BUILD_MANIFEST.json`](BUILD_MANIFEST.json), and [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json). The latter intentionally keeps the release state incomplete.

## V6 repair scope

V6 preserves the prior Linux host-path / sandbox-path separation, first-party evaluator E2E coverage, deterministic four-run ABBA/BAAB ordering, family-level inference, and the fixed 500-attempt alpha allocation. It repairs sample identity binding end to end: each canonical record binds a sample ID to its public-input digest and full-record digest, and that record list is carried through reference evaluation, panel construction, signed transaction, authenticated reservation state, and recovery verification. Detached or altered row identities fail validation.

## Local qualification

| Gate | Evidence | Result |
|---|---|---|
| Full local test suite | [`pytest-junit.xml`](qualification/repair-1.3.6/pytest-junit.xml) | PASS: 229 passed, 1 skipped |
| Targeted canary/recovery/identity tests | local Python 3.12 hash-locked environment | PASS: 23 passed |
| Compile check | `python -m compileall -q aide tests tools rsi_anchor_service.py` | PASS |
| Ruff and Black | exact repository workflow file sets; locked versions | PASS |
| Hash-locked CI tool environment | [`dependency-lock-install.json`](qualification/repair-1.3.6/dependency-lock-install.json) | PASS: 67 distributions, Python 3.12.0, NumPy 1.26.2 |
| Wheel and source distribution | `tools/verify_package.py` and clean wheel smoke | PASS for required packaged RSI runtime components |
| Statistical null/power and in-memory lineage calibration | [`multitask-statistical-qualification.json`](qualification/repair-1.3.6/multitask-statistical-qualification.json) | PASS for the documented synthetic models only |

The dependency lock covers the Python 3.12 security/statistical CI and package-qualification toolchain. It does **not** lock every optional AIDE research/provider runtime dependency; it is not a complete production-runtime lock.

## Hosted qualification

Fresh hosted runs for source snapshot `e8949265…` are **PENDING**. Earlier green workflows were run against a superseded source digest and are retained only as historical evidence. The initial linter run on commit `f4fe8b4` failed because generated release manifests had not yet been committed; that run is not qualification evidence for this snapshot.

| Gate | Current state |
|---|---|
| Linux Bubblewrap first-party trusted-evaluator E2E | PENDING fresh run |
| macOS Seatbelt first-party trusted-evaluator E2E | PENDING fresh run |
| macOS nested candidate timeout cleanup | PENDING fresh run |
| Windows RSI state lock/statistics | PENDING fresh run |
| Linter and generated-manifest check | PENDING fresh run |
| Package completeness | PENDING fresh run |

The active hosted run record will be [`qualification/repair-1.3.6/hosted-workflow-runs.json`](qualification/repair-1.3.6/hosted-workflow-runs.json) and must bind every run to the same workflow head and source snapshot. Superseded results are named accordingly under `qualification/repair-1.3.6/`.

## Statistical calibration summary

The V6 synthetic artifact uses 20,000 familywise null lineages, a fixed 500-attempt horizon, 5,000 power replicates per cell, 80 tasks grouped into 40 declared family clusters, four paired runs per task, and 500 in-memory lineage attempts.

- Familywise null: 910/20,000 promotions (4.55%); 95% Wilson interval 4.2698%–4.8477%, below the configured 5% family alpha for the modeled scenarios.
- Correlation grid: 25/25 tested seed/family-correlation cells passed the artifact's calibration criterion.
- Sequence nuisance: 32/32 tested scenario/magnitude combinations passed; maximum observed rate 0.020% and maximum 95% Wilson upper bound 0.0514%.
- Power at effect `0.02` for 20/30/40/50/60 families: 4.36% / 16.22% / 42.32% / 52.22% / 69.60%. At effect `0.03`: 19.94% / 56.04% / 88.46% / 92.40% / 95.52%.
- Synthetic lineage: 500 attempts, 500 unique panels, 45 simulated crashes, 30 failed panels, 346 rejections, 79 promotions, and 0.05 alpha spent. This is an in-memory simulation, not an RSIStateStore or external-anchor recovery qualification.

These results establish behavior under the simulator's assumptions; they do not prove that real task families are independent or representative, nor do they demonstrate AIDE improvement. The production minimum is 40 independent family clusters; power remains limited for subtle effects.

## Unclosed release gates

| Gate | State |
|---|---|
| Fresh hosted matrix on the current source snapshot | PENDING |
| Frozen real-task null, degraded, and planted-improvement controls through the complete trusted promotion path | NOT_RUN; no qualification corpus is present |
| Independently administered external monotonic anchor and destructive host rollback test | NOT_RUN; no external service is deployed |
| Complete reproducible lock for optional AIDE research/provider dependencies | NOT_RUN |
| Real multi-generation AIDE-RSI experiment demonstrating improvement of the improvement process | NOT_RUN |

Do not mark this build release-qualified while any required gate is pending or not run.

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
python tools/generate_release_manifests.py --check
```
