# Validation Report — AIDE-DREAM-RSI v1.3.5

## Current statistical-authority milestone

This is the current validation record for the unreleased branch
`fix/aide-rsi-authority-closure`. The qualified code snapshot is commit
`c4603ac4128f9e45480c286457ad4a1eeac48ee4`, Git tree
`0587067e04f7d67c1bbbf2f3d491c54ad6885173`, with package metadata still at
`1.3.5`. It is not a v1.4.0 release. The canonical source, TCB, statistical
artifact, and test identities are in [`RELEASE_FREEZE_MANIFEST.json`](RELEASE_FREEZE_MANIFEST.json)
and [`TCB_MANIFEST.json`](TCB_MANIFEST.json).

Local qualification on 2026-10-01:

- Full project suite: **208 passed, 1 skipped** (209 tests; JUnit artifact
  hash is recorded in the release freeze manifest).
- Compile check, Ruff, Black, and `git diff --check`: passed.
- Synthetic null calibration: **674 false-promotion lineages / 20,000**
  (3.37%); 95% Wilson interval **3.13%–3.63%**, below the experiment-wide
  alpha of 5% for this configured 100-attempt campaign.
- Correlation sensitivity: **25/25** seed-correlation × family-correlation
  cells passed. Each cell used 20,000 simulated attempts; the highest observed
  false-promotion rate was 2.235%, with a highest 95% Wilson upper bound of
  2.449% against the first-attempt alpha allocation of 2.5%.
- Power sensitivity: for a 0.02 effect at attempt 1, estimated power was
  70.9%, 86.5%, and 92.5% with 20, 30, and 40 independent family clusters.
  At attempt 100 it was 0.6%, 6.8%, and 17.8%, respectively. This shows the
  current conservative spending schedule has low late-attempt power; these
  curves are synthetic and are not evidence of AIDE task improvement.
- Synthetic in-memory lineage stress: 500 panel attempts, 47 crashes after
  reservation, 26 failed panels, 500 unique panels, and alpha remaining
  `0.0000998004`. This exercises the in-memory budget/lineage model; it does
  not qualify `RSIStateStore`, an external anchor, or crash behavior in a
  deployed experiment.
- Wheel and source distribution contents were checked; a clean wheel install
  exercised the statistics and anchor entry points, bundled LocalJevFabric,
  and a local anchor compare-and-swap/read smoke test.
- The calibration tool also completed a reduced smoke campaign from both the
  installed wheel and extracted source distribution without Git metadata; each
  resolved the frozen commit/tree from its bundled release freeze.

Still unqualified: hosted workflows for this latest code commit, an independently
deployed external anchor and whole-directory rollback, real multi-task
identical/degraded/stronger controls, and genuine multi-generation AIDE-RSI
improvement. The requirements files are not a locked dependency set. Synthetic
independence assumptions do not prove that real task-family clusters are
independent or representative. See the machine-readable freeze for exact
`NOT_RUN` and `NOT_CONFIRMED` statuses. Older sections below are historical
validation for earlier commits and must not be attributed to this source.

## Unreleased hardening closure branch

Package metadata remains 1.3.5. This branch adds canary recovery authority
closure, full-width policy identities, candidate-visible sample-content
identity, one-use canary reservations that burn interrupted shards, sticky
external anchor authority with HTTPS certificate pinning, rotating canary shard
epochs, sequential alpha spending with immutable thresholds over signed
promotion attempts, a portable writer lock, per-evaluation dataset rehashing, artifact-backed evidence checks,
evaluator process and descriptor ceilings, and the first-party tabular adapter.
This is source branch validation, not release qualification.

Current hardening validation date: 2026-10-01.

Validation on the local macOS host:

- RSI test files: **127 passed, 1 skipped**.
- Focused recovery and trusted-evaluator tests: **57 passed**.
- Full project suite: **178 passed, 1 skipped**.
- `python -m compileall -q aide`: passed.
- `python setup.py -q sdist`: passed; `python setup.py --version` returned
  `1.3.5`.
- Black: passed for modified Python files.
- Ruff: passed for changed RSI security source and tests. The config module was
  checked with its pre-existing local-version findings excluded.
- The first-party candidate boundary and outer-timeout cleanup ran under macOS
  Seatbelt.
- A 100-attempt interrupted-canary simulation retained all retired sample
  identities after reservation-file deletion.
- Sequential alpha-spending and dynamically increasing minimum paired runs
  passed deterministic gate tests; experiment alpha and static gate settings
  are pinned by the authenticated state.
- HTTPS anchor pin tests confirmed a wrong certificate is rejected before the
  bearer credential is sent.

GitHub Actions checked commit `cd94004`:

- [macOS nested candidate timeout](https://github.com/dawsonblock/Xx/actions/runs/36848550589): passed.
- [Linux Bubblewrap and authority regression tests](https://github.com/dawsonblock/Xx/actions/runs/36848550461): passed.
- [Windows state and authority regression tests](https://github.com/dawsonblock/Xx/actions/runs/36848550549): passed.
- [Python linter](https://github.com/dawsonblock/Xx/actions/runs/36848550714): passed.

The remainder of this file records the v1.3.5 baseline and must not be read as
validation of the unreleased changes above.

Build identity: `VERSION=1.3.5`, distribution `aideml-rsi==1.3.5`.
Validation date: 2026-09-30.

## Local validation

- Full project pytest suite: **141 passed, 1 skipped**.
- RSI suite: **90 passed, 1 skipped**.
- Trusted-evaluator module: **16 passed**.
- Black 25.1.0: passed for the changed Python files.
- Ruff 0.16.0: passed for `aide/rsi/trusted_evaluator.py` and
  `tests/test_rsi_trusted_evaluator.py`. The whole-repository check reports 96
  existing findings; `aide/utils/config.py` has five pre-existing findings.
- `python -m compileall -q aide tests`: passed.
- `python setup.py --version`: `1.3.5`.
- Shipped YAML and `BUILD_MANIFEST.json` parse successfully.
- `git diff --check`: passed.

The trusted-evaluator tests exercise multi-file local imports, bytecode
immutability, read-only inputs, scratch output limits, child cleanup,
resource-identity binding, persisted prediction and signed-record artifacts,
independent canary split enforcement, prior-state identity migration,
candidate snapshot mutation rejection, host-file denial, loopback network
denial, and Bubblewrap command construction. The deterministic test evaluator
contains no hidden task data.

The macOS Seatbelt backend was exercised locally, including filesystem,
network, candidate-mutation, scratch-limit, and child-cleanup checks. Linux
Bubblewrap execution and OCI candidate execution were not run on macOS; its
command construction was unit tested. No task-specific hidden-data evaluator
or live model backend was exercised. This report does not establish deployment
readiness or candidate isolation inside an operator-supplied evaluator.

## Evaluator security and evidence limits

Trusted evaluator processes run in a deny-by-default macOS Seatbelt or Linux
Bubblewrap sandbox. The sandbox permits reads of the pinned runtime, evaluator
bundle, configuration, split, dataset, and candidate snapshot; writes are
limited to temporary scratch space; network access is denied. Bubblewrap uses
private namespaces and a private `/proc`. The host also enforces a timeout,
CPU limit, per-file output limit, and aggregate scratch limit. Linux applies a
per-process address-space limit. macOS samples the evaluator process RSS; this
does not aggregate memory used by evaluator grandchildren.

The sandbox intentionally gives the evaluator access to task data so it can
compute the metric. It does not isolate candidate code that the evaluator runs
in-process. The task bundle must execute candidates in a separately qualified
sandbox that hides labels and credentials. The HMAC key is withheld from the
evaluator child, but the signer is not a dedicated UID or signing service and
there is no hardware-backed key boundary.

Replay splits separate historical worlds, not task data. Replay validation and
qualification reuse discovery scores and are not untouched generalization
evidence. Separate validation and one-shot qualification data authorities are
not implemented. The host trusts the pinned task evaluator's metric
implementation and does not independently recompute it from labels and
predictions. Environment identity records the Python runtime, installed
packages, restricted `PATH`, sandbox backend, platform, and limits, but does
not bind a container image or every external executable and system library.

## Historical validation

The v1.3.4 report is preserved in
`docs/archive/VALIDATION_REPORT_v1.3.4.md`; its test counts do not apply to this
build. Earlier reports remain in the archive directory.
