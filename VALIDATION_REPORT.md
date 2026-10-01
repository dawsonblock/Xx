# Validation Report — AIDE-DREAM-RSI v1.3.5

## Unreleased hardening closure branch

Package metadata remains 1.3.5. This branch adds canary recovery authority
closure, full-width policy identities, candidate-visible sample-content
identity, one-use canary reservations that burn interrupted shards, sticky
external anchor authority, rotating canary shard epochs, a portable writer
lock, per-evaluation dataset rehashing, artifact-backed evidence checks,
evaluator process and descriptor ceilings, and the first-party tabular adapter.
This is source branch validation, not release qualification.

Validation on the local macOS host:

- RSI test files: **122 passed, 1 skipped**.
- Focused recovery and trusted-evaluator tests: **53 passed**.
- Full project suite: **173 passed, 1 skipped**.
- `python -m compileall -q aide`: passed.
- `python setup.py -q sdist`: passed; `python setup.py --version` returned
  `1.3.5`.
- Black: passed for modified Python files.
- Ruff: passed for all changed Python source and test files.
- The first-party candidate boundary and outer-timeout cleanup ran under macOS
  Seatbelt.

GitHub Actions checked commit `18167f8` on the platform-specific paths:

- [macOS nested candidate timeout](https://github.com/dawsonblock/Xx/actions/runs/36841501712): passed.
- [Linux Bubblewrap isolation](https://github.com/dawsonblock/Xx/actions/runs/36841501818): passed.
- [Windows state import and writer lock](https://github.com/dawsonblock/Xx/actions/runs/36841501831): passed.
- [Python linter](https://github.com/dawsonblock/Xx/actions/runs/36841501730): passed.

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
