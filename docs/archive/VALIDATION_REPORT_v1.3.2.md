# Validation Report — AIDE-DREAM-RSI v1.3.2

Build identity: `VERSION=1.3.2`, distribution `aideml-rsi==1.3.2`.
Validation date: 2026-09-30.

## Local validation

- Full project suite: **130 passed, 1 skipped**.
- RSI suite: **79 passed, 1 skipped**.
- Ruff 0.7.1: passed for `aide/`.
- Black 24.3.0: passed for `aide/` and the trusted-evaluator integration test.
- `python -m compileall -q aide tests`: passed.
- `python setup.py --version`: `1.3.2`.
- `git diff --check`: passed.
- Build manifest JSON validation: passed.

The trusted-evaluator subprocess protocol was exercised end-to-end with a
deterministic fixture bundle. Tests cover host signing-key isolation, signed
metric propagation into the live node and canary gate, fail-closed evaluator
errors, read-only dataset enforcement, and identity binding. No task-specific
hidden-data evaluator bundle or live model backend was run.

Bubblewrap and OCI candidate execution were not run on this macOS host. Native
Seatbelt behavior remains covered by the repository's macOS tests and CI; this
report does not claim deployment qualification for the operator's evaluator
bundle or its internal candidate sandbox.

## Evaluator authority

When configured, the runner executes an operator-pinned evaluator bundle in a
separate Python process after candidate sandbox execution. The evaluator must
independently run the content-addressed candidate against its pinned task
configuration and hidden data/split, then calculate predictions and a fixed
metric. The host checks the returned identity fields, rechecks the evaluator and
control-file pins, and creates the HMAC attestation. The signing key is excluded
from the evaluator subprocess environment. If evaluation fails, the candidate
is unscored and feedback-model metrics are not used as fallback.

No task-specific evaluator bundle is included. Trusted evaluation is disabled
by default, so automatic policy promotion and best-solution publication remain
fail-closed until an operator supplies and qualifies a reviewed bundle. See
[docs/TRUSTED_EVALUATOR.md](docs/TRUSTED_EVALUATOR.md) for the protocol and
configuration contract.

## Holdout and recovery controls

- Development worlds alone feed live memory, replay support, grid planning, and
  best-solution selection.
- Validation worlds are used for candidate tuning; qualification worlds are
  only used for promotion decisions and are retired after an attested shard.
- The split bootstrap assigns 2 development, 1 validation, and 3 qualification
  worlds by the sixth discovery round. Seven default rounds provide a following
  paired-canary opportunity.
- Candidate artifacts are content-addressed and source hashes are checked
  before publication.
- Canary decisions recover from durable policy transactions; persisted policy
  digests and trusted-evaluator identity are checked when resuming.
- OCI and Bubblewrap writable workspaces use size-limited temporary filesystems;
  OCI containers are explicitly killed and removed after CLI failure or timeout.

## Historical validation

The v1.3.0 and v1.3.1 reports are preserved in
`docs/archive/VALIDATION_REPORT_v1.3.0.md` and
`docs/archive/VALIDATION_REPORT_v1.3.1.md`. Those results do not apply to this
build.
