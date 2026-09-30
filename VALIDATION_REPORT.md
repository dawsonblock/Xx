# Validation Report — AIDE-DREAM-RSI v1.3.4

Build identity: `VERSION=1.3.4`, distribution `aideml-rsi==1.3.4`.
Validation date: 2026-09-30.

## Local validation

- Full project pytest suite: **138 passed, 1 skipped**.
- RSI suite: **87 passed, 1 skipped**.
- Trusted-evaluator module: **13 passed**.
- Black 26.3.1: passed for the modified Python files.
- Ruff 0.16.9: passed for changed runner and trusted-evaluator test files.
- `python -m compileall -q aide tests`: passed.
- `python setup.py --version`: `1.3.4`.
- Shipped YAML parses with the new canary evaluator defaults disabled.
- `BUILD_MANIFEST.json` parses and its version matches the package.
- `git diff --check`: passed.

The trusted-evaluator tests exercise a multi-file bundle with a local helper
import, assert that importing it does not create `__pycache__`, check read-only
bundle and dataset permissions, enforce a bounded scratch directory, terminate
an evaluator grandchild, persist content-addressed prediction and signed-record
artifacts, reject a forged prediction digest, verify fail-closed metric
handling, and enforce distinct search/canary data identities and metric parity.
It also verifies migration of prior single-evaluator run identities and rejects
candidate snapshot mutation without changing the canonical artifact. The test
evaluator is deterministic and contains no hidden task data.

Bubblewrap, OCI candidate execution, a task-specific evaluator bundle, and a
live model backend were not run for this build. This report does not establish
deployment readiness or candidate isolation inside an operator-supplied
evaluator.

## Evaluator security and evidence limits

The host launches evaluator Python with `-I -B` and sets
`PYTHONDONTWRITEBYTECODE=1`. It requires the evaluator bundle to have no write
permission bits, applies a per-file limit and samples aggregate scratch use in
the temporary directory against `max_output_mb`, kills the evaluator process
group, and stores verified predictions and attested records by content hash.
This does not constrain writes outside that directory or stop a deliberate new
session. Read-only mode bits do not stop hostile same-UID code from changing
permissions; deployment should mount the bundle read-only.

The evaluator receives no HMAC key through inherited environment variables.
That does not provide OS-level key isolation: a same-UID child may inspect its
parent environment through `/proc` on common Linux configurations. HMAC remains
a symmetric record-integrity mechanism under a trusted host process. A
restricted signer process or service is not included.

The replay split separates historical worlds, not task data. Replay validation
and qualification reuse discovery scores and are not untouched generalization
evidence. A separate pinned canary evaluator is now required for trusted live
promotion, but task-specific candidate confinement remains the operator's
responsibility. Separate validation and one-shot qualification data authorities
are not implemented.

The host trusts the task evaluator's metric implementation and does not
independently recompute it from labels and predictions. Environment identity
records platform and `PATH` values along with the Python executable and package
inventory; it does not bind a container image or the contents of external
executables and system libraries.

## Historical validation

The v1.3.3 report is preserved in
`docs/archive/VALIDATION_REPORT_v1.3.3.md`; its test counts do not apply to this
build. Earlier reports remain in the archive directory.
