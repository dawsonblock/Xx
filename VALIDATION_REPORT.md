# Validation Report — AIDE-DREAM-RSI v1.3.3

Build identity: `VERSION=1.3.3`, distribution `aideml-rsi==1.3.3`.
Validation date: 2026-09-30.

## Local validation

- RSI suite: **83 passed, 1 skipped**.
- Trusted-evaluator module: **9 passed**.
- Black 26.3.1: passed for the modified Python files.
- Ruff 0.16.0: passed for changed evaluator modules and tests. `config.py` passed
  with five pre-existing findings ignored; the same five findings reproduce on
  the v1.3.2 version of that file.
- `python -m compileall -q aide tests`: passed.
- `python setup.py --version`: `1.3.3`.
- `git diff --check`: passed.
- `BUILD_MANIFEST.json`: JSON parsing passed.
- Full project suite: not run for this build.

The trusted-evaluator tests exercise a multi-file bundle with a local helper
import, assert that importing it does not create `__pycache__`, check read-only
bundle and dataset permissions, enforce a bounded scratch directory, terminate
an evaluator grandchild, persist content-addressed prediction and signed-record
artifacts, reject a forged prediction digest, and verify fail-closed metric
handling. The test evaluator is deterministic and contains no hidden task data.

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
session. Read-only mode bits do not stop hostile same-UID code
from changing permissions; deployment should mount the bundle read-only.

The evaluator receives no HMAC key through inherited environment variables.
That does not provide OS-level key isolation: a same-UID child may inspect its
parent environment through `/proc` on common Linux configurations. HMAC remains
a symmetric record-integrity mechanism under a trusted host process. A
restricted signer process or service is not included.

The replay split separates historical worlds, not task data. The same configured
evaluator can be queried during discovery and canary, so those scores are
adaptive search feedback rather than untouched generalization evidence. Separate
search, validation, qualification, and canary evaluator authorities remain a
task-specific follow-up.

The environment identity records platform and `PATH` values along with the
Python executable and package inventory; it does not bind a container image or
the contents of external executables and system libraries.

## Historical validation

The v1.3.2 report is preserved in
`docs/archive/VALIDATION_REPORT_v1.3.2.md`; its test counts do not apply to this
build. Earlier reports remain in the archive directory.
