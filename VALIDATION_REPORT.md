# Validation Report — AIDE-DREAM-RSI v1.3.1

Build identity: `VERSION=1.3.1`, distribution `aideml-rsi==1.3.1`.
Validation date: 2026-09-29.

## Current validation

- Full project suite: **125 passed, 1 skipped**, using declared dependencies installed in `/tmp/aide-rsi-review-deps`.
- RSI suite: **74 passed, 1 skipped**.
- Ruff 0.7.1: passed for `aide/`.
- Black 24.3.0: passed for `aide/`.
- `python -m compileall -q aide tests`: passed.
- `python setup.py --version`: `1.3.1`.
- `git diff --check`: passed.

Bubblewrap and OCI execution were not run on this macOS host. Their workspace construction and OCI timeout cleanup are covered by focused unit tests. The suite and prior local qualification exercised macOS Seatbelt paths. No live model backend or task-specific trusted evaluator was run.

## Evaluation authority

AIDE feedback-model metrics are advisory. Replay qualification, the paired real canary, and best-solution publication require an HMAC-attested record binding candidate, task, evaluator/configuration, dataset/split, predictions, environment, metric identity/direction, and score. Verification uses the host-only `AIDE_RSI_EVALUATION_HMAC_KEY`; strict candidate sandboxes clear the environment.

This repository still has no task-specific external evaluator or hidden-data contract. Its live runner therefore creates no trusted evaluation records, so autonomous promotion and best-solution publication remain fail-closed. HMAC proves which shared-key holder created the record; the evaluator integration must verify its approved evaluator and dataset identities before signing. This is not public-key non-repudiation.

## Holdout and recovery controls

- Development worlds alone feed live memory, replay support, grid planning, and best-solution selection.
- Validation worlds are used for candidate tuning; qualification worlds are only used for promotion decisions and are retired after a complete attested shard is evaluated.
- The split bootstrap assigns 2 development, 1 validation, and 3 qualification worlds by the sixth discovery round. Seven default rounds provide a subsequent paired-canary opportunity.
- Candidate artifacts are content-addressed and source hashes are checked before publication.
- Canary decisions are recovered from durable policy transactions; persisted incumbent and pending policy digests are checked at startup.
- OCI and Bubblewrap writable workspaces use size-limited temporary filesystems; OCI containers are explicitly killed and removed after CLI failure or timeout.

These controls do not establish deployment readiness. The task-specific trusted evaluator remains a release blocker for automatic recursive promotion.

## Historical validation

The v1.3.0 validation snapshots are preserved in [docs/archive/VALIDATION_REPORT_v1.3.0.md](docs/archive/VALIDATION_REPORT_v1.3.0.md) and do not apply to this build.
