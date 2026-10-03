# Migration: v1.3.2 to v1.3.3

v1.3.3 hardens the pinned evaluator subprocess. Python bytecode writing is
disabled with `-B` and `PYTHONDONTWRITEBYTECODE`, evaluator bundle files must
have no write permission bits, scratch output is bounded with
`rsi.trusted_evaluator.max_output_mb`, and evaluator process groups are killed
before output validation. Verified predictions and signed evaluation records
are retained content-addressed under the run's RSI artifact directory.

The default scratch cap is 64 MiB. Set a value from 1 to 4096 MiB for a task's
prediction volume. The evaluator bundle must be readable and have no write
permission bits; mount it read-only for deployment because permission bits do
not constrain a hostile process running under the same UID.

The documentation now distinguishes removing the attestation key from the
child's environment from OS-level key isolation. A same-UID process may inspect
the parent environment through `/proc` on common Linux configurations. Use a
separate restricted UID or signer service when that boundary is required.

Replay-world splitting does not separate the underlying evaluation data. The
same configured evaluator may be queried during discovery and canary; these
scores are search feedback and do not qualify untouched generalization. This
release documents that boundary but does not add task-specific evaluator
authorities for separate search, validation, qualification, and canary datasets.

Trusted evaluation remains opt-in, so no configuration change is needed for
existing installations. Existing trusted-evaluation run identities continue to
use their v1.3.2 evaluator pins. Start a fresh experiment if the evaluator,
configuration, dataset, split, metric, or environment changes.
