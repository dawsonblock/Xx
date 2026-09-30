# Migration: v1.3.4 to v1.3.5

Trusted evaluator subprocesses now run inside a fail-closed native OS sandbox.
`sandbox_backend: auto` selects macOS Seatbelt or Linux Bubblewrap. It does not
fall back to an unrestricted process; trusted evaluation initialization fails
if the strict backend is unavailable. Linux uses private namespaces and a
read-only runtime, bundle, dataset, split, config, and candidate snapshot, with
only scratch writable. macOS applies a deny-by-default Seatbelt profile with
the same task-input and scratch access model.

Evaluator CPU and per-file output are limited. Linux applies a per-process
address-space limit; macOS samples the evaluator process RSS up to
`max_memory_mb`. This macOS memory sample does not aggregate the memory of
evaluator grandchildren. Set `sandbox_backend`, `max_memory_mb`,
`max_output_mb`, and `timeout_s` separately for the search and canary evaluator
roles when needed.

The new default fails closed on Linux hosts without Bubblewrap. Install and
qualify Bubblewrap before enabling trusted evaluation there. Existing runs
retain their pinned search and canary evaluator identities; the selected OS
sandbox backend is included in evaluator environment identity, so changing the
backend on resume requires a fresh experiment.

This outer evaluator sandbox restricts host filesystem and network access. It
does not hide the evaluator's mounted task data from candidate code that the
bundle executes in-process. Task bundles must continue to use a separately
qualified candidate sandbox. Replay validation and qualification also continue
to reuse discovery scores rather than independent data authorities.
