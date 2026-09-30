# Migration: v1.0.0 → v1.1.0

v1.1 is a hardening release. Existing source configuration is mostly compatible, but authority and evidence semantics are stricter.

## Replay pool

New replay pools use schema v3: SHA-256 content-addressed objects plus an explicit insertion-order list. v2 manifests are migrated deterministically on first read. Standalone `.world.json` files still require a matching `.sha256` sidecar.

Replay now rejects a history where one non-root node has multiple recorded children. The live reference controller executes serially, so a non-root frontier can have only one continuation before it ceases to be a leaf. Rejecting ambiguous histories prevents offline replay from receiving actions that are unavailable online. Root branches remain unrestricted.

## Split assignments

Development, validation, and qualification assignments persist for the lifetime of a split epoch. Do not delete `rsi/split_manifest.json` merely to get a more favorable split. Provision a new untouched qualification set and intentionally increment `rsi.split_epoch` when starting a new evaluation epoch.

## Candidate execution

`rsi.sandbox.mode=strict` is the default and requires Linux `bubblewrap`. Strict mode clears credentials, disables network via namespaces, mounts task input read-only, creates a disposable writable workspace, and applies configurable POSIX resource limits.

On a host without the strict backend, the runner fails closed. The legacy same-user process executor is available only when both of these are set:

```yaml
rsi:
  sandbox:
    mode: process
    allow_insecure_process: true
```

That mode is for trusted-code research or for use inside an external isolation boundary.

## Resume

Resume through the original log directory:

```bash
aide-rsi data_dir=/path/to/data goal="..." \
  rsi.resume_log_dir=/absolute/path/to/original/log
```

The state machine resumes live discovery from the saved journal or deterministically reruns an incomplete replay-policy phase from immutable inputs.

## Parallelism

v1.1 deliberately sets effective live parallelism to 1 and forces replay parallel reward to zero. `rsi.max_parallelism` is retained for forward compatibility but does not claim wall-clock speedup in this release.
