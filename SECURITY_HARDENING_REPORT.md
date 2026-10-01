# RSI authority closure hardening report

## Status

This is an unreleased source hardening branch based on AIDE-DREAM-RSI v1.3.5.
Package metadata remains at 1.3.5; the work has not been published as a release
archive. The branch's pre-follow-up full local project suite passed with **153
passed, 1 skipped** on macOS; after this follow-up, the full project suite
passed with **162 passed, 1 skipped**. Linux Bubblewrap execution passed in a
privileged container, while deployment qualification remains open.

## Promotion and recovery authority

Canary recovery now requires an HMAC-authenticated durable RSI state, signed
transaction, and signed decision. Trusted runs reject unsigned legacy state and
any state whose signature no longer verifies. The
transaction is bound to the durable incumbent, pending challenger, round, and
full-width policy digests. It binds the canary gate configuration and each
canary journal digest. Recovery loads the bound journals, validates their
trusted evidence, recomputes the gate, and compares that result with the signed
decision before promoting. A plain `passed: true` file cannot authorize
promotion. The regression suite covers missing evidence, substituted
transaction policies, modified journals, altered gate configuration, and edited
or unsigned durable state.

Policy identities use full SHA-256 digests. Trusted evidence checks that the
candidate, predictions, and canonical evaluation record artifacts exist and
match their recorded content digests before publication, qualification, or
canary acceptance. The HMAC covers the canonical evaluation record bytes and
the artifact identity.

Canary decisions use canonical evaluation sample IDs. The first-party tabular
adapter also rejects matching canonical feature-row-plus-label hashes even when
duplicate examples use different IDs. Canary IDs are committed to
HMAC-authenticated durable state before evaluation, and a per-log-directory
exclusive lock prevents simultaneous controllers. Deleting a round transaction
cannot restore retired IDs. The reference candidate workspace is read-only;
Linux writable `/tmp` is a sized tmpfs, stdout is capped, and the adapter records
the nested process group so outer timeout cleanup can kill it on macOS too.

Canary promotion now requires five paired repeats, a deterministic 95% lower
percentile bootstrap bound over per-repeat normalized best-score differences,
a nonnegative median effect by default, a minimum passing fraction, and a
worst-pair regression ceiling. This quantifies repeat-to-repeat rollout
variation; it is not a per-sample confidence interval and does not establish
generalization beyond the retired canary shard. The generic operator evaluator
supports ID-based overlap checks only. The cumulative consumed-ID list grows
with canary use; an authenticated append-only ledger is a future storage
improvement.

## Evaluator integrity and isolation

The trusted evaluator rehashes the pinned dataset before and after each
authoritative evaluation. It validates the memory limit in MiB and applies
`RLIMIT_NPROC` and `RLIMIT_NOFILE` in the evaluator wrapper. Children inherit
those outer ceilings. Per-child `preexec_fn` limits are not used because they
can fail when nested sandbox processes try to alter inherited resource limits.

A first-party tabular evaluator adapter is included. It gives candidate code
public feature inputs in a separate strict Seatbelt or Bubblewrap sandbox and
scores predictions in a fixed scorer process with labels. It does not pass the
HMAC key to the evaluator child. The adapter process runs outside the outer OS
sandbox on both platforms so it can launch its nested candidate sandbox. It is
content-pinned and resource-limited by the wrapper, but has host filesystem,
process, and network access; it remains trusted host code. Candidate execution
still occurs in the strict inner sandbox.

Operator-supplied evaluator bundles remain responsible for isolating their
candidate execution from labels. The generic trusted evaluator cannot make an
unsafe in-process `exec(candidate)` implementation safe. The first-party
adapter currently supports its documented tabular input contract; other task
formats require a reviewed adapter. The reference adapter's own process is in
the trusted computing base because it runs outside the OS sandbox.

## Migration and remaining limits

Unsigned v1.3.5 canary transaction records do not satisfy this recovery
contract. Start with a fresh RSI log directory and a fresh canary split epoch;
do not resume pending promotion state from an older run. See
[`docs/MIGRATION_v1.3.5_hardening-closure.md`](docs/MIGRATION_v1.3.5_hardening-closure.md).

The HMAC key remains a host-held symmetric secret, not a hardware-backed or
separate-service signing key. Same-host compromise can expose it. Dataset
rehashing detects changes at authoritative evaluation boundaries but does not
provide an immutable filesystem snapshot against a concurrent privileged host
actor. HMAC state authentication detects edits but cannot prevent rollback of a
complete older signed state and evidence snapshot without an external monotonic
anchor. The external-anchor client and protocol test are implemented, but no
independently operated monotonic service is configured here. The Linux
Bubblewrap reference evaluator passed in a privileged Linux Docker container;
unprivileged namespace execution was blocked by this host's container policy.
A GitHub-hosted Linux VM workflow now runs the real isolation tests. Deployment
qualification and separate untouched validation and one-shot qualification
datasets remain open.

## Validation performed

- Full project after this follow-up: `162 passed, 1 skipped`.
- Recovery, evaluator, canary statistics, and first-party adapter tests:
  `56 passed`.
- RSI suite after this follow-up: `111 passed, 1 skipped`.
- Linux first-party adapter and Bubblewrap tests in a privileged Docker
  container: `4 passed`.
- Package source distribution: passed at v1.3.5.
- `python -m compileall -q aide`: passed.
- Black on changed Python files: passed.
- Ruff on changed Python source and tests: passed.
- First-party candidate isolation exercised with macOS Seatbelt.
- Linux Bubblewrap execution passed in the privileged Linux container; this
  macOS host cannot provide unprivileged namespaces directly.
