# RSI authority closure hardening report

## Status

This is an unreleased source hardening branch based on AIDE-DREAM-RSI v1.3.5.
Package metadata remains at 1.3.5; the work has not been published as a release
archive. The latest full local project run passed with **173 passed, 1
skipped** on macOS after the canary crash, rotation, anchor, and sample-identity
fixes. The nested outer-timeout test passes locally and on a GitHub-hosted
macOS runner. The prior Linux Bubblewrap workflow passed before these latest
edits and must rerun against this commit. Windows lock execution has not been
exercised on a Windows host. Deployment qualification remains open.

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

Canary reservations use canonical IDs, candidate-visible input hashes, and full
record hashes. The first-party tabular adapter preserves sorted file names and
column names, canonicalizes CSV scalar values, and rejects duplicate
candidate-visible rows within a shard. Search/canary overlap checks ignore
labels when comparing candidate-visible inputs, so relabeling cannot hide
reused features. IDs and hashes are committed to HMAC-authenticated state
before evaluation and included in signed transactions; deleting a reservation
cannot restore retired identities. A running canary without a complete signed
decision burns its shard and abandons its pending challenger. Recovery rejects
incomplete or inconsistent evidence instead of rerunning the evaluation.

Canary evaluator authority is separate from the rotating shard identity. An
operator can install a new disjoint split within the same experiment by
incrementing `rsi.canary_evaluator.shard_epoch` by one. The runner checks
authority continuity and disjointness against search and retired canary data
before signing the new shard identity into state. A per-log-directory exclusive
lock prevents simultaneous controllers; its Windows implementation uses
`msvcrt` rather than importing POSIX-only `fcntl`.

The optional state anchor is sticky once enrolled. Signed state binds a
normalized anchor URL hash and rejects launches that omit or replace that
authority. This pins the endpoint string, not the service's cryptographic key;
DNS, TLS, and anchor-service administration remain deployment trust
assumptions. The reference candidate workspace is read-only; Linux writable
`/tmp` is a sized tmpfs, stdout is capped, and the adapter records the nested
process group so outer timeout cleanup can kill it on macOS too. An integration
test forces an outer evaluator timeout while the nested candidate sleeps and
verifies the candidate process group is gone.

Canary promotion now requires five paired repeats, a deterministic 95% lower
percentile bootstrap bound over per-repeat normalized best-score differences,
a nonnegative median effect by default, a minimum passing fraction, and a
worst-pair regression ceiling. This quantifies repeat-to-repeat rollout
variation; it is not a per-sample confidence interval and does not establish
generalization beyond the retired canary shard. The generic operator evaluator
supports ID-based overlap checks only because it has no canonical sample
content model. The cumulative consumed-ID and content-hash lists grow with
canary use; an authenticated append-only ledger is a future storage
improvement.

## Evaluator integrity and isolation

The trusted evaluator rehashes the pinned dataset before and after each
authoritative evaluation. It validates the memory limit in MiB and applies
`RLIMIT_NPROC` and `RLIMIT_NOFILE` in the evaluator wrapper. Requested process
and descriptor limits are capped to the host hard limit and the effective
ceilings are part of the evaluator identity. Children inherit those outer
ceilings. Per-child `preexec_fn` limits are not used because they can fail when
nested sandbox processes try to alter inherited resource limits.

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

- Full local project suite with current source changes: `173 passed, 1 skipped`
  on macOS.
- RSI test files with current source changes: `122 passed, 1 skipped` on macOS.
- Focused recovery and trusted-evaluator suites: `53 passed` on macOS.
- Nested reference-candidate outer-timeout integration: passed on the local
  macOS host and GitHub-hosted macOS.
- Linux first-party adapter and Bubblewrap tests in a privileged Docker
  container: `4 passed`.
- Package source distribution: passed for the current source; `setup.py --version`
  remains `1.3.5`.
- `python -m compileall -q aide`: passed.
- Black on changed Python files: passed.
- Ruff on changed Python source and tests: passed.
- First-party candidate isolation exercised with macOS Seatbelt.
- Linux Bubblewrap execution passed in the privileged Linux container; this
  macOS host cannot provide unprivileged namespaces directly.
- GitHub Linux Bubblewrap workflow passed on the preceding authority-closure
  revision; rerun is pending for the current edits. The macOS nested-timeout
  hosted workflow passed on the preceding revision, and the current local full
  suite passed its timeout test.
