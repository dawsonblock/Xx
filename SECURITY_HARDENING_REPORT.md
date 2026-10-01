# RSI authority closure hardening report

## Status

This is an unreleased source hardening branch based on AIDE-DREAM-RSI v1.3.5.
Package metadata remains at 1.3.5; the work has not been published as a release
archive. The current source has **178 passed, 1 skipped** in the full local
suite, **127 passed, 1 skipped** in RSI tests, and **57 passed** in the focused
recovery/evaluator suite on macOS. Hosted macOS, Linux, Windows, and linter
reruns for this source revision are pending. Deployment qualification remains
open.

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

The optional state anchor is sticky once enrolled. Signed state binds the
normalized anchor URL and, for HTTPS, an out-of-band leaf-certificate SHA-256
pin. The client verifies the standard TLS chain, hostname, and configured pin
before sending the bearer credential. Missing or changed pins fail closed;
certificate renewal requires explicit operator migration. Loopback HTTP is
limited to protocol tests. The reference candidate workspace is read-only; Linux writable
`/tmp` is a sized tmpfs, stdout is capped, and the adapter records the nested
process group so outer timeout cleanup can kill it on macOS too. An integration
test forces an outer evaluator timeout while the nested candidate sleeps and
verifies the candidate process group is gone.

Canary promotion retains the deterministic 95% bootstrap non-inferiority bound,
minimum passing fraction, and worst-pair regression ceiling. It now also uses a
one-sided exact paired sign test with alpha spending
`alpha_i = experiment_alpha / (i * (i + 1))`; the monotonic attempt index is
stored in authenticated state, with the total experiment alpha immutable for
the run. The complete static promotion-rule digest is also pinned in state, so
confidence levels and regression thresholds cannot drift between generations.
The attempt index is bound into each signed transaction and decision; the
derived alpha appears in the signed result and gate configuration. Repeats grow
as the per-attempt alpha shrinks: six pairs at attempt one and seven at attempt
two with the default 0.05 budget. The
spending schedule sums to the configured experiment alpha if each attempt's
sign-test p-value is valid. That requires independent paired rollout outcomes;
the current runner does not establish cross-task or seed independence, so this
is an implemented statistical control with an explicit qualification boundary,
not a claim of proven end-to-end false-promotion control. It measures repeated
rollout behavior and does not establish generalization beyond retired canary
shards. The generic operator evaluator
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

- Full local project suite with current source changes: `178 passed, 1 skipped`
  on macOS.
- RSI test files with current source changes: `127 passed, 1 skipped` on macOS.
- Focused recovery and trusted-evaluator suites: `57 passed` on macOS.
- A 100-iteration interrupted-canary simulation preserved retired IDs and
  content hashes after deleting each transaction file.
- Sequential alpha spending, expanding paired-run minimums, mismatched-attempt
  recovery, and HTTPS certificate-pin-before-credential behavior are covered.
- Nested reference-candidate outer-timeout integration: passed on the local
  macOS host and GitHub-hosted macOS.
- Linux first-party adapter and Bubblewrap tests in a privileged Docker
  container: `4 passed`.
- Package source distribution: passed for the current source; `setup.py --version`
  remains `1.3.5`.
- `python -m compileall -q aide`: passed.
- Black on changed Python files: passed.
- Ruff on changed RSI security source and tests: passed. The changed config
  module was checked with its pre-existing local-version findings excluded.
- First-party candidate isolation exercised with macOS Seatbelt.
- Linux Bubblewrap execution passed in the privileged Linux container; this
  macOS host cannot provide unprivileged namespaces directly.
- GitHub-hosted platform and linter workflows from commit `18167f8` passed, but
  they predate the sequential-alpha and TLS-pin changes. Reruns for the current
  source commit are pending.
