# Migration: v1.3.1 to v1.3.2

v1.3.2 integrates a host-owned, pinned external evaluator protocol into discovery
and real-canary runs. Trusted evaluation remains opt-in; the default configuration
continues to use advisory feedback-model metrics and cannot promote policies or
publish a best solution.

## Enable task-owned evaluation

Review and build a task-specific evaluator bundle that independently runs the
candidate on its configured data and split, computes a fixed metric, and returns
the exact JSON response described in [TRUSTED_EVALUATOR.md](TRUSTED_EVALUATOR.md).
The candidate must never receive hidden labels or the host attestation key. The
dataset directory must be read-only. Pin the evaluator bundle tree, evaluator
configuration file, dataset tree, split manifest, and environment manifest. Set
those paths and hashes under `rsi.trusted_evaluator`, along with `metric_id`,
`metric_maximize`, and `timeout_s`.

Set `AIDE_RSI_EVALUATION_HMAC_KEY` in the AIDE host environment to a secret of at
least 32 bytes. The runner omits it from the evaluator subprocess environment.
When trusted evaluation is enabled, successful candidates use its score directly;
an evaluator error or invalid response leaves the candidate unscored and does not
fall back to feedback-model scores.

The evaluator identity is persisted with RSI state. Do not enable, disable, or
change evaluator/data/task pins when resuming an experiment that already has
worlds. Start a fresh experiment and split epoch for a new evaluator identity.

This release does not bundle a task-specific evaluator or certify its sandbox.
The operator remains responsible for evaluator correctness, candidate isolation
inside that evaluator, hidden-data confidentiality, and deployment qualification.

## Existing runs

v1.3.1 split assignments and attested replay records remain readable. Existing
runs created without the evaluator identity cannot be resumed with trusted
evaluation enabled; this prevents advisory histories from being mixed into a
trusted-evidence run.
