# v1.3.5 hardening closure migration note

This branch contains unreleased security changes on the v1.3.5 source line. It
does not change `VERSION`, `setup.py`, or the distribution metadata.

## Existing RSI runs

The new code uses full SHA-256 policy identities and rejects unsigned canary
transactions and decisions. Existing state files use shortened policy digests,
and earlier state and canary JSON have no host HMAC signature. The runner fails
closed on those records and does not migrate a pending challenger or recover a
previous unsigned promotion. Preserve the old log directory for audit, and use
a new log directory and split epoch for a run under this hardening branch.

Keep the HMAC key stable for the lifetime of a hardened run. Canary sample IDs
are now retired in HMAC-authenticated `rsi/state.json` before evaluation;
deleting a round's `canary/transaction.json` cannot make them reusable. Do not
restore an older version of the log directory. Configure
canonical `evaluation_sample_ids` for both search and canary split manifests.
Canary sample IDs are consumed as soon as a signed reservation is written,
including when evaluation later crashes or fails.

## Evaluator configuration

Pin the evaluator bundle, evaluator config, dataset tree, split manifest, and
environment lock. The dataset must be read-only and is rehashed before and
after every evaluation. Set process and open-file limits under each trusted
evaluator role. For tabular tasks, the first-party adapter can use
`entrypoint: __aide_reference__`; its pinned task config lists label and public
feature files. Review [TRUSTED_EVALUATOR.md](TRUSTED_EVALUATOR.md) before
enabling promotion.

Do not use this source branch as a released v1.3.6 package until the package
version and full release validation are intentionally updated.
