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

Keep the HMAC key stable for the lifetime of a hardened run. Canary sample IDs,
full record hashes, and candidate-visible input hashes are retired in
HMAC-authenticated `rsi/state.json` before evaluation; deleting a round's
`canary/transaction.json` cannot make them reusable. If a running canary
restarts without its complete signed decision, the shard is burned and the
pending challenger is abandoned. Do not restore an older version of the log
directory. Configure canonical `evaluation_sample_ids` for both search and
canary split manifests.

Canary evaluator authority is stored separately from its rotating data shard.
To use another fresh shard in the same experiment, change the pinned canary
split/data and increment `rsi.canary_evaluator.shard_epoch` by exactly one. The
new shard must not overlap search samples or any retired canary ID, full record,
or candidate-visible input hash. Skipped epochs, shard reuse, and evaluator
authority changes fail closed.

Once a run uses external state anchoring, every later launch must provide the
same anchor authority URL and ID. Disabling or replacing that anchor is
rejected. Older anchored state without a signed authority URL hash requires an
explicit operator migration. HTTPS anchors now also require the exact
out-of-band TLS leaf-certificate fingerprint through
`AIDE_RSI_STATE_ANCHOR_TLS_CERT_SHA256`; certificate renewal requires an
explicit operator pin migration.

The canary attempt index is HMAC-authenticated and monotonic. The multi-task
statistical protocol has a fixed horizon of 500 promotion attempts and a
Bonferroni allocation of `alpha_i = family_alpha / 500`. A reserved canary
consumes its allocation before evaluation. Existing runs with a nonzero
attempt count under an older statistical protocol must start a fresh
experiment; those attempts cannot be silently reinterpreted under the new
error budget. Gate thresholds, protocol, horizon, and configured alpha are
pinned for the run. A full signed-directory rollback can also roll back this
index unless an external monotonic anchor is configured.

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
