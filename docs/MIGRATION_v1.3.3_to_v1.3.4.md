# Migration: v1.3.3 to v1.3.4

v1.3.4 adds the optional `rsi.canary_evaluator` configuration. Search and
canary evaluators must use the same metric name and direction. When both are
enabled, the runner rejects identical dataset and split digests. Live canary
runs use only the canary evaluator; if it is disabled, canary scores are
advisory and cannot authorize promotion.

Candidate source is copied to a per-evaluation snapshot before invoking the
evaluator. The host verifies the snapshot digest after evaluation and rejects
mutated or replaced snapshots, leaving the content-addressed source artifact
unchanged.

Existing state written with a single evaluator identity is migrated to the
role-specific identity map. A new canary evaluator may be added when resuming
an existing run with the same search evaluator. The canary evaluator identity
is then pinned in durable state. Changing the search evaluator still requires a
fresh experiment.

Replay validation and qualification continue to reuse discovery scores. They
remain held-out world trajectory checks and do not provide untouched data
generalization evidence. This release separates the live canary authority only;
separate validation and one-shot qualification data authorities remain
task-specific work.

The canary evaluator must satisfy the same operator review and candidate
sandbox contract as the search evaluator. Separate dataset or split pins do
not isolate candidate code from hidden labels inside an unsafe evaluator.
