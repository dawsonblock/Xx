# Migration: v1.3.0 to v1.3.1

v1.3.1 hardens evaluator authority and qualification isolation. It intentionally
does not enable trusted automatic promotion: a task-specific external evaluator
is still required.

## Evaluator attestations

Qualification, canary promotion, and best-solution publication now require
HMAC-attested evaluator records binding candidate/task/evaluator/configuration,
dataset/split, predictions, environment, metric identity/direction, and score.
The trusted evaluator and host process must share
`AIDE_RSI_EVALUATION_HMAC_KEY`, configured with at least 32 bytes. Do not
expose this key to generated candidate code or model prompts. Strict sandbox
backends clear the host environment.

The attestation API is `aide.rsi.evidence.attest_evaluation`. An evaluator
integration must supply candidate, evaluator, dataset, and split SHA-256 values,
the metric direction, and the measured score. The evaluator must validate its
own approved code/data identity before signing. Feedback-model metrics remain
advisory. No generic hidden-label evaluator is included because its data and
metric contract is task-specific.

## Holdout behavior

The default bootstrap assigns two development worlds, one validation world, and
three qualification worlds in the first six discovery rounds. Seven rounds
provide one following paired-canary opportunity. Qualification worlds do not
feed live summaries, memory, replay-support scoring, grid planning, or
best-solution selection. A complete attested qualification shard is retired
after its decision and cannot be reused for later candidates.

Existing split manifests remain readable. Previously assigned worlds retain
their roles; qualification worlds can now be retired after an attested decision.
The default split epoch remains unchanged.
