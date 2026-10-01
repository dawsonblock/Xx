# Sequential canary statistical qualification

`RealCanaryGate` uses a one-sided exact sign test over paired rollout deltas
and spends family alpha using the fixed schedule
`alpha_i = alpha / (i * (i + 1))`. The sum over all attempts is at most the
configured family alpha. `StatisticalBudget` records the rule ID/version,
attempt index, current allocation, spent and remaining alpha, and a chained
reservation digest in authenticated RSI state. A reservation is committed
before the canary runs; an interrupted, failed, or rejected attempt does not
refund alpha. State writes allow only the exact next reservation.

The per-attempt sign-test guarantee depends on valid independent paired signs.
Repeated seeds from one task are not automatically independent tasks. The
current runner still evaluates canary repetitions using one pinned task and
dataset shard, so it has not established cross-task generalization or the
independence assumption required by the sign test.

## Synthetic calibration probe

Run the same production gate implementation against seeded synthetic data:

```sh
python tools/qualify_canary_statistics.py \
  --campaigns 500 --attempts 100 --power-replicates 1000 \
  --bootstrap-samples 1000 \
  --output qualification/canary-statistics-synthetic.json
```

The output includes family-wise false promotion under independent null rollout
pairs, a clustered same-task null model, positive/negative effect acceptance
rates at early and late sequential attempts, Wilson intervals, and the
theoretical alpha allocated. The default bootstrap count is deliberately low
for a quick smoke run; a release campaign must set the same bootstrap count as
the target production configuration and use substantially more independent
lineages.

The clustered model holds one zero-mean task effect across seeds and promotion
attempts while adding small within-task noise. It is a sensitivity analysis,
not an estimate of real AIDE task correlation. A high promotion rate in this
model demonstrates why repeated seeds from one task cannot be counted as
independent evidence for cross-task claims.

One recorded local run used seed `20261001`, 500 null lineages per model,
100 promotion attempts per lineage, 500 power replicates, and only 100
bootstrap resamples per gate. Under independent null pairs it promoted 12/500
lineages (2.4%; 95% Wilson interval 1.38%–4.15%). Under the shared-task
clustered null it promoted 239/500 (47.8%; 95% Wilson interval
43.46%–52.18%). For a synthetic `+0.015` effect with `0.01` rollout standard
deviation, single-attempt acceptance was 65.6% at attempt 1 and 25.6% at
attempt 100. The full seeded output and source-file hashes are in
[`qualification/canary-statistics-synthetic.json`](../qualification/canary-statistics-synthetic.json).

This is not release qualification: it uses a low bootstrap count and a
synthetic correlation model, and it does not estimate real task/seed
correlation. It does show that the current repeated-seed procedure cannot
support a cross-task false-promotion claim until task clusters become the
inference units.

These simulations do not replace a fixed multi-task qualification matrix.
Before unattended multi-generation promotion, define the inference unit as a
task, dataset shard, and search seed; determine task-level aggregation; then
measure within-task and between-task variance on a precommitted task matrix.
The current state and canary protocol do not yet implement that matrix.
