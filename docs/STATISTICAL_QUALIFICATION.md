# Multi-task canary statistical protocol

Promotion inference uses independent task-family clusters. Seeds are paired within a task; tasks sharing a family are reduced to one median family effect. Only family effects enter the one-sided exact sign test. This is more conservative than counting each task as independent when tasks from the same family share data, prompts, scoring code, or environment. A tie at the configured practical-effect threshold counts as a non-win.

`MULTITASK_PROMOTION_PROTOCOL_V6` fixes the protocol identity and records:

- at least 40 distinct tasks and at least 40 independent task-family clusters;
- exactly 4 paired runs per task, reduced to one median task effect;
- one median task effect per family cluster for inference;
- at least 3 broad task strata, at least 3 independent families per stratum, and no stratum above half of the panel;
- equal family weights, a predeclared practical-effect threshold, and a worst-task regression limit;
- a panel digest, fixed replicate IDs and seeds, task budgets, evaluator and shard identities, sample identities, metric definitions, and a canonical ABBA/BAAB run order. Replicate IDs are metadata and cannot select order. Each task has exactly two challenger-first and two incumbent-first pairs; the symmetric schedule cancels constant first/second-position and linear within-task sequence effects in the median task effect. Seeds may be paired within a dependence family but may not be reused across independent families;
- a fixed 500-attempt horizon and Bonferroni allocation `alpha_i = family_alpha / 500`; attempt 501 is rejected rather than extending or resetting the sequence.

The YAML retains `attempts` and `repeats` as deprecated, unused compatibility
fields. `min_pass_fraction`, `min_pairs`, `confidence_level`,
`bootstrap_samples`, and `max_single_pair_regression` remain controls for
direct legacy V1 `RealCanaryGate.evaluate_series()` callers only. None affect
the V6 panel or promotion decision. V6 binds `min_valid`,
`score_scale_floor`, the fixed four-run schedule, task/family protocol,
practical-effect threshold, maximum task regression, and alpha allocation.
`max_normalized_regression` is also bound because it determines the serialized
per-pair diagnostic flag; that flag does not independently veto panel
promotion. Regression tests ensure legacy settings cannot change the V6
protocol digest while decision or signed-result fields remain bound. V6 also
serializes each sample ID with its public-input and full-record hashes and
rejects detached row identities during recovery.

The minimum was raised to 40 families after the model-based power curves
estimated 4.36% power for a 0.02 effect at 20 families, 42.32% at 40, and
69.60% at 60. For a 0.03 effect, estimated power was 88.46% at 40 and 95.52%
at 60. The 20- and 30-family curves remain in the report as below-minimum
comparisons. The default still has limited power for subtle effects; larger
panels are recommended when the experiment needs to detect improvements near
0.02.

`task_family` identifies a dependence cluster: every task with a plausible shared source of outcome dependence must use the same family ID. `task_stratum` records the broader domain (for example classification, forecasting, or resource-constrained search) and is used only to balance the precommitted panel. If two nominal families still share a meaningful shock, they must be merged for inference; relabeling correlated tasks cannot make them independent.

The complete panel and allocated alpha are authenticated in durable state before the first result is observed. The signed transaction binds the panel, task set, protocol, seed and execution schedules, incumbent/challenger, and budget digest. Every task journal is content-hash-bound into the signed decision. Recovery recomputes task effects, family effects, and the gate from those journals. The decision records the exact critical number of positive family clusters for its allocated alpha. If a canary has been reserved but its complete signed decision is missing, recovery aborts the challenger and burns the panel and alpha allocation; it never reruns that panel.

The configured seeds initialize local Python and NumPy random generators and are paired between incumbent and challenger. They do not control randomness inside every LLM provider. Each run records that provider-side RNG seeding is not guaranteed. Seeds estimate within-task variability; tasks estimate a family effect; independent family clusters provide the nominal inference units.

## Synthetic calibration

Run the seeded calibration harness with its release-scale defaults:

```sh
python tools/qualify_canary_statistics.py \
  --campaigns 20000 --attempts 500 --power-replicates 5000 \
  --tasks 80 --task-families 40 --runs-per-task 4 \
  --lineage-attempts 500 \
  --output qualification/repair-1.3.6/multitask-statistical-qualification.json
```

The null calibration sweeps within-task seed correlation and within-family task correlation over `0.0`, `0.25`, `0.5`, `0.75`, and `0.95`. It includes heteroscedastic family/task variance, heavy-tailed noise, ties, and shared environment noise that cancels under paired evaluation. Each order nuisance is tested at magnitude `0.01`, `0.05`, `0.10`, and `0.25`: first-run and second-run advantages, linear time drift, monotonic load drift, cache warm-up, provider degradation, and family-specific order sensitivity. A combined adverse sequence case sweeps the same magnitudes. The harness reports Wilson intervals, a positive/negative/null power curve at 20, 30, 40, 50, and 60 independent families, experiment-wide null lineages, and a 500-attempt in-memory alpha/panel lineage. Missing or failed authoritative runs are fail-closed by the runtime gate and are exercised by its recovery tests. Source file hashes are included in the output. The tool runs from a Git checkout, source archive, or installed wheel; it resolves source identity from explicit arguments, the bundled release freeze, or Git metadata, then falls back to a local source-file digest without inventing a commit or tree.

This is model-based qualification, not proof that any real panel's declared family clusters are independent or representative. It does not qualify an external anchor or show that AIDE improves across tasks. Those require a fixed real task panel, independently deployed anchor, and hosted platform runs. The earlier 47.8% same-task null result remains a historical finding about the previous run-level inference; it is not treated as evidence for this protocol.

## Statistical epoch changes

The protocol digest, family alpha, fixed attempt horizon, and spending rule are immutable in authenticated state. Changing the test, task/family aggregation, task strata, alpha schedule, practical-effect threshold, or regression limits requires a new statistical epoch with a fresh alpha budget. An old nonzero attempt counter cannot be migrated into this protocol because its previous decisions used a different allocation. Panel data and seed schedules may rotate between attempts only when the previous panel has been consumed and the new task identities and content have not appeared in the retired set.
