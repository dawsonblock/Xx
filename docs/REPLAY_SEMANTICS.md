# Replay Semantics and Invariants — v1.3

## Grounded-only rule

A replay action may reveal only a node already present in the immutable `ReplayWorld`. No transition model and no synthetic continuation exists.

## Shared-policy rule

Replay and live discovery call the same `AdaptiveReplayPolicy.select_batch()` implementation. Adapters may translate state representation but may not reimplement ranking, allocation, or stopping logic.

## Typed-policy rule

Structural policy evolution is restricted to verified operator enums and bounded scalar parameters. Unknown scoring/allocation/stopping operators fail closed. Arbitrary generated controller Python is not executed.

## Prefix-only rule

Policy-visible state contains only revealed observations, opaque legal actions, metric direction, explicit public baseline if any, effective worker count, and replay-support coverage derived from revealed structure. Hidden node scores/IDs are not exposed.

## Replay-support rule

Support is a similarity/coverage signal over historical **prefixes**. It is not an outcome model. In replay, the evaluated world is excluded from its own support index. In live execution, only prior committed worlds populate the support index.

## Batch rule

- action IDs are unique;
- a batch may not exceed effective worker count;
- each non-root node has at most one recorded continuation in a replayable world;
- a parent cannot be refined twice in one replay round;
- root slots have distinct opaque IDs;
- width caps count already-open roots plus legal root slots.

Current live execution has effective parallelism 1, so replay receives no parallelism bonus.

## Failure rule

One failed implementation does not prove a direction is bad. Compile/runtime/resource/evaluation failures may remain repairable. Hard external failures are penalized more strongly. Recovery cannot permanently starve ordinary exploration.

## Split rule

Development, validation, and qualification membership is persisted per split epoch and never migrates as the pool grows.

## Integrity rule

Worlds are content-addressed by SHA-256. Logical IDs are immutable. Missing/corrupt objects fail closed. Legacy standalone worlds require a matching SHA-256 sidecar.

## Qualification rule

Replay qualification checks validation margin, aggregate held-out qualification regression, and worst-single-world qualification regression. Passing grants only `pending` status.

## Canary rule

Promotion requires repeated paired real incumbent/challenger canaries. Every pair receives equal budgets and fresh equivalent workspaces; execution order alternates across repetitions. The configured pass fraction and median-regression gate must both pass.

## Resume rule

A committed replay world is never regenerated after restart. A partially completed live world may resume only through the original experiment log (`rsi.resume_log_dir`).
