# AIDE-DREAM-RSI v1.3 Architecture

AIDE-RSI combines AIDE's measured draft/debug/improve loop with the replay-world mechanism from **Dream-RSI: Recursive Self-Improvement through Evolving Worlds**. It does not train a learned latent world model. A completed discovery tree is the replay world; offline policy improvement can reorder recorded exploration, refine different branches, and stop earlier, but cannot invent unseen outcomes.

## Authority split

```text
Immutable authority
├── evaluator / metric semantics
├── execution sandbox policy
├── replay object store + integrity manifest
├── persistent split assignments
├── replay qualification gate
├── repeated paired online canary
└── promotion / transaction state

Recursively improvable boundary
└── typed exploration PolicyGenome DSL
    ├── scoring rule: linear | ucb | trend
    ├── allocation: portfolio | greedy | race
    ├── stopping: threshold | patience | conservative
    └── bounded numeric parameters

Fixed discovery engine
└── AIDE coding agent
    ├── draft
    ├── debug
    └── improve
```

The policy cannot rewrite the evaluator, sandbox, replay pool, split manifest, qualification code, or promotion records.

## One policy implementation for replay and live execution

`AdaptiveReplayPolicy.select_batch()` is the only branch-selection algorithm. `ReplaySimulator` and `LiveExplorationController` only adapt state into that shared interface.

```text
ReplayWorld ── ReplaySimulator ──┐
                                ├── AdaptiveReplayPolicy.select_batch()
AIDE Journal ─ Live adapter ─────┘
```

Replay and live state both expose a `support_score`. It measures whether the *currently revealed prefix* resembles historical prefixes and only adjusts exploration pressure; it does not predict unseen outcomes.

## Recursive loop

```text
incumbent π_t
    │
    ▼
real online AIDE discovery
    │
    ▼
content-addressed discovery world
    │
    ▼
immutable dev / validation / qualification assignments
    │
    ▼
offline typed-policy evolution + beta sweeps
    │
    ▼
aggregate + worst-world held-out replay qualification
    │
    ▼
pending challenger
    │
    ▼
repeated paired real canary
 incumbent vs challenger
 same task state / same budget
 alternating execution order
    │
    ├── fail → retain incumbent
    └── pass → promote challenger
```

## Typed policy DSL

The paper evolves executable exploration-policy code. v1.3 retains a numeric-only genome without granting arbitrary code authority. The DSL contains verified categorical operators plus bounded parameters. Unsupported operator names fail closed during deserialization/bounding.

This permits structural variants such as UCB-style optimism, trend racing, greedy allocation, dynamic portfolios, explicit branch racing, and different stop semantics while keeping the recursive surface non-Turing-complete.

## Replay evidence store

Worlds are canonical JSON objects addressed by SHA-256. `manifest.json` maps immutable logical world IDs to object digests and preserves insertion order. Missing objects, digest mismatches, ID mismatches, or attempts to reuse a world ID for different content fail closed.

## Prefix-only semantics

Replay validates that each non-root node has at most one recorded continuation, matching the current serial live frontier interface. Legal action IDs are opaque and never contain an unrevealed target node ID. No first hidden score is exposed as a baseline.

## Prefix-aware support

`ReplaySupportIndex` indexes prefixes from prior worlds. During live execution, the current revealed Journal prefix is compared against this historical prefix set. During replay evaluation, each world is evaluated against support built from *other* worlds, preventing trivial self-support of 1.0.

The support signal cannot generate a score or continuation. It only increases exploration pressure when current behavior is outside historical support.

## Immutable split epochs

`PersistentSplitManager` persists development, validation, and qualification assignments. Adding worlds cannot move an existing qualification world into development. Qualification data can be recycled only by deliberately starting a new epoch with fresh held-out worlds.

## Qualification

Replay qualification has two held-out checks:

1. aggregate qualification Pareto fitness cannot regress beyond its configured envelope;
2. no individual qualification world may exceed the worst-world regression limit.

Passing replay grants only `pending` status.

## Repeated paired online canary

A pending challenger and incumbent run multiple fresh paired canaries with equal budgets and the incumbent-selected resource grid. Execution order alternates across repetitions. Promotion requires the configured fraction of pairs to pass and the median normalized delta to remain within the regression envelope.

Canary traces are evidence only and are not inserted into the discovery replay pool.

## JEV decision fabric

v1.3 adds an optional LocalJevFabric/SystemOne advisory layer between prefix observation and local semantic classification. The authority split is deliberately asymmetric:

```text
AdaptiveReplayPolicy -> legal search batch and long-horizon allocation
JEV                  -> bounded semantic advice
AIDE                 -> candidate generation
SecureInterpreter    -> execution
Evaluator            -> measured outcome
Qualification/canary -> promotion
```

All JEV decisions are shadow/advisory by default. If `rsi.jev.failure_influence=true` is explicitly enabled, only high-confidence failure repairability may refine recovery classification. JEV legal-action ranking, coder-tier routing, and verification-depth choices remain shadow-only. JEV cannot add an action to the legal set or alter the batch selected by `AdaptiveReplayPolicy`.

Historical JEV failure advice is serialized with the node and copied into replay worlds. Offline replay therefore does not depend on a live JEV call and does not fabricate new semantic decisions for unobserved history.

The full supplied LocalJevFabric v1.5.0 source is bundled under `vendor/LocalJevFabric-v1.5.0/`; it remains an independent service boundary.

## Crash recovery

`rsi/state.json` remains an atomic phase record:

```text
IDLE
CANARY_RUNNING
LIVE_RUNNING
WORLD_COMMITTED
POLICY_EVALUATING
CANDIDATE_PENDING
COMPLETED
```

A partially completed live discovery world can resume from its saved journal. Replay-policy evaluation is deterministic from immutable inputs and can be rerun safely.

## Execution boundary

`SecureInterpreter` strict mode now supports:

- **Bubblewrap** on Linux: namespace isolation, no network, read-only runtime/input, disposable writable workspace, cleared environment, resource limits.
- **OCI container** through Docker or Podman: `--network none`, read-only rootfs, dropped capabilities, no-new-privileges, bounded pids/memory/ulimits, read-only input mount, disposable candidate workspace, and no host credential inheritance.

`auto` prefers Bubblewrap on Linux, then a configured OCI image. If neither strict backend exists, execution fails closed.

`process` mode remains an explicitly insecure trusted-code compatibility path.

## Parallelism

v1.3 still executes one live candidate at a time and forces replay `parallel_bonus=0`. The controller does not claim parallel efficiency until a real isolated worker pool exists.
