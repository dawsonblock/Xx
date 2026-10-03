# DREAM-RSI Paper → v1.3 Implementation Mapping

Source: **Dream-RSI: Recursive Self-Improvement through Evolving Worlds**, arXiv:2609.14858v1 (2026-09-14).

| Paper mechanism | v1.3 implementation | Status |
|---|---|---|
| Online discovery tree | `aide.rsi.runner` + AIDE Agent | Implemented |
| History becomes replay simulator | `ReplayWorld` / `ReplaySimulator` | Implemented |
| Same policy interface online/offline | shared `AdaptiveReplayPolicy` + adapters | Enforced |
| Prefix-only observations | replay/live state adapters | Enforced |
| Stored children revealed without rerunning evaluator | `ReplaySimulator.probe_batch()` | Implemented |
| Quality/work exploration objective | `ReplayEvaluator` | Implemented |
| Policy improvement over history | typed `PolicyEvolutionEngine` + optional constrained LLM proposals | Implemented |
| Structural policy improvement | verified scoring/allocation/stopping DSL | Implemented safely |
| Beta trade-off sweep | beta-grid Pareto fitness + between-cycle beta selection | Implemented |
| Updated policy redeployed online | pending → replay gate → repeated paired canary → incumbent | Implemented with stronger gate |
| Width/depth adaptation | `plan_grid()` | Implemented |
| Failure/recovery trajectory reasoning | shared policy scorer | Implemented |

## Deliberate control-plane extensions

- SHA-256 content-addressed replay evidence;
- immutable split assignments by evaluation epoch;
- aggregate + worst-world replay qualification;
- repeated order-balanced real canaries;
- transactional crash/resume state;
- strict Bubblewrap/OCI candidate sandbox interface;
- prefix-aware replay support that never predicts unseen outcomes;
- one-policy-per-world provenance;
- no parallelism reward until genuine concurrency exists;
- prompt-level cross-round guidance disabled by default.

## Deliberate restriction

The paper evolves executable controller code. v1.3 instead evolves a typed non-Turing-complete controller DSL. This sacrifices some open-ended policy expressiveness in exchange for a much smaller and verifiable recursive authority surface.
