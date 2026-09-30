# JEV Integration — v1.3

## Purpose

LocalJevFabric is used as a bounded semantic decision service inside AIDE-DREAM-RSI. It is not the long-horizon planner and it is not an authority source.

```text
Exploration prefix
      |
      +--> AdaptiveReplayPolicy ------> legal DREAM batch (authoritative search decision)
      |
      +--> LocalJevFabric ------------> advisory typed decisions
                                           |
                                           +-- failure repairability (may influence recovery if confidence gate passes)
                                           +-- legal-action ranking (shadow only)
                                           +-- coder tier recommendation (shadow only)
                                           +-- verification depth (shadow only)
```

The evaluator, replay pool, qualification gate, canary, sandbox, and promotion state remain outside JEV authority.

## Why this boundary

The DREAM-RSI replay loop learns long-horizon allocation from grounded historical discovery worlds. JEV is better suited to local bounded classification/routing questions. Mixing JEV directly into replay branch selection would change replay/live semantics and make offline dreaming depend on a live model service. v1.3 therefore keeps branch-control authority in the shared deterministic policy.

## Typed questions

The adapter uses these question IDs:

- `dream.failure_class.v1`
- `dream.branch_action.v1`
- `dream.model_route.v1`
- `dream.verification_depth.v1`
- `dream.doctor.v1`

Failure classification choices are:

- `repairable_implementation`
- `resource_or_timeout`
- `environment_dependency`
- `structural_algorithm`
- `uncertain`

By default all answers are advisory only. If an operator explicitly sets `rsi.jev.failure_influence=true`, answers at or above `rsi.jev.confidence_threshold` may resolve repairability. Low-confidence or unavailable answers always fall back to the existing deterministic classifier.

## Privacy and evidence

The adapter does not send candidate source code by default. Failure classification sends an allowlisted failure class, fixed diagnostic signal names, and presence flags; raw error and analysis text stay local. Other shadow questions use compact branch/evaluation metadata, plan summaries, and task digests. Common API-key/token patterns are redacted and payloads are length bounded.

`jev_advisory.jsonl` stores state hashes, choices, confidence, probabilities, request IDs, backend identifiers, and fabric evidence digests. Raw state is not written by the advisory logger.

Each node serializes `rsi_jev_advisory`, so crash/resume and the resulting replay world preserve the exact bounded evidence used online. Replay never re-calls JEV for historical node classification.

## Fail-open semantics

Default:

```yaml
rsi:
  jev:
    enabled: false
    failure_influence: false
    fail_open: true
```

With `fail_open: true`, a fabric timeout/HTTP/schema failure produces an advisory error record and deterministic AIDE-DREAM-RSI continues.

With `fail_open: false`, advisory-service failure terminates the run. Use this only if JEV availability is itself a deliberate system requirement.

## Bundled LocalJevFabric

The complete supplied `LocalJevFabric-v1.5.0` source is included at:

```text
vendor/LocalJevFabric-v1.5.0/
```

The bundle contains AnyJev, LLM2Jev, the Jev gateway, registry/audit/qualification tooling, and the `/v1/systemone` fabric service. It does not contain TypeSafe Jev weights.

Install the fabric layer:

```bash
make install-jev
```

Then configure at least one backend according to the bundled LocalJevFabric README and run:

```bash
local-jev-fabric
```

Test AIDE-side connectivity:

```bash
aide-rsi-jev doctor
```

Review accumulated shadow evidence before enabling influence:

```bash
aide-rsi-jev report /path/to/logs
```

## Promotion rule

A JEV recommendation is never sufficient for policy or artifact promotion. Promotion still requires replay qualification and the paired real incumbent/challenger canary. Even a LocalJevFabric response that carries its own `direct_authorized=true` metadata is treated as non-authoritative by the AIDE adapter.
