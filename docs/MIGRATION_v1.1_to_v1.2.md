# Migration: v1.1.0 → v1.2.0

v1.2 is backward compatible with v1.1 replay pools and policy JSON.

## Policy files

Existing v1.1 policies load unchanged. Missing structural fields default to:

```yaml
score_rule: linear
allocation_rule: portfolio
stop_rule: threshold
ucb_weight: 0.35
race_min_roots: 3
```

New policies may safely evolve among the verified structural operators. Unknown operator values fail closed.

## Canary configuration

New defaults:

```yaml
rsi:
  canary:
    attempts: 4
    repeats: 3
    min_pass_fraction: 0.66
```

Each repetition runs a fresh paired incumbent/challenger canary. Order alternates by repetition.

## Qualification

New option:

```yaml
rsi:
  evolution:
    max_single_world_regression: 0.05
```

This is applied in addition to aggregate qualification replay regression.

## Strict sandbox on macOS/Windows

Build the OCI image:

```bash
make sandbox-image
```

Then configure:

```yaml
rsi:
  sandbox:
    mode: strict
    backend: container
    container_runtime: auto
    container_image: aideml-rsi-sandbox:1.2.0
```

Linux `backend=auto` still prefers Bubblewrap when installed.

## Replay support

`ood_explore_boost` now operates on prefix-level historical support in both replay and live execution. No migration is required.
