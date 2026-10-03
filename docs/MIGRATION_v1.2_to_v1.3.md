# Migration: v1.2.0 → v1.3.0

v1.3 is backward compatible with v1.2 replay worlds and policy genomes.

## Replay schema

Replay-world schema advances to version 3 by adding optional node fields:

```text
repairability
advisory
```

v1/v2 worlds remain loadable; absent fields receive safe defaults.

## Journal schema

AIDE `Node` adds the serialized field `rsi_jev_advisory`. Existing journals load with an empty default.

## Configuration

New optional section:

```yaml
rsi:
  jev:
    enabled: false
    endpoint: http://127.0.0.1:8090/v1/systemone
    model: local-jev-fabric
    api_key_env: FABRIC_API_KEY
    timeout_s: 1.5
    confidence_threshold: 0.72
    fail_open: true
    max_state_chars: 12000
    failure_classification: true
    failure_influence: false
    shadow_action_ranking: true
    shadow_model_routing: false
    shadow_verification_depth: false
```

No JEV service is required when `enabled=false`.

## Authority behavior

v1.3 does not hand branch-control or promotion authority to JEV. High-confidence failure repairability is the only JEV signal allowed to influence the shared DREAM policy. All other JEV outputs are shadow evidence.

## Bundled source

The supplied LocalJevFabric v1.5.0 source is vendored under `vendor/LocalJevFabric-v1.5.0/` for a self-contained integration artifact.
