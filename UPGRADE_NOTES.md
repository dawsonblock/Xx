# AIDE-DREAM-RSI v1.3.0 Upgrade Notes

Base upgraded artifact: `AIDE-DREAM-RSI-v1.2.0.zip`.

Primary integration source: `LocalJevFabric_v1.5.0_Full_Upgraded_Source.zip`.

Reference decision-schema source: `Jev-1.2.0-Corrected.zip`.

## Main upgrades

- **Bundled LocalJevFabric v1.5.0:** the complete supplied fabric source is included under `vendor/LocalJevFabric-v1.5.0/`.
- **Bounded SystemOne adapter:** `aide/rsi/jev.py` adds typed choice calls for failure classification, legal-action ranking, model-tier routing, verification depth, and connectivity checks.
- **Authority preservation:** JEV cannot create legal actions, alter replay worlds, modify the evaluator, bypass the sandbox, or promote a policy. LocalJevFabric `direct_authorized` metadata is intentionally non-authoritative inside AIDE-RSI.
- **Shadow-first deployment:** all JEV advice is advisory by default. `failure_influence=false` prevents semantic advice from affecting the DREAM policy until an operator explicitly enables it after reviewing evidence.
- **Optional high-confidence repairability:** with `failure_influence=true`, only high-confidence failure classification can refine the existing recovery-versus-abandon decision. Low-confidence or unavailable JEV advice falls back to the deterministic classifier.
- **Replay persistence:** JEV node evidence is serialized in `Node.rsi_jev_advisory`, copied into replay-world schema v3, and replayed without re-querying JEV.
- **Privacy-minimized advisory log:** `jev_advisory.jsonl` stores state hashes and typed evidence, not raw prompts/source code.
- **JEV tooling:** `aide-rsi-jev doctor`, `aide-rsi-jev report`, and `aide-rsi-jev vendor-path` are provided.
- **Replay compatibility:** replay schema v3 adds optional `repairability` and `advisory` fields while keeping v1/v2 worlds loadable.
- **No latent world model:** grounded historical discovery trees remain the only replay worlds.
- **Truthful serial execution:** live discovery remains serial and replay parallel reward remains zero.

## Default JEV posture

```yaml
rsi:
  jev:
    enabled: false
    failure_classification: true
    failure_influence: false
    shadow_action_ranking: true
    shadow_model_routing: false
    shadow_verification_depth: false
```

This gives a low-overhead shadow path: one branch-ranking call per decision and failure classification only when a node fails.

## Validation in this build

- `PYTHONPATH=. pytest -q tests/test_rsi_*.py` — 43 passed.
- bundled LocalJevFabric fabric tests — 57 passed.
- `python -m compileall -q aide tests vendor/LocalJevFabric-v1.5.0/fabric/local_jev_fabric` — passed.
- replay CLI smoke — passed (`build-world` → `evaluate` → `evolve`).
- JEV advisory-report smoke — passed.
- package metadata — `1.3.0`.

## Remaining intentional limitations

- live AIDE discovery is still serial;
- replay cannot estimate unseen branch outcomes;
- JEV branch/model/verification advice is shadow-only in v1.3;
- JEV failure influence is opt-in and not enabled by default;
- actual AnyJev/LLM2Jev model quality depends on the backend configured by the operator;
- strict Bubblewrap/OCI execution must still be integration-tested on the deployment host.
