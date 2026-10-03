# Migration: v1.3 -> v1.4

1. Registry schema v3 remains loadable. The next signed write emits schema v4.
2. Existing bindings become `deployment_stage=stable` in memory; behavior is unchanged.
3. New CLI promotions default to `shadow`. Supply `--deployment-stage stable` only when deliberately bypassing staged rollout; direct authority still requires stable mode.
4. Configure `FABRIC_SHADOW_JOURNAL` to collect shadow/canary comparison evidence.
5. Configure `FABRIC_OUTCOMES` if external agents/test harnesses can provide labels.
6. Build a drift reference with `jev-fabric-drift` before enabling `FABRIC_DRIFT_PROFILE`.
7. Use `jev-fabric-rollout` for shadow -> canary -> stable transitions. All transitions are signed higher registry revisions.
8. Add `jev-fabric-benchmark` to release qualification and keep `--max-false-direct-rate 0` for any environment where direct execution is enabled.

No gateway authority-envelope migration is required: v1.4 retains authority envelope v3. Rollout and drift are enforced before the envelope can assert direct authority.
