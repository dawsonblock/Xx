# Migrating v1.1 → v1.2

Existing generalist routes continue to work. Existing direct-authorized specialist routes need one deliberate upgrade because v1.2 verifies live calibration evidence.

1. Keep the existing AnyJev artifact bundle and pinned model revision.
2. Produce/freeze the held-out evaluation report that justified the task threshold.
3. Restart AnyJev with `--calibration-report <report>` and `--require-level L2`.
4. Re-bind each direct-authorized exact question with `jev-fabric-bind-specialist ... --min-score <validated-threshold> --direct-authorized`. This updates the registry with the live calibration evidence digest.
5. Re-sign the registry if required; the binder does this automatically when `FABRIC_REGISTRY_HMAC_KEY` is present.
6. Optionally configure `FABRIC_REGISTRY_CHECKPOINT` and an external `FABRIC_REGISTRY_MIN_REVISION` floor.
7. Optionally configure `FABRIC_AUDIT_HMAC_KEY` + `FABRIC_AUDIT_CHECKPOINT`.
8. Run `jev-fabric-doctor` before enabling gateway routing.

The gateway direct path now expects a v2 authority envelope. If a v1.1 fabric is left in front of the v1.2 gateway, direct execution is downgraded to the normal forced/LLM path rather than being trusted.
