# v1.5.0 upgrade report

v1.4 proved staged deployment behavior. v1.5 focuses on evidence independence, backend economics and post-incident reproducibility.

The main security change is that direct authority no longer relies only on evidence generated inside the same promotion trust domain. It now requires an independent Ed25519 evaluator qualification and a separate Ed25519 artifact-supply-chain attestation, both bound into the authenticated registry and enforced by gateway authority-envelope v4.

The main routing change is a non-authoritative capability manifest with cost-aware ranking/escalation. This is intentionally unable to weaken fail-closed specialist policy or grant direct execution.

The main operational change is sanitized replay plus incident bundles and content-free telemetry. This improves diagnosability without turning the observability plane into a second copy of user prompts or private state.
