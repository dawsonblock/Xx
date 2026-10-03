# Local fabric hardening

This integrated copy adds four policies on top of the supplied gateway:

1. A loopback `JEV_URL` can be used without a hosted-provider API key, allowing LocalJevFabric/LLM2Jev to be the decision service. A keyless non-loopback Jev URL is rejected.
2. Non-loopback gateway binds require `ROUTER_API_KEY` unless an explicit insecure override is supplied.
3. Tool decisions pass through `JEV_TOOL_RISK_JSON` / `JEV_UNKNOWN_TOOL_RISK`. Jev confidence is evidence, never authorization.
4. With `JEV_DIRECT_REQUIRE_AUTHORITY=true` (default), R0 direct calls require a complete LocalJevFabric **v2 authority envelope**. The gateway requires an authenticated registry flag, 64-hex registry/evidence digests and non-empty per-question decisions whose `authority`, `attestation_verified` and calibrated score semantics all agree. A bare `direct_authorized=true` is rejected.

Risk classes: R0 read-only, R1 reversible/local mutation, R2 external side effect, R3 destructive/privileged. Unknown defaults to R1.
