# Migration: v1.2.x to v1.3.0

v1.3.0 upgrades the task registry schema from v2 to v3 and the direct-execution authority envelope from v2 to v3.

## Non-direct routes

v2 registries containing only normal specialist/generalist routes can be loaded and rewritten by v1.3. The next registry mutation emits schema v3.

## Existing v2 direct-authorized routes

They are intentionally **not grandfathered**. A v2 direct route lacks a signed held-out qualification binding, so v1.3 refuses to load it as direct authority.

For each direct route:

1. Start the exact AnyJev specialist that the route is intended to use.
2. Produce independent held-out evaluation results.
3. Run `jev-fabric-promotion qualify` with `FABRIC_PROMOTION_HMAC_KEY`.
4. Promote the task with `jev-fabric-promotion promote --direct-authorized --approve` using the registry HMAC key.
5. Advance/update the registry checkpoint after verifying the new revision.

Do not edit the old route by hand to add a fake qualification hash. The point of v3 is that the digest corresponds to an HMAC-authenticated qualification artifact bound to the live specialist.

## Gateway

v1.3 jev-gateway requires `authority_version >= 3` for direct execution. v2 fabric authority metadata is treated as advisory and will fall back to normal LLM-mediated execution.

## New optional configuration

```bash
FABRIC_PROMOTION_JOURNAL=./logs/jev-fabric-promotion.jsonl
FABRIC_PROMOTION_HMAC_KEY=<separate secret used offline by qualification CLI>
```

The promotion journal is optional and non-authoritative. The promotion key should be separate from both the registry key and audit checkpoint key.
