# External RSI state anchor protocol

The runner can detect whole-directory rollback when it is configured with an
independently operated monotonic checkpoint service. Set these environment
variables in the trusted AIDE host process:

```sh
AIDE_RSI_STATE_ANCHOR_URL=https://anchor.example.internal
AIDE_RSI_STATE_ANCHOR_TOKEN=<scoped bearer credential>
AIDE_RSI_STATE_ANCHOR_ID=<stable experiment identifier>
AIDE_RSI_STATE_ANCHOR_TLS_CERT_SHA256=<64 lowercase hex certificate digest>
```

An anchor requires HMAC-authenticated RSI state. The anchor ID must remain the
same if the experiment directory moves. The service must authorize that ID to
this experiment and must not let the client delete, reset, or freely create
replacement IDs. Keep its database and credentials outside the experiment
directory and under a separate administrative boundary. Loopback HTTP is
accepted for local protocol tests; deployed endpoints must use HTTPS and an
out-of-band SHA-256 pin of the anchor's leaf TLS certificate. The client
validates the normal TLS chain and hostname, then checks the exact certificate
pin before sending the bearer credential. HTTPS without the pin fails at
startup. Certificate renewal requires an explicit pin migration; the client
does not learn a replacement certificate from the network.

The first anchored state signs `anchor_required: true` and a SHA-256 identity
of the normalized base URL and configured TLS certificate pin. Every later
load requires the anchor configuration to remain present and match that
identity; removing the URL or TLS pin or pointing it at a replacement endpoint
fails closed. Previously anchored state from the older schema, which did not
store a TLS pin, must be reviewed and re-enrolled rather than silently trusted.
For local loopback HTTP tests there is no TLS pin; do not use that mode for
deployed promotion authority.

## API

`GET /v1/checkpoints/{anchor_id}` returns the latest checkpoint:

```json
{"revision": 12, "sha256": "<64 lowercase hex characters>"}
```

Return HTTP 404 only when the ID has never been initialized. The runner then
sends `PUT /v1/checkpoints/{anchor_id}` after atomically writing signed local
state:

```json
{
  "previous_revision": 12,
  "previous_sha256": "<previous checkpoint hash>",
  "revision": 13,
  "sha256": "<SHA-256 of exact state.json bytes>"
}
```

The server must atomically compare both previous values and require
`revision = previous_revision + 1`; only one concurrent update may win. For a
new ID, the previous revision is zero and previous hash is null. Return 200,
201, or 204 after commit; return 409 on stale or conflicting state. The bearer
token must be scoped to the assigned anchor ID and permit only monotonic
advances. The service should retain an append-only audit trail of every head.

The client reads the remote head before each state transition and on recovery.
It rejects missing local state, older signed snapshots, changed bytes, and
conflicting revisions. If the process crashes after the local atomic write but
before the remote advance, the next run completes that exact signed one-step
advance. A service outage blocks RSI state transitions; it never falls back to
local-only promotion.

This repository includes the client protocol and local HTTP conformance test,
but does not deploy or operate an anchor service. Rollback protection is active
only after an operator provisions a service with the semantics above and sets
all three variables. Protecting a copied experiment under a new anchor ID is
the anchor service's enrollment and authorization responsibility.
