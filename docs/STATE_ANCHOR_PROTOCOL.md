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

## Reference service

The repository includes a small standard-library service in
[`rsi_anchor_service.py`](../rsi_anchor_service.py). It stores the current head
and an append-only transition history in SQLite, commits each update in one
`BEGIN IMMEDIATE` transaction, and uses WAL mode with `synchronous=FULL`. The
compare-and-swap checks both the previous revision and digest, then requires an
exact one-step advance. Concurrent writers therefore cannot both commit the
same expected head. The service verifies SQLite integrity and walks the history
chain before starting. The HTTP API has no reset or delete operation. Local
development may use loopback HTTP; any non-loopback listener requires a TLS
certificate and key.

Provision one random token for each experiment ID. Keep the bearer token in the
experiment host's secret manager; the service's private authorization file
contains only its SHA-256 digest:

```sh
python rsi_anchor_service.py token experiment-001
# Securely retain the emitted token. Put only its sha256 value in this file:
# {"experiment-001":"<64 lowercase hex characters>"}
chmod 600 /etc/aide-rsi/anchor-auth.json
python rsi_anchor_service.py serve \
  --database /var/lib/aide-rsi-anchor/checkpoints.sqlite3 \
  --auth-file /etc/aide-rsi/anchor-auth.json \
  --host 0.0.0.0 --port 8765 \
  --tls-certificate /etc/aide-rsi-anchor/fullchain.pem \
  --tls-private-key /etc/aide-rsi-anchor/private-key.pem
```

The auth file maps stable anchor IDs to token digests, so credentials are
scoped to one experiment. Unknown IDs and invalid credentials receive the
same not-found response. The database and auth file must live outside the
experiment directory and be administered separately. Use TLS with a normal
validated certificate chain and configure the client with the exact
out-of-band leaf-certificate SHA-256 pin. Never put tokens in command history,
process arguments, service logs, or the experiment directory.

After generating the authorization file, restrict it to the service account
and mode `0600` (or stricter). The service refuses a symlinked or group/world
readable authorization file and refuses a symlinked or non-regular database.
The SQLite file is set to mode `0600`; run the process with a restrictive
umask so its WAL and shared-memory files are private as well.

SQLite is a single-host reference backend, not a substitute for a separately
operated service boundary. The database owner can still replace the entire
database, and a stale database restore can roll back the anchor itself. Keep
the service host, credentials, storage, and tested backups independent of the
experiment host; protect backup generations with a separate monotonic or
administrative control. For multi-host failover, use a PostgreSQL-backed
implementation with transaction-scoped row locking and the same wire contract.
Do not copy a live SQLite database file as a backup; use SQLite's online backup
API and qualify restore behavior before relying on it.

The repository now includes a local service conformance suite and an
end-to-end test that advances 100 signed state revisions, restores revision
20, and verifies startup fails before further RSI work. Those tests qualify
the implementation locally; they do not mean this service has been deployed
or independently operated. Rollback protection is active only when an
operator provisions and monitors an external service and configures all anchor
variables. Protecting a copied experiment under a new anchor ID remains the
service enrollment and authorization responsibility.
