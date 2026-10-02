# Trusted evaluator integration

RSI keeps feedback-model scores advisory. A content-pinned trusted evaluator is
required for publishing measured candidates or promoting a search policy. The
search evaluator and canary evaluator have separate identities and pinned data.
Promotion remains disabled unless both are enabled and the canary split lists
canonical `evaluation_sample_ids` disjoint from search and every previously used
canary shard.

## Candidate and label boundary

The operator-supplied evaluator bundle is trusted code. It can read the hidden
dataset and must not execute candidate code in its own process. For task formats
supported by the first-party tabular adapter, configure
`entrypoint: __aide_reference__`. The adapter copies only configured public
feature files into a strict candidate sandbox, accepts predictions keyed by
sample ID, and scores them in a separate fixed-metric process that receives no
candidate source. The content-pinned adapter process runs outside the outer OS
sandbox on both platforms so it can launch the nested candidate sandbox. It
inherits the evaluator resource limits and does not receive the HMAC key, but
it has host filesystem, process, and network access and remains trusted host
code. Candidate code itself runs under a deny-by-default Seatbelt profile on
macOS or Bubblewrap namespaces on Linux. Its workspace is read-only on both
platforms. Linux provides a size-limited tmpfs at `/tmp`; predictions travel
only over capped stdout. The adapter records the nested candidate process
group in outer scratch so an outer timeout can terminate it, including on
macOS.

The reference adapter supports CSV feature and label files, JSON split manifests,
and the fixed metrics `accuracy`, `mean_squared_error`,
`root_mean_squared_error`, `mean_absolute_error`, and `r2`. The task config names
`labels_file`, `public_files`, optional `id_column` and `label_column`, and
resource limits under `candidate_sandbox` and `scoring`. Candidate stdout must
contain exactly one `{"id": ..., "prediction": ...}` JSON object per pinned
sample. The adapter rejects missing or duplicate sample IDs. Other data formats
can use an operator-reviewed evaluator bundle, which remains responsible for
isolating candidate execution from labels.

## Evidence and recovery authority

Before evaluation, candidate source is stored by SHA-256. Predictions and a
canonical evaluation record are stored in the artifact CAS. The host HMAC binds
the candidate, evaluator, task, dataset, split, environment, prediction digest,
metric, result, and evaluation-record digest. Qualification, publication, and
canary gates require the candidate, prediction, and evaluation objects to exist
and match their hashes.

Canary reservation records bind both policy digests, round, shard authority,
shard identity, shard epoch, sample IDs, candidate-visible sample hashes, and
repeat count under the host HMAC. The signed state retires those identities
before evaluation. If a restart finds a running canary without both its signed
reservation and decision, it abandons the challenger and burns the reserved
shard; it never reruns that shard. A decision HMAC binds the reservation file
hash, gate settings, paired journal hashes, and the computed gate result.
Recovery checks that transaction policies match durable incumbent and pending
state, verifies every signature and journal hash, and recomputes the gate before
promotion. A plain `passed: true` record has no promotion authority.

Dataset trees are rehashed immediately before and after every authoritative
evaluation. The outer evaluator process has wall-clock, CPU, file-size, process,
open-file, memory, and aggregate scratch limits. The HMAC key is not placed in
the evaluator child's environment. It remains a same-user host secret and is
not protected from compromise of the AIDE process or its account.

## Split independence and reuse

Search and canary sample IDs are normalized with Unicode NFC and checked for
overlap. The first-party tabular adapter also computes two identities without
the partition-local sample ID: a candidate-visible hash over sorted relative
file names, sorted columns, and canonical cell values, plus a full record hash
that also binds the label. Candidate-visible hashes are checked across search
and canary data and retired in signed state, so changing labels cannot conceal
reused candidate inputs. Duplicate candidate-visible rows within a shard are
rejected. Custom evaluator formats receive ID-based checks only unless their
adapter implements equivalent content identities.

Rotate a canary by changing its pinned split/data and incrementing
`rsi.canary_evaluator.shard_epoch` by exactly one. The stable evaluator authority
identity excludes the rotating dataset and split, while the full shard identity
is recorded in signed state and each transaction. The runner rejects a changed
authority, a skipped/reused epoch, overlap with search samples, or reuse of
retired IDs and content hashes. The shard epoch is committed only after those
checks pass.

An exclusive per-log-directory writer lock prevents concurrent RSI controllers
from producing conflicting transitions. Signed state detects edits, but a full
rollback to an older valid experiment snapshot still requires an external
monotonic checkpoint to detect. The optional external anchor client is enabled
with `AIDE_RSI_STATE_ANCHOR_URL`, `AIDE_RSI_STATE_ANCHOR_TOKEN`, and a stable
`AIDE_RSI_STATE_ANCHOR_ID`. HTTPS anchors also require an out-of-band leaf
certificate fingerprint in `AIDE_RSI_STATE_ANCHOR_TLS_CERT_SHA256`. The client
checks the standard TLS chain and hostname, then verifies this exact pin before
sending the bearer token. The first anchored state binds the normalized URL
and pin, and later launches fail closed if either is absent or changed. Pin
renewal requires operator action; loopback HTTP remains for protocol tests
only.
See [the anchor protocol](STATE_ANCHOR_PROTOCOL.md) for the required server
semantics. This repository supplies the client and protocol tests, not a
deployed checkpoint service.

## Canary promotion statistics

General policy promotion uses an immutable multi-task `CanaryPanel`. Each panel
contains at least 20 distinct task identities from at least 20 independent
task-family clusters, with exactly four paired runs per task. It also fixes
at least three broad task strata, with at least three independent families per
stratum and no stratum above half the family clusters. Incumbent and challenger are run with the same
fixed task seed and budget; execution order is fixed by canonical task position,
not caller-supplied replicate IDs. Each task uses an exact ABBA or BAAB schedule,
so both policies run first twice and second twice. The median normalized paired effect within each task
is the task-level estimate; correlated task estimates in the same family are
reduced to one median family effect. A one-sided exact sign test then operates
across independent family effects, with ties at the practical-effect threshold
counted as non-wins. Seeds estimate within-task variation and never increase
the nominal independent-family count.

The gate also requires the configured minimum median task effect and rejects a
panel if any task exceeds the maximum regression limit. Families are
predeclared dependence clusters and receive equal weight; strata are
predeclared for domain balance. Panel composition, evaluator/shard identities,
sample hashes, seed schedule, run budgets, metric definition, execution order,
protocol digest, statistical epoch, and allocated alpha are authenticated
before any score is observed. Protocol V4 fixes a 500-attempt Bonferroni
horizon with `alpha_i = family_alpha / 500`; attempt 501 is rejected. A
reservation spends alpha before execution and cannot be refunded. A missing or
incomplete signed decision burns the panel rather than retrying it. Recovery
verifies journal hashes and recomputes task and family effects, including the
exact critical family count required at the reserved alpha.

The statistical protocol assumes genuinely independent family clusters and
valid paired outcomes. The synthetic calibration suite tests correlated runs
within tasks and correlated task effects within families; it does not establish
that an operator's real family panel is independent or representative. If two
families share a plausible outcome shock, they must be combined as one
inference cluster. Provider-side LLM randomness may remain uncontrolled even
though the local Python/NumPy seed schedule is fixed. Real multi-task controls
and long-run power/generalization qualification remain release gates.

Replay development, validation, and qualification worlds are trajectory splits,
not independent data holds. Replay qualification reuses measured scores and
does not establish untouched generalization. The live canary is the independent
sample gate, and repeated access is prevented by one-use shard accounting.

## Configure a task

Pin the bundle, config, dataset tree, split manifest, and evaluator environment:

```python
from aide.rsi.trusted_evaluator import file_sha256, tree_sha256

print("bundle_sha256:", tree_sha256("/secure/evaluator-bundle"))
print("config_sha256:", file_sha256("/secure/evaluator-config.json"))
print("dataset_sha256:", tree_sha256("/secure/hidden-data"))
print("split_sha256:", file_sha256("/secure/split.json"))
print("environment_manifest_sha256:", file_sha256("/secure/requirements.lock"))
```

For the first-party adapter, set `entrypoint: __aide_reference__` in both the
operator's evaluator configuration and the pinned config file. The bundle still
needs a valid content pin. Its config file should follow this shape:

```json
{
  "labels_file": "labels.csv",
  "public_files": ["features.csv"],
  "scoring": {"id_column": "id", "label_column": "label"},
  "candidate_sandbox": {
    "timeout_s": 300,
    "memory_mb": 1024,
    "max_output_mb": 64
  }
}
```

The split manifest must include a nonempty list such as
`{"evaluation_sample_ids":["sample-001", "sample-002"]}`. Both evaluator roles
must use the same task and metric direction, and the canary IDs must be disjoint
from search IDs. Keep the dataset, config, bundle, split, and environment lock
read-only. Set `AIDE_RSI_EVALUATION_HMAC_KEY` in the AIDE host environment to at
least 32 random bytes.

Changes in this hardening branch are unreleased source updates on the existing
v1.3.5 line. Version and package metadata remain at 1.3.5 until a release is
prepared and validated.
