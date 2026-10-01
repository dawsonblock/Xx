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

Canary reservation records bind both policy digests, round, sample IDs, and
repeat count under the host HMAC. This reservation is written before execution,
so a shard remains consumed after a crash. A decision HMAC binds the reservation
file hash, gate settings, paired journal hashes, and the computed gate result.
Recovery checks that transaction policies match durable incumbent and pending
state, verifies every signature and journal hash, and recomputes the gate before
promotion. A plain `passed: true` record has no promotion authority.

Dataset trees are rehashed immediately before and after every authoritative
evaluation. The outer evaluator process has wall-clock, CPU, file-size, process,
open-file, memory, and aggregate scratch limits. The HMAC key is not placed in
the evaluator child's environment. It remains a same-user host secret and is
not protected from compromise of the AIDE process or its account.

## Split independence and reuse

When search and canary share a dataset, the evaluator requires canonical sample
IDs and checks set intersection after Unicode NFC normalization, trimming, and
duplicate rejection. For the first-party tabular adapter it also hashes the
canonical feature row and label without the partition-local sample ID, then
rejects content duplicates across evaluator roles. Custom evaluator formats
receive ID-based checks only unless their adapter implements an equivalent
content identity. Different JSON formatting or different split-file hashes do
not establish sample independence. Canary IDs are committed to HMAC-authenticated
durable state before evaluation, so deleting reservation files cannot restore
them. Rotate to a fresh, disjoint canary shard before further promotion.

An exclusive per-log-directory writer lock prevents concurrent RSI controllers
from producing conflicting transitions. Signed state detects edits, but a full
rollback to an older valid experiment snapshot still requires an external
monotonic checkpoint to detect.

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
