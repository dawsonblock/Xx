# Trusted evaluator integration

v1.3.3 added the host-owned protocol for task-specific external evaluators.
v1.3.4 added separate canary data. This version runs evaluator subprocesses
inside an OS sandbox. The
repository does not ship a hidden-label evaluator because the data format,
prediction interface, split, and metric belong to each task. With the default
configuration, feedback-model scores remain advisory and policy promotion stays
disabled.

## Trust boundary

The operator must review the evaluator implementation and its environment. Set
`sandbox_backend` to `auto`, `seatbelt`, or `bubblewrap`; `auto` chooses the
supported native backend and never falls back to an unrestricted process. For
each candidate, the runner invokes the pinned evaluator bundle inside macOS
Seatbelt or Linux Bubblewrap. `auto` selects the native local backend and fails
closed if it is unavailable. The process receives read access to its Python
runtime, pinned bundle and task inputs, and read/write access to a temporary
scratch directory. Network access is denied. Linux uses private namespaces and
a private `/proc`; macOS uses a deny-by-default Seatbelt profile. The evaluator
receives a per-evaluation candidate snapshot, and the host checks its digest
afterward.

The evaluator must load that exact candidate and run it on its task data and
split. It must compute the metric from its own predictions and labels; it must
never accept a metric printed by the candidate or copied from the AIDE journal.
The OS sandbox limits the evaluator's access to the host, but the task dataset
is intentionally readable by the evaluator. Candidate execution inside it is
still untrusted and must not receive hidden labels. A task evaluator that uses
`exec(candidate)` or launches Python directly can expose its mounted labels to
candidate code. It must invoke the candidate through `SecureInterpreter` or an
equivalent separately qualified confinement layer.

The host applies a wall timeout, CPU limit, and per-file output limit. Linux
also applies a per-process address-space limit. macOS samples evaluator resident
memory and kills the process if it exceeds `max_memory_mb`; this sample does not
sum memory used by evaluator grandchildren. The aggregate scratch monitor
limits files under the temporary directory. Keep pinned inputs read-only and
unchanged while the run is active.

The evaluator returns predictions' digest and a numeric score. The host checks
all pinned identities and creates the HMAC attestation after the process
returns. Python is launched with `-B` and `PYTHONDONTWRITEBYTECODE=1`; `-B` is
needed because isolated mode (`-I`) ignores `PYTHON*` environment variables.
The host requires the bundle to have no write permission bits as an additional
integrity check. The sandbox also mounts or exposes it read-only.

The evaluator receives the following JSON request through `--request PATH` and
writes one JSON response to `--response PATH`:

```json
{
  "schema_version": 1,
  "candidate_sha256": "...",
  "candidate_path": "/.../artifacts/sha256/.../...py",
  "task_sha256": "...",
  "evaluator_sha256": "...",
  "evaluator_config_sha256": "...",
  "evaluator_config_path": "/.../task-evaluator.json",
  "dataset_sha256": "...",
  "dataset_dir": "/.../private-evaluation-data",
  "split_sha256": "...",
  "split_manifest_path": "/.../evaluation-split.json",
  "environment_sha256": "...",
  "metric_id": "accuracy",
  "metric_maximize": true,
  "output_dir": "/.../predictions"
}
```

The response must contain exactly these keys:

```json
{
  "schema_version": 1,
  "candidate_sha256": "...",
  "task_sha256": "...",
  "evaluator_sha256": "...",
  "evaluator_config_sha256": "...",
  "dataset_sha256": "...",
  "split_sha256": "...",
  "environment_sha256": "...",
  "metric_id": "accuracy",
  "metric_maximize": true,
  "score": 0.91,
  "predictions_sha256": "..."
}
```

Every echoed identity must match the request. Scores must be finite JSON numbers,
and the prediction digest must be a lowercase SHA-256 hex string equal to the
host-computed SHA-256 of `output_dir/predictions.jsonl`. The evaluator must write
the serialized predictions it actually scored to that file. A per-file limit
and aggregate scratch monitor enforce `max_output_mb` inside the evaluator's
temporary directory. The OS profile restricts writes to that scratch directory.
A limit breach, timeout, malformed output, digest mismatch, or evaluator error
marks the node unscored. The runner
does not fall back to feedback-model scoring when trusted evaluation is enabled.
After verification, predictions and the signed evaluation record are persisted
under `<log_dir>/rsi/artifacts/predictions/sha256/` and
`<log_dir>/rsi/artifacts/evaluations/sha256/`. Node provenance includes both
artifact digests.

The HMAC key is removed from the evaluator child's environment. The Linux
private PID namespace and macOS deny-by-default profile also block ordinary
inspection of the host process. The key still belongs to the AIDE user account;
this is not a separate-UID signer service or hardware-backed key boundary.

The replay split separates worlds, not the underlying task data. Discovery
scores are adaptive search feedback; replay validation and qualification reuse
those scores and do not establish untouched data generalization. A configured
`rsi.canary_evaluator` is used for both sides of every live canary and must match
the task metric while pinning a different dataset or split from
`rsi.trusted_evaluator`. If it is omitted, canary runs have no trusted scores
and cannot promote a policy. Separate validation and one-shot qualification
data authorities with query limits are still not implemented.

The host does not independently recompute the task metric from labels and
predictions. It trusts the pinned evaluator to calculate the score correctly
and verifies that the prediction file matches the returned digest. Environment
identity includes the pinned manifest, Python executable/version, platform
string, sandbox backend, restricted evaluator `PATH`, evaluation limits, and
installed Python distributions, but does not bind an OS/container image digest,
system libraries, GPU driver, or the contents of executables reachable through
the allowed system runtime paths.

## Configure a task

Prepare an evaluator bundle with an `evaluate.py` entrypoint, a separate task
configuration file, a read-only hidden dataset directory, an immutable split
manifest, and a lock/manifest for the evaluator Python environment. Compute the
content pins with the public helpers:

```python
from aide.rsi.trusted_evaluator import file_sha256, tree_sha256

print("bundle_sha256:", tree_sha256("/secure/evaluator-bundle"))
print("config_sha256:", file_sha256("/secure/evaluator-config.json"))
print("dataset_sha256:", tree_sha256("/secure/hidden-data"))
print("split_sha256:", file_sha256("/secure/split.json"))
print("environment_manifest_sha256:", file_sha256("/secure/requirements.lock"))
```

Set the resulting paths and digests under `rsi.trusted_evaluator`, along with a
fixed `metric_id`, `metric_maximize`, an evaluation `timeout_s`, and a
`max_output_mb` scratch budget. Set
`AIDE_RSI_EVALUATION_HMAC_KEY` in the AIDE host environment to at least 32
random bytes. The key is omitted from the evaluator subprocess environment, but
same-UID process inspection can bypass that filtering on some systems. Mount the
evaluator bundle read-only and keep the config, dataset, split, and environment
manifest immutable while a run is active.

The recorded environment identity includes the manifest digest, Python
executable digest/version, platform string, PATH value, evaluation limits, and
installed distribution names/versions. The operator still needs to ensure that
manifest describes the installed evaluator environment. Start a fresh
experiment when changing any evaluator identity;
the runner rejects identity changes when resuming an existing run.

To permit trusted policy promotion, configure `rsi.canary_evaluator` with an
independently pinned evaluator and dataset or split. It must use the same metric
name and direction as the search evaluator. Reusing the same dataset and split
digests for both roles is rejected. Separate pins do not replace the evaluator's
candidate sandbox: the evaluator must still prevent candidate code from reading
hidden labels or host credentials.

`sandbox_backend` defaults to `auto`, which selects Seatbelt on macOS and
Bubblewrap on Linux. Trusted evaluation fails to initialize if the selected
strict backend is unavailable. Set `max_memory_mb` for the evaluator process
along with `timeout_s` and `max_output_mb` for each evaluator role.

## Example response implementation

The evaluator entrypoint should follow this outline. `run_candidate_safely`
and `score_predictions` are task-specific functions that must be supplied by
the operator's reviewed bundle.

```python
import hashlib

request = json.loads(Path(args.request).read_text())
predictions = run_candidate_safely(
    Path(request["candidate_path"]),
    Path(request["dataset_dir"]),
    Path(request["split_manifest_path"]),
    Path(request["output_dir"]),
)
score = score_predictions(predictions, hidden_labels)
predictions_path = Path(request["output_dir"]) / "predictions.jsonl"
predictions_path.write_text(serialize_canonical_jsonl(predictions))
predictions_sha256 = hashlib.sha256(predictions_path.read_bytes()).hexdigest()
response = {key: request[key] for key in IDENTITY_KEYS}
response.update(
    schema_version=1,
    score=float(score),
    predictions_sha256=predictions_sha256,
)
Path(args.response).write_text(json.dumps(response))
```

This protocol provides an integration point and host-side identity checks. The
correctness and confidentiality of a task evaluator still depend on its review,
its candidate sandbox, its data contract, and its environment qualification.
