# Trusted evaluator integration

v1.3.2 adds a host-owned protocol for task-specific external evaluators. The
repository does not ship a hidden-label evaluator because the data format,
prediction interface, split, and metric belong to each task. With the default
configuration, feedback-model scores remain advisory and policy promotion stays
disabled.

## Trust boundary

The operator must review the evaluator implementation and its environment. For
each candidate, the runner invokes the pinned evaluator bundle in a fresh Python
subprocess. The evaluator must load the exact content-addressed candidate and
run it on its own task data and split. It must compute the metric from its own
predictions and labels; it must never accept a metric printed by the candidate
or copied from the AIDE journal. Candidate execution inside the evaluator is
untrusted and must receive no hidden labels, credentials, or unrestricted host
access. The evaluator subprocess itself is not an OS sandbox: it runs as the
user and can read files available to that account. The evaluator bundle must
invoke the candidate through `SecureInterpreter` or an equivalent separately
qualified confinement layer. AIDE enforces a timeout and kills the evaluator's
process group, but does not set its memory or CPU limits. Keep the hidden dataset
tree read-only and unchanged while the run is active.

The evaluator returns predictions' digest and a numeric score. The host checks
all pinned identities and creates the HMAC attestation after the process
returns. The attestation key is not included in the evaluator subprocess
environment.

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
the serialized predictions it actually scored to that file. Nonzero exit,
timeout, malformed output, digest mismatch, or evaluator error marks the node
unscored. The runner does not fall back to feedback-model scoring when trusted
evaluation is enabled.

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
fixed `metric_id`, `metric_maximize`, and an evaluation `timeout_s`. Set
`AIDE_RSI_EVALUATION_HMAC_KEY` in the AIDE host environment to at least 32
random bytes. The key is used only by the host; it is omitted from the child
environment. Keep the evaluator bundle, config, dataset, split, and environment
manifest immutable while a run is active.

The recorded environment identity includes the manifest digest, Python
executable digest/version, and installed distribution names/versions. The
operator still needs to ensure that manifest describes the installed evaluator
environment. Start a fresh experiment when changing any evaluator identity;
the runner rejects identity changes when resuming an existing run.

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
