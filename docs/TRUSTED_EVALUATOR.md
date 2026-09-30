# Trusted evaluator integration

v1.3.3 adds a host-owned protocol for task-specific external evaluators. The
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
access. AIDE does not enforce this second execution boundary; an evaluator that
uses `exec(candidate)` or launches Python directly can expose hidden labels and
the host account to candidate code. The evaluator subprocess itself is not an
OS sandbox: it runs as the user and can read files available to that account.
The evaluator bundle must invoke the candidate through `SecureInterpreter` or
an equivalent separately qualified confinement layer. AIDE enforces a timeout
and kills the evaluator's process group, but does not set its memory or CPU
limits. A child that deliberately starts a new session can escape process-group
cleanup; the evaluator must remain trusted code. Keep the hidden dataset tree
read-only and unchanged while the run is active.

The evaluator returns predictions' digest and a numeric score. The host checks
all pinned identities and creates the HMAC attestation after the process
returns. Python is launched with `-B` and `PYTHONDONTWRITEBYTECODE=1`; `-B` is
needed because isolated mode (`-I`) ignores `PYTHON*` environment variables.
The host requires the bundle to have no write permission bits, but mode bits
alone are not an OS boundary against a hostile same-UID process. Mount the
bundle read-only for deployment.

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
temporary directory. This does not restrict writes elsewhere because the
evaluator is not OS-sandboxed. A limit breach, timeout, malformed output,
digest mismatch, or evaluator error marks the node unscored. The runner
does not fall back to feedback-model scoring when trusted evaluation is enabled.
After verification, predictions and the signed evaluation record are persisted
under `<log_dir>/rsi/artifacts/predictions/sha256/` and
`<log_dir>/rsi/artifacts/evaluations/sha256/`. Node provenance includes both
artifact digests.

The HMAC key is removed from the evaluator child's inherited environment. This
does not isolate it from a same-UID child: on common Linux configurations, the
child can inspect the parent process environment through `/proc`. The HMAC is a
record integrity check under a trusted host process, not a process security
boundary. Strong signer isolation needs a separate restricted UID or signing
service, which this implementation does not provide.

The replay split separates worlds, not the underlying task data. One configured
evaluator identity is queried during discovery and canary. Those scores are
adaptive search feedback and do not establish untouched generalization. Strong
generalization claims require separate pinned search, validation, qualification,
and canary data authorities with query limits; that multi-authority workflow is
not implemented here.

The host does not independently recompute the task metric from labels and
predictions. It trusts the pinned evaluator to calculate the score correctly
and verifies that the prediction file matches the returned digest. Environment
identity includes the pinned manifest, Python executable/version, platform
string, `PATH` value, evaluation limits, and installed Python distributions, but
does not bind an OS/container image digest, system libraries, GPU driver, or the
contents of executables reachable through `PATH`.

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
