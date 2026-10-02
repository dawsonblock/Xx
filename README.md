# AIDE-DREAM-RSI

**AIDE-DREAM-RSI** combines AIDE's code-search loop with DREAM's bounded replay policy and an optional JEV advisory layer. It is a research system for evaluating changes to how an agent searches; it does not let the recursive policy rewrite its evaluator, sandbox, evidence verifier, or promotion authority.

> **Current status: unreleased qualification snapshot.** The package metadata remains `1.3.5`. This repair branch updates trusted-evaluator process construction and moves canary execution to a four-run, task-family-clustered protocol. Local tests and synthetic calibration do not qualify hosted Linux Bubblewrap, external rollback anchoring, real task panels, or unattended promotion. See the [release qualification record](RELEASE_QUALIFICATION_MANIFEST.md) before operating it.

## What the system does

AIDE proposes and evaluates candidate programs. DREAM chooses bounded search actions using recorded experience. RSI can evolve a constrained `PolicyGenome` through development, validation, and one-shot replay qualification. A challenger can be promoted only after a separate multi-task canary panel passes the trusted evidence and statistical gates.

```text
AIDE candidate search
        │
        ▼
trusted, content-addressed measurements
        │
        ▼
DREAM replay and bounded policy evolution
        │
        ▼
held-out trajectory qualification
        │
        ▼
reserve a fresh multi-task canary panel and alpha allocation
        │
        ▼
paired incumbent/challenger runs
        │
        ▼
task effects → family-cluster effects → exact sign test
        │
        ▼
signed decision and authenticated promotion
```

The main authority boundaries are:

| Component | Role | Promotion authority |
|---|---|---|
| AIDE candidate | Produces a task solution | None |
| DREAM / `PolicyGenome` | Selects bounded search actions | None by itself |
| JEV | Optional bounded advice; shadow-first | None |
| Trusted evaluator | Measures candidate output against pinned task data | Attests measurement only |
| Qualification and canary gate | Verifies evidence and applies the precommitted test | Can authorize a transition when every check passes |
| RSI state store / external anchor | Records monotonic state and attempt budget | Rejects edits, conflicting writers, and anchored rollback |

## Statistical promotion protocol

The active protocol is `MULTITASK_PROMOTION_PROTOCOL_V5`. It treats independent task-family clusters as the inference units:

- Each task has exactly **four paired runs** using the same task, seed, and budget for incumbent and challenger.
- Four-run execution order is fixed before observation as ABBA or BAAB. Caller-supplied replicate IDs label evidence and cannot choose which policy runs first.
- Runs reduce to one median effect per task; related tasks reduce to one median effect per predeclared family. Seeds and tasks in the same family do not multiply the independent sample count.
- A one-sided exact sign test operates on family effects, with a fixed 500-attempt alpha budget and a separate practical-effect and worst-task-regression gate.
- The complete panel, evaluator and data identities, seeds, order schedule, policy digests, and alpha allocation are reserved before canary results are read. An interrupted panel is burned and its alpha is not refunded.

A panel currently requires at least 40 task records across at least 40 operator-declared independent families, with at least three balanced task strata. The minimum was raised after calibration showed only 4.2% estimated power for a 0.02 effect at 20 families, 42.4% at 40, and 70.3% at 60 in the current noise model. This remains modest power for small effects; task panels should use 60 or more independent families when feasible. The declaration of family independence is an experimental assumption that must be justified by the operator. The synthetic harness tests correlated seeds, correlated tasks within a family, heavy tails, heteroscedasticity, ties, and sequence-order effects; it cannot prove independence or representativeness for real tasks.

The YAML also keeps the older single-task `evaluate_series()` controls for compatibility. Those legacy fields do not affect V5 promotion. The per-pair regression flag is recorded for audit but is not itself a promotion veto; the active score normalization, panel schedule, family-level test, alpha allocation, practical-effect threshold, and task-regression limit are bound into the V5 authority configuration.

See [Statistical Qualification](docs/STATISTICAL_QUALIFICATION.md) for the exact protocol, calibration procedure, and qualification limits.

## Trusted evaluation and sandboxing

Feedback-model scores remain advisory. Authoritative evaluation binds candidate source, evaluator, evaluator configuration, dataset, split, environment, metric, result, predictions, and evaluation record. The expected content-addressed artifacts must exist and match their hashes. Dataset inputs are rehashed before and after authoritative evaluation.

For tabular tasks, the first-party reference evaluator (`entrypoint: __aide_reference__`) separates candidate execution from hidden labels. It gives the candidate public feature files in a strict inner sandbox, collects bounded predictions, then scores them in a fixed process with labels. Custom evaluator bundles are trusted code and must implement an equivalent candidate/label boundary themselves.

Linux uses Bubblewrap for strict candidate isolation. macOS can use Seatbelt or a container backend. The first-party adapter is trusted host code because it launches the nested candidate sandbox; its candidate remains in the inner boundary. Windows can use the Docker/Podman container backend. See [Trusted Evaluator Integration](docs/TRUSTED_EVALUATOR.md) and the [Threat Model](docs/THREAT_MODEL.md).

The HMAC key is a host-held secret, not a hardware-backed signer. HMAC state detects edits but does not detect restoration of an older complete snapshot unless an independently operated monotonic anchor is configured. An anchor server is not deployed by this repository.

## Installation

The project requires Python 3.10 or newer. For a normal editable install:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

The hash-locked `requirements-rsi-ci.lock` is for the Python 3.12 security, statistical, packaging, and CI test toolchain. It is not a lock for every optional AIDE research dependency:

```bash
python -m pip install --require-hashes -r requirements-rsi-ci.lock
```

For Linux strict-sandbox qualification, install Bubblewrap through the OS package manager and run the evaluator workflow tests. For macOS, the hosted workflows verify Seatbelt and nested process cleanup. A local pass on one platform does not qualify another platform.

## Quick start

Run AIDE with a task dataset and goal:

```bash
aide data_dir=/path/to/data goal="Optimize the solution"
```

For replay-based policy research:

```bash
aide-rsi \
  data_dir=/path/to/data \
  goal="Optimize the solution" \
  rsi.enabled=true
```

Strict candidate execution can be selected explicitly:

```bash
aide-rsi \
  data_dir=/path/to/data \
  goal="Optimize the solution" \
  rsi.enabled=true \
  rsi.sandbox.mode=strict \
  rsi.sandbox.backend=seatbelt
```

The reference live executor is serial (`rsi.max_parallelism=1`). Do not enable unattended promotion until the deployment has a reviewed evaluator/data configuration, independent canary panel, protected signing secret, external anchor where rollback resistance is required, and completed platform qualification.

## JEV advisory layer

The optional bundled LocalJevFabric v1.5.0 integration is advisory and shadow-first. It cannot execute tools, alter legal search actions, edit evidence, change the trusted evaluator, or promote a policy. Failure-repairability influence is opt-in; deterministic DREAM behavior remains available when JEV is unavailable.

Install the optional service:

```bash
make install-jev
```

Configure the generalist endpoint and registry for your deployment, then inspect it:

```bash
export LLM2JEV_URL=http://127.0.0.1:30000
export LLM2JEV_MODEL=qwen-local
export FABRIC_GENERALIST_ORDER=llm2jev
export FABRIC_REGISTRY="$PWD/vendor/LocalJevFabric-v1.5.0/config/tasks.registry.json"

aide-rsi-jev doctor
```

Enable advisory integration for a run only after reviewing the deployment settings:

```bash
aide-rsi \
  data_dir=/path/to/data \
  goal="Optimize the solution" \
  rsi.enabled=true \
  rsi.jev.enabled=true \
  rsi.jev.endpoint=http://127.0.0.1:8090/v1/systemone
```

See [JEV Integration](docs/JEV_INTEGRATION.md) for configuration and audit behavior.

## Validation

Run the focused local suite and standard checks:

```bash
python -m pytest -q tests/test_rsi_trusted_evaluator.py \
  tests/test_rsi_reference_evaluator.py \
  tests/test_rsi_multitask_canary.py \
  tests/test_rsi_statistics_qualification_tool.py \
  tests/test_rsi_recovery_hardening.py \
  tests/test_rsi_qualification.py

python -m compileall -q aide tests tools rsi_anchor_service.py
ruff check aide/ tools/ tests/
black --check aide/ tools/ tests/
```

Run the release-scale synthetic statistical campaign:

```bash
python tools/qualify_canary_statistics.py \
  --campaigns 20000 --attempts 500 --power-replicates 5000 \
  --tasks 80 --task-families 40 --runs-per-task 4 \
  --lineage-attempts 500 \
  --output qualification/repair-1.3.6/multitask-statistical-qualification.json
```

Generate and check the current source, TCB, build, and release-freeze manifests:

```bash
python tools/generate_release_manifests.py
python tools/generate_release_manifests.py --check
```

The release freeze remains `UNRELEASED_QUALIFICATION_INCOMPLETE` until hosted platform runs, real-task controls, external anchor rollback qualification, and the other stated release gates are recorded against the same source snapshot. Historical artifacts are retained under [`qualification/history/`](qualification/history/).

## Repository map

| Path | Contents |
|---|---|
| `aide/` | AIDE runtime, replay logic, bounded RSI policy and authority code |
| `aide/rsi/trusted_evaluator.py` | Evaluator identity, namespace-aware launch, evidence validation |
| `aide/rsi/reference_evaluator.py` | First-party tabular candidate/scorer split |
| `aide/rsi/statistics.py` | Canary panel, task-family test, protocol digest and alpha budget |
| `aide/rsi/state.py` | Authenticated state, writer lock, sticky external anchor client |
| `docs/` | Architecture, threat model, evaluator and qualification guidance |
| `qualification/repair-1.3.6/` | Current repair-branch test and statistical evidence |
| `qualification/history/` | Preserved pre-repair manifests and qualification outputs |
| `vendor/LocalJevFabric-v1.5.0/` | Bundled advisory service and component notices |

## License

The repository license is in [`LICENSE`](LICENSE). The included AIDE ML source retains its separate notice in [`LICENSE-AIDE`](LICENSE-AIDE); bundled components retain their notices under `vendor/LocalJevFabric-v1.5.0/components/`.
