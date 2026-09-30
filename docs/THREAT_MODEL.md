# Authority and Threat Model — v1.3

## Self-improvement boundary

The recursively improved exploration controller is a typed, bounded DSL. It may change verified scoring/allocation/stopping operators and numeric parameters. It cannot modify:

- evaluator code or metric direction;
- sandbox configuration;
- replay objects or integrity manifests;
- split assignments;
- qualification/canary implementations;
- promotion state;
- controller credentials.

## Evaluation authority

The current AIDE feedback model interprets candidate source and terminal output to produce a metric. That result is tagged `feedback_model_interpreted_candidate_output`; it is advisory evidence and cannot authorize policy promotion or `best_solution.py` publication. The qualification gate and publisher require `evaluation_authority=trusted_external` plus SHA-256 bindings for candidate source, evaluator, dataset, split, and result on every scored replay node. A task-specific trusted evaluator is not bundled because hidden data, split identity, metric, and evaluator version are task-defined. Until one is integrated, automatic policy promotion and best-solution publication remain disabled.

Each evaluated source file is stored by SHA-256 before execution. The immutable replay node carries that digest, and publication loads and re-verifies the content-addressed artifact rather than reading mutable journal source. Generation prompts in RSI use fixed prior-world context and the selected parent or its observed failure; they do not receive the mutable current-round journal summary.

## JEV/SystemOne boundary

JEV is not an execution or promotion authority inside AIDE-DREAM-RSI. The adapter accepts only typed bounded choice responses and treats LocalJevFabric `direct_authorized` metadata as informational.

The adapter does not send candidate source code by default. Failure classification sends only an allowlisted failure class and fixed diagnostic signal names; raw error and analysis text stay local. Advisory logs store state hashes and typed evidence rather than raw state.

With `rsi.jev.fail_open=true`, a JEV outage cannot stop deterministic DREAM search. With `fail_open=false`, unavailable/invalid JEV responses fail the controller run by explicit operator choice.

With the default `failure_influence=false`, a compromised JEV service can only corrupt advisory telemetry. If an operator explicitly enables failure influence, a compromised service could bias repairability classification with a high-confidence answer. This remains bounded to recovery prioritization; it cannot create legal actions, bypass the sandbox, change measured scores, modify replay objects, or promote a policy.

## Candidate-code threat model

Model-generated candidate code is untrusted.

### Bubblewrap strict backend

On Linux, Bubblewrap:

- unshares namespaces including network;
- clears environment variables;
- exposes task input read-only;
- exposes required runtime roots read-only;
- gives the candidate an ephemeral size-limited tmpfs `/workspace` and a small bounded `/tmp`;
- destroys that workspace after execution;
- enforces wall timeout plus POSIX resource limits;
- caps captured output.

### OCI strict backend

On Docker/Podman hosts, the strict container backend runs candidate code with:

- `--network none`;
- read-only container root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges`;
- pids/memory/open-file/file-size limits where supported;
- task input mounted read-only;
- one disposable writable candidate workspace;
- only HOME/TMPDIR explicitly passed; host API credentials are not injected.

The container image must already contain all runtime dependencies. Build the provided image with `make sandbox-image` or supply another audited image.

### macOS Seatbelt backend

On macOS, `rsi.sandbox.backend=seatbelt` uses the local `sandbox-exec` kernel
profile. It denies all operations by default, permits reads of the Python
runtime and task input, and permits writes only in a disposable workspace.
Network access and process spawning are denied. The child receives a minimal
environment without controller credentials. Before candidate execution, a
live probe checks that Python runs, the workspace is writable, and host reads,
host writes, network access, and process spawning are denied. Failure refuses
strict execution.

The writable workspace is a mounted sparse disk image with a hard capacity
configured by `rsi.sandbox.workspace_mb`. The controller monitors the
candidate's resident memory via macOS `proc_pidinfo` and kills sustained use
above the smaller of `memory_mb` and `seatbelt_memory_mb`. Monitoring is
sampled, so it cannot prevent a short memory spike or guarantee a hard
physical-memory ceiling. Host-owned stdout and stderr capture files are stored
outside the candidate's writable mount so candidate-created symlinks cannot
redirect the controller's result reader to host files.

The interface is deprecated by Apple and can change in a macOS update. The
profile permits host file metadata lookup and reads of the selected Python
installation, including available Homebrew Cellar/opt directories when
applicable. This also covers Python runtimes installed by pyenv or uv that load
shared libraries from Homebrew.
There is no container-style process/memory isolation. CPU, per-file size, and
open-file limits are enforced where the kernel supports them; Darwin rejected
the address-space limit in local tests.
Candidate dependencies may fail to import if they require files
outside the allowed runtime roots. This backend must be requalified on each
target macOS/runtime combination before unattended use.

### Compatibility process mode

`rsi.sandbox.mode=process` is not hostile-code containment. It requires `allow_insecure_process=true` and should be used only for trusted code or inside a stronger external isolation boundary.

## Secrets

The controller may hold API credentials. Strict candidate sandboxes never inherit them. Candidate-generated code cannot legitimately access the controller's credential environment.

## Replay poisoning

Replay worlds are append-only and content-addressed. Corruption is detected on load. A malicious or incorrect evaluator can still generate bad evidence; evaluator integrity therefore remains outside the recursive boundary.

## Holdout leakage

Split assignments are persistent within an epoch. Replay qualification additionally checks worst-world regression so large gains on one held-out world cannot mask a severe loss on another.

## Stochastic promotion risk

One live A/B rollout can be noisy. v1.3 retains multiple paired incumbent/challenger canaries with alternating execution order and aggregate promotion rules. This reduces, but does not mathematically eliminate, stochastic false promotion.
