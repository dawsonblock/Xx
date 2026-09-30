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
- gives the candidate an ephemeral writable `/workspace`;
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

The interface is deprecated by Apple and can change in a macOS update. The
profile permits host file metadata lookup and reads of the selected Python
installation, including Homebrew Cellar/opt directories when applicable.
There is no per-workspace disk quota or container-style process/memory
isolation. Candidate dependencies may fail to import if they require files
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
