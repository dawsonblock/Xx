# Validation Report — AIDE-DREAM-RSI v1.3.0

Build date: 2026-09-29

## Local macOS Seatbelt follow-up (2026-09-29)

- Added an explicit native `seatbelt` backend and macOS `auto` selection when
  no OCI image is configured. It performs a live confinement probe before
  candidate execution and fails closed if the probe fails.
- On macOS 26.2, a real candidate using the isolated Python 3.10 environment
  read permitted task input. Host-file reads and writes, input mutation,
  loopback network connection, and subprocess creation were denied by the
  kernel profile. A deliberately permissive profile was rejected by preflight.
  A native timeout stopped an overlong candidate and cleaned its workspace.
- Seatbelt is a deprecated macOS interface and lacks the OCI backend's
  process/memory isolation. These local checks do not establish security
  qualification across macOS or Python runtime versions.
- A follow-up audit found that a rejected Darwin `RLIMIT_AS` value skipped
  later resource limits. CPU, per-file size, and open-file limits now apply
  independently; a failure to set one of those limits refuses candidate
  execution. Address-space limiting remains unsupported on this host.
- The full project suite now passes **106 tests**. Ruff and Black pass for
  `aide/`, and the updated wheel and source distribution build successfully.

## Post-review local hardening (2026-09-29)

- In an isolated Python 3.10 environment with test/runtime imports installed, `PYTHONPATH=. python -m pytest -q` — **100 passed**.
- The repository CI style gate also passes locally: Ruff 0.7.1 and Black 24.3.0 over `aide/`.
- Bundled LocalJevFabric fabric suite — **57 passed**. Bundled LLM2Jev suite — **220 passed, 17 skipped** (optional model backends). The only LLM2Jev change was a stale test assertion updated to check the existing instruction boundary; the bundled source implementation was not changed. Its SHA256SUMS entry was updated and the full checksum list verifies.
- `python3 -m compileall -q aide tests vendor/LocalJevFabric-v1.5.0/fabric/local_jev_fabric vendor/LocalJevFabric-v1.5.0/components/LLM2Jev/src vendor/LocalJevFabric-v1.5.0/components/AnyJev` — passed. Wheel and source distribution built successfully; the wheel contains the changed AIDE modules and imports from an isolated installation target.
- The AIDE advisor was exercised against the bundled fabric ASGI endpoint with a deterministic fake backend. This verifies typed request/response integration and confirms failure text secrets are excluded from that request. It does not qualify a live model backend.
- Strict Bubblewrap/OCI execution was not run: this host is macOS, Docker Desktop's socket did not answer a five-second ping, and Colima is stopped. Sandbox command construction, fail-closed behavior, output limits, and timeout handling have local test coverage.

These are local source/build checks; they do not replace the original build-environment results below or establish deployment qualification.

## Passed in the build environment

- `PYTHONPATH=. pytest -q tests/test_rsi_*.py` — **43 passed**
- bundled LocalJevFabric fabric suite — **57 passed**
- `python -m compileall -q aide tests vendor/LocalJevFabric-v1.5.0/fabric/local_jev_fabric vendor/LocalJevFabric-v1.5.0/components/LLM2Jev/src vendor/LocalJevFabric-v1.5.0/components/AnyJev`
- replay CLI smoke: `build-world` → `evaluate` → `evolve`
- JEV evidence CLI smoke: `aide.rsi.jev_cli report`
- package metadata smoke: `python setup.py --version` → `1.3.0`

The v1.3 regression suite covers:

- all v1.2 replay/live parity, split, qualification, sandbox-command, canary, and provenance checks;
- typed SystemOne response validation;
- high-confidence repairability mapping;
- low-confidence fallback to deterministic recovery logic;
- fail-open JEV outage behavior;
- replay persistence of recorded JEV repairability and confidence;
- shadow action ranking being unable to alter the authoritative DREAM batch;
- policy use of explicitly enabled recorded repairability.

## Bundled LocalJevFabric

The supplied LocalJevFabric v1.5.0 `fabric/tests` suite passes **57/57** with the source-tree import path configured. The bundled source itself was not functionally modified.

The bundled LLM2Jev component suite was not certified in this environment because its optional runtime dependency `openai` is not installed here. The complete LLM2Jev source remains included unchanged.

## Not certified in this environment

The inherited AIDE full pytest suite cannot fully collect because several dependencies declared by the original project are not installed in this build environment (`humanize`, `backoff`, `dataclasses_json`). This report does not claim the legacy AIDE suite passed.

Bubblewrap and Docker/Podman are not available in this build container, so strict sandbox execution itself was not run. Fail-closed behavior and command construction remain covered by the RSI regression suite inherited from v1.2.

No live AnyJev or LLM2Jev model backend was started in the build environment. JEV integration behavior was validated with typed mock SystemOne responses plus the LocalJevFabric fabric unit suite.

## Remaining intentional limitations

- live discovery remains serial (`rsi.max_parallelism=1`);
- replay remains empirical only;
- JEV is advisory/shadow by default;
- enabling `rsi.jev.failure_influence=true` is an operator decision and does not constitute formal calibration proof;
- canary and replay qualification reduce promotion risk but do not provide a formal statistical guarantee.
