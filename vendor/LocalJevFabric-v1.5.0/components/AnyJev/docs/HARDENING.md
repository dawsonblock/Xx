# AnyJev hardening in LocalJevFabric

This integration deliberately changes L2 routing semantics.

## 1. Exact routing by default

An L2 head is a classifier over a specific hidden-state task. Matching `kind` and option text is not proof that two questions are the same task. The old convenience behavior was especially unsafe for `noul`, where unrelated questions all have the options `Yes` and `No`.

`Decider.route()` now accepts only:

1. the exact question key used to fit/load the head, or
2. an alias explicitly registered with `Decider.register_alias(source, alias, note=...)`.

Aliases are deployment configuration. Register them only after evaluating the alias against held-out examples.

## 2. Artifact compatibility binding

New head/calibration artifacts contain a deterministic backend compatibility binding covering the available model revision/commit metadata, architecture configuration, hidden size/layer count, quantization metadata, tokenizer vocabulary/special-token state, and chat template. Loading fails closed on a mismatch.

This is a compatibility fingerprint, not a byte hash of multi-gigabyte weight files. For strict reproducibility, pin immutable model revisions and preserve your own weight-manifest SHA-256 alongside the artifact.

## 3. Legacy artifacts

Artifacts created before this hardening do not contain a binding and are rejected by default. If you independently verified one, opt in explicitly with `allow_legacy_artifacts=True` on the `Decider`, the corresponding load override, or `anyjev-serve --allow-legacy-artifacts`.

The shipped upstream example heads in this source snapshot predate the binding. The demo therefore requires `--allow-legacy-heads` when those files are used. Re-fit and re-export heads to migrate them.

## 4. SystemOne server

`anyjev.systemone_server` exposes `/v1/systemone`. The adapter includes the complete canonical SystemOne question specification in the AnyJev question identity, so changing instructions, type, criteria, or score bounds creates a different task instead of silently reusing a head.

For a specialist deployment, keep `require_level=L2`: an unseen question should fall back to LocalJevFabric's generalist rather than being silently handled by the wrong specialist head.
