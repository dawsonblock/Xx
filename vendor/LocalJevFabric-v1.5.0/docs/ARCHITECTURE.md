# Architecture

## Authority boundaries

The stack separates four concerns that were previously easy to blur:

1. **Decision inference** — which answer/tool is preferred?
2. **Task identity** — is a specialist actually trained for this exact semantic/layout contract?
3. **Calibration/evidence** — how should a numeric model score be interpreted?
4. **Authorization** — is the selected action permitted to execute?

No single model output is authoritative for all four.

## Request path

`jev-gateway` constructs one SystemOne request containing shared state plus typed questions. `LocalJevFabric` hashes each canonical question. Registered signatures are eligible for their declared specialist backend; unregistered signatures start with the first configured generalist. Questions targeting the same backend are batched into one call.

For a registered AnyJev task, the AnyJev SystemOne adapter independently canonicalizes the complete question into its head identity and can be configured with `require_level=L2`. This creates two gates rather than one:

```text
Fabric exact SHA-256 registration
           AND
AnyJev exact L2 artifact identity
```

If either gate does not match, the specialist does not silently reinterpret the task.

## Specialist binding

New AnyJev artifacts include a backend compatibility fingerprint derived from available immutable/relevant model metadata, architecture/configuration, tokenizer state, special tokens, chat template, hidden dimension and layer count. It is deliberately called a compatibility binding rather than a full weight byte hash. Production deployments should additionally pin the model revision/commit and record their own weight-manifest SHA-256.

## Generalists

LLM2Jev evaluates candidate answers from local LLM prefill logits. It is useful for unseen tasks because it needs no task-specific head. Its normalized output is a concentration distribution, not a guaranteed calibrated correctness probability.

An external Laya SystemOne server can be added as another generalist without changing the front-door protocol.

## Failover

Fallback is now a task policy, not an unconditional behavior.

```text
fallback_policy=generalist
registered specialist -> generalist #1 -> generalist #2 -> ...

fallback_policy=fail_closed
registered specialist -> stop on failure
```

Inactive or expired registered bindings also fail closed so an already-known high-assurance task cannot silently become an unseen generalist task.

## Tool authority

`jev-gateway` keeps action authority outside the decision model:

```text
R0 read-only            -> direct only with closed/certain args AND explicit fabric authority
R1 reversible mutation  -> upstream LLM may be forced to the selected tool
R2 external side effect -> advisory only / passthrough unless explicit hint mode
R3 destructive          -> passthrough; Jev cannot override
```

Unknown tools are R1 by default. In a production environment, explicitly classify every tool and consider making unknowns R2 or R3 instead.

## v1.4 authority evidence

Direct fabric authority is emitted only from an HMAC-verified registry entry with fail-closed policy, calibrated score semantics, artifact/fingerprint/calibration evidence, and a matching live specialist attestation including the held-out calibration report digest. The authority-v3 envelope also carries replay evidence digests. Registry v4 additionally requires stable rollout and normal drift before direct authority can be emitted. See `AUTHORITY_CHAIN.md`.


### Controlled specialization

Unregistered exact tasks may be recorded to an opt-in promotion journal. Candidate mining is outside the runtime authority path. A candidate becomes a specialist only after independent held-out qualification, HMAC authentication, live AnyJev re-attestation, explicit approval, and registry mutation. Direct authorization additionally requires the v3 qualification binding and gateway R0 policy.


## Evidence-driven deployment

A qualified specialist is not automatically production traffic. Registry v4 supports:

```text
shadow: baseline answers; candidate mirrored only
canary: deterministic candidate percentage; alternate arm mirrored
stable: candidate is production
```

Shadow/canary stages are non-authoritative. Their comparison records are written to an optional state-free shadow journal. Outcome labels can later be joined into immutable dataset snapshots.

## Drift monitor

The runtime can load a reference profile for an exact task and monitor a rolling window of observable score and answer-key behavior. Degraded drift blocks authority; severe drift either routes an ordinary specialist to a generalist or stops a fail-closed authority-bearing task.


## v1.5 routing and evidence planes

Generalist selection can use a non-authoritative capability manifest containing supported question types, benchmarked expected accuracy, latency and abstract cost. This plane may reorder or escalate generalists but cannot create direct authority.

Direct authority uses authority envelope v4. In addition to the existing registry/live-attestation/calibration/qualification chain, each direct-authorized binding must carry an independently signed evaluator qualification digest and a signed artifact-bundle attestation digest. The gateway validates both bindings before R0 direct execution.

Sanitized replay records and OTel-style JSONL spans are observability evidence only. They cannot change routing policy or authority.
