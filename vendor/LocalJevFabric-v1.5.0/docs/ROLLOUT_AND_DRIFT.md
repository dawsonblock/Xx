# Shadow, Canary, and Drift Operations

LocalJevFabric v1.4 separates qualification from deployment. A head can pass offline qualification and still spend time in shadow/canary before becoming stable.

## Stages

```text
qualified candidate -> shadow -> canary -> stable
                         |         |
                         +---------+---- no direct authority
```

A `shadow` binding keeps `baseline_backend` in production and mirrors the exact question to the candidate. Candidate failures and answers do not affect the live result.

A `canary` binding deterministically assigns a percentage of request IDs to the candidate. The hash input is the request ID plus exact question signature, so the same request ID is sticky. Candidate traffic may fall back to the baseline if the candidate fails. Baseline traffic does not fall forward into the experimental candidate.

Only `stable` bindings may be direct-authorized.

## Commands

Stage a qualified registered task into shadow:

```bash
jev-fabric-rollout --registry config/tasks.registry.json \
  shadow <QUESTION_SIGNATURE> --baseline-backend llm2jev
```

Move to a 5% canary:

```bash
jev-fabric-rollout --registry config/tasks.registry.json \
  canary <QUESTION_SIGNATURE> --baseline-backend llm2jev --percent 5
```

After evidence supports it:

```bash
jev-fabric-rollout --registry config/tasks.registry.json stable <QUESTION_SIGNATURE>
```

All registry mutations require `FABRIC_REGISTRY_HMAC_KEY` and increment the registry revision.

## Shadow evidence

Enable:

```bash
export FABRIC_SHADOW_JOURNAL="$PWD/logs/jev-fabric-shadow.jsonl"
```

The shadow journal stores no request `state`. It records task signature, production/shadow backend, selected answer keys, scores, agreement, rollout stage and evidence hash.

## Canary rollback with labels

Record outcomes through `/v1/fabric/outcomes` or the outcome store. If labels contain `expected_key`, evaluate a canary:

```bash
jev-fabric-rollout --registry config/tasks.registry.json \
  evaluate <QUESTION_SIGNATURE> \
  --shadow-journal logs/jev-fabric-shadow.jsonl \
  --outcomes logs/jev-fabric-outcomes.jsonl \
  --min-samples 200 \
  --max-error-delta 0.01
```

Add `--rollback` to automatically replace the candidate route with its baseline as a new higher signed registry revision when the candidate error rate exceeds the configured delta. Rollback strips specialist authority evidence because the baseline was not qualified as that specialist artifact.

## Drift

Build a reference profile from JSONL rows with `signature`, `score`, and `answer_key`:

```bash
jev-fabric-drift evidence/reference-decisions.jsonl evidence/drift-profile.json
export FABRIC_DRIFT_PROFILE="$PWD/evidence/drift-profile.json"
```

Runtime monitoring compares a rolling window against that reference with:

- score mean deviation normalized by reference standard deviation;
- Jensen-Shannon divergence over answer-key distribution.

`degraded` drift denies direct authority immediately. `disabled` drift prevents fail-closed/direct specialists from running rather than silently routing the same authority-bearing task to a weaker backend. For ordinary non-authoritative specialist tasks, severe drift can route production to the configured generalist.

This detector uses observable outputs. It is not hidden-state drift detection.
