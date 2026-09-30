# Benchmarks, Outcomes, and Immutable Datasets

## Outcome feedback

Configure:

```bash
export FABRIC_OUTCOMES="$PWD/logs/jev-fabric-outcomes.jsonl"
```

Submit labels:

```json
POST /v1/fabric/outcomes
{
  "request_id": "...",
  "question_id": "tool",
  "signature": "<64-hex exact question signature>",
  "evidence_sha256": "<decision evidence hash>",
  "correct": true,
  "expected_key": "search_repo",
  "label_source": "integration-test"
}
```

The outcome store does not contain request state.

## Dataset snapshots

With `FABRIC_PROMOTION_JOURNAL` and outcomes enabled:

```bash
jev-fabric-dataset snapshot \
  --promotion-journal logs/jev-fabric-promotion.jsonl \
  --outcomes logs/jev-fabric-outcomes.jsonl \
  --output datasets/decision-snapshot-2026-09-28
```

A snapshot contains `examples.jsonl` and `manifest.json`. Example IDs are SHA-256-derived and assigned deterministically to:

- 70% train
- 12% validation
- 12% qualification
- 6% audit_holdout

The snapshot command refuses to overwrite a non-empty destination. Files are written read-only where the platform supports it. The manifest includes the examples SHA-256. Qualification and audit-holdout partitions are reserved and must not be fed into the trainer.

## End-to-end benchmark

Benchmark JSONL cases contain real SystemOne state/questions plus expected answer keys:

```json
{"state":"...","questions":{"tool":{"type":"choice","criteria":{"search":"...","read":"..."}}},"expected":{"tool":"search"},"allow_direct":false}
```

Run:

```bash
jev-fabric-benchmark evidence/agent-routing-benchmark.jsonl \
  --url http://127.0.0.1:8090 \
  --concurrency 16 \
  --min-question-accuracy 0.98 \
  --max-false-direct-rate 0
```

Reported metrics include question accuracy, request-level exact accuracy, false-direct authorization rate, backend decision counts, failures, and P50/P95/P99/mean latency.

For production qualification, build cases from real agent traces and stratify by tool risk class. Plain aggregate accuracy can hide unacceptable R2/R3 errors.
