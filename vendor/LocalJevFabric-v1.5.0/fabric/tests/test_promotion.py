import json
from pathlib import Path

import pytest

from local_jev_fabric.promotion import (
    PromotionJournal,
    QualificationPolicy,
    expected_calibration_error,
    load_eval_records,
    mine_candidates,
    qualification_digest,
    qualification_payload,
    sign_qualification,
    verify_qualification,
    wilson_upper_error,
)
from local_jev_fabric.registry import TaskRegistry, atomic_write_json, question_signature


def test_promotion_journal_records_only_unregistered_question_not_state(tmp_path):
    q = {"type": "noul", "instructions": "Need verification?"}
    path = tmp_path / "promotions.jsonl"
    journal = PromotionJournal(str(path))
    n = journal.append(
        request_id="r1",
        questions={"a": q, "b": {"type": "noul", "instructions": "Known?"}},
        trace={
            "evidence_sha256": "e" * 64,
            "decisions": {
                "a": {"registered": False, "signature": question_signature(q), "backend": "llm2jev", "score": 0.91, "score_semantics": "concentration"},
                "b": {"registered": True, "signature": "ignored", "backend": "anyjev", "score": 0.99},
            },
        },
    )
    assert n == 1
    text = path.read_text()
    assert "secret state" not in text
    row = json.loads(text)
    assert row["question"] == q
    assert row["signature"] == question_signature(q)


def test_candidate_mining_groups_exact_tasks_and_rejects_tamper(tmp_path):
    q = {"type": "noul", "instructions": "Repeat?"}
    path = tmp_path / "journal.jsonl"
    journal = PromotionJournal(str(path))
    for i in range(3):
        journal.append(
            request_id=f"r{i}", questions={"q": q},
            trace={"evidence_sha256": "a" * 64, "decisions": {"q": {
                "registered": False, "signature": question_signature(q), "backend": "llm2jev",
                "score": 0.8 + i * 0.05, "score_semantics": "concentration",
            }}},
        )
    candidates = mine_candidates(path, min_observations=3)
    assert len(candidates) == 1
    assert candidates[0]["observations"] == 3
    assert candidates[0]["backends"] == ["llm2jev"]
    assert candidates[0]["mean_score"] == pytest.approx(0.85)
    lines = path.read_text().splitlines()
    bad = json.loads(lines[0]); bad["question"]["instructions"] = "Tampered"
    lines[0] = json.dumps(bad)
    path.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="signature mismatch"):
        mine_candidates(path, min_observations=1)


def test_qualification_metrics_sign_and_verify(tmp_path):
    q = {"type": "noul", "instructions": "Stable task?"}
    eval_path = tmp_path / "eval.jsonl"
    rows = [{"correct": True, "confidence": 0.97} for _ in range(120)]
    eval_path.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
    records, digest = load_eval_records(eval_path)
    policy = QualificationPolicy(min_samples=100, min_accuracy=0.95, max_ece=0.08,
                                 max_brier=0.10, max_wilson_error_upper=0.10,
                                 operating_threshold=0.90)
    payload = qualification_payload(
        question=q, task_id="stable.v1", backend="anyjev", backend_model="m",
        artifact_digest="sha256:" + "a" * 64,
        backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "c" * 64,
        eval_records=records, eval_digest=digest, policy=policy,
    )
    assert payload["qualified"] is True
    assert payload["metrics"]["accuracy"] == 1.0
    signed = sign_qualification(payload, "promotion-secret")
    verified = verify_qualification(signed, hmac_key="promotion-secret")
    assert verified["task_id"] == "stable.v1"
    assert qualification_digest(signed).startswith("sha256:")
    tampered = json.loads(json.dumps(signed)); tampered["metrics"]["accuracy"] = 0.1
    with pytest.raises(ValueError, match="digest mismatch"):
        verify_qualification(tampered, hmac_key="promotion-secret")


def test_failed_qualification_cannot_verify_as_qualified(tmp_path):
    q = {"type": "noul", "instructions": "Weak?"}
    rows = [(0.9, False)] * 50
    payload = qualification_payload(
        question=q, task_id="weak.v1", backend="anyjev", backend_model="m",
        artifact_digest="sha256:" + "a" * 64,
        backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "c" * 64,
        eval_records=rows, eval_digest="sha256:" + "e" * 64,
        policy=QualificationPolicy(),
    )
    assert payload["qualified"] is False
    signed = sign_qualification(payload, "k")
    with pytest.raises(ValueError, match="did not pass"):
        verify_qualification(signed, hmac_key="k", require_qualified=True)


def test_calibration_helpers_are_bounded():
    assert expected_calibration_error([(0.9, True)] * 10) == pytest.approx(0.1)
    assert 0.0 <= wilson_upper_error(0, 100) <= 0.1
    assert wilson_upper_error(100, 100) == pytest.approx(1.0)


def test_v2_direct_registry_requires_requalification(tmp_path):
    q = {"type": "noul", "instructions": "Legacy direct?"}
    # Build a valid v2 payload by hand, including its old digest, but omit qualification evidence.
    from local_jev_fabric.registry import canonical_json
    import hashlib
    payload = {
        "version": 2,
        "revision": 1,
        "updated_at": "2026-09-28T00:00:00Z",
        "routes": {
            question_signature(q): {
                "backend": "anyjev", "fallback_policy": "fail_closed", "direct_authorized": True,
                "artifact_digest": "sha256:" + "a" * 64,
                "backend_fingerprint": "sha256:" + "f" * 64,
                "calibration_digest": "sha256:" + "c" * 64,
                "min_score": 0.9,
            }
        },
    }
    digest = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    value = {**payload, "integrity": {"payload_sha256": digest}}
    p = tmp_path / "registry.json"; p.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="requalify"):
        TaskRegistry.load(str(p))


def test_promote_and_monotonic_rollback_round_trip(tmp_path, monkeypatch):
    import argparse
    import local_jev_fabric.promotion_cli as cli

    monkeypatch.setenv("FABRIC_PROMOTION_HMAC_KEY", "promotion-secret")
    monkeypatch.setenv("FABRIC_REGISTRY_HMAC_KEY", "registry-secret")
    q = {"type": "noul", "instructions": "Promotable?"}
    qpath = tmp_path / "q.json"; qpath.write_text(json.dumps(q))
    regpath = tmp_path / "registry.json"
    atomic_write_json(regpath, TaskRegistry().to_dict(hmac_key="registry-secret"))

    policy = QualificationPolicy(min_samples=2, min_accuracy=0.5, max_ece=1, max_brier=1,
                                 max_wilson_error_upper=1, operating_threshold=0.8)
    payload = qualification_payload(
        question=q, task_id="promotable.v1", backend="anyjev", backend_model="anyjev",
        artifact_digest="sha256:" + "a" * 64,
        backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "c" * 64,
        eval_records=[(0.9, True), (0.8, True)], eval_digest="sha256:" + "e" * 64,
        policy=policy,
    )
    signed = sign_qualification(payload, "promotion-secret")
    qualpath = tmp_path / "q.qual.json"; qualpath.write_text(json.dumps(signed))

    monkeypatch.setattr(cli, "_manifest", lambda url, api_key: {
        "component": "AnyJev", "served_model": "anyjev",
        "artifact_bundle_sha256": "a" * 64,
        "backend_fingerprint_sha256": "f" * 64,
        "calibration_evidence_sha256": "c" * 64,
        "score_semantics": "calibrated", "legacy_artifacts_enabled": False,
    })
    history = tmp_path / "history"
    args = argparse.Namespace(
        approve=True, promotion_hmac_key_env="FABRIC_PROMOTION_HMAC_KEY",
        registry_hmac_key_env="FABRIC_REGISTRY_HMAC_KEY", registry=str(regpath),
        qualification=str(qualpath), question_json=str(qpath), url="http://anyjev",
        api_key=None, direct_authorized=False, min_score=0.85, task_id="promotable.v1",
        backend="anyjev", note=None, expires_at=None, history_dir=str(history), deployment_stage="shadow", baseline_backend="laya",
    )
    cli.cmd_promote(args)
    promoted = TaskRegistry.load(str(regpath), hmac_key="registry-secret", require_hmac=True)
    binding = promoted.lookup(q)
    assert binding is not None and binding.direct_authorized is False
    assert binding.deployment_stage == "shadow" and binding.baseline_backend == "laya"
    assert binding.qualification_digest == qualification_digest(signed)
    assert binding.promotion_id == qualification_digest(signed)
    promoted_revision = promoted.revision

    snapshot = history / "registry-revision-00000000.json"
    assert snapshot.exists()
    rollback_args = argparse.Namespace(
        approve=True, registry_hmac_key_env="FABRIC_REGISTRY_HMAC_KEY",
        registry=str(regpath), snapshot=str(snapshot), history_dir=str(history),
    )
    cli.cmd_rollback(rollback_args)
    rolled = TaskRegistry.load(str(regpath), hmac_key="registry-secret", require_hmac=True)
    assert rolled.routes == {}
    assert rolled.revision == promoted_revision + 1
