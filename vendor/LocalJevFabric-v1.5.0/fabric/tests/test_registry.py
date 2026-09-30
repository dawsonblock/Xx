import json
from datetime import datetime, timedelta, timezone

import pytest

from local_jev_fabric.registry import TaskRegistry, question_signature


def test_signature_is_exact_and_order_stable_for_object_keys():
    a = {"type": "noul", "instructions": "Is this safe?", "criteria": {"true": "yes", "false": "no"}}
    b = {"criteria": {"false": "no", "true": "yes"}, "instructions": "Is this safe?", "type": "noul"}
    c = {"type": "noul", "instructions": "Should this restart?", "criteria": {"true": "yes", "false": "no"}}
    assert question_signature(a) == question_signature(b)
    assert question_signature(a) != question_signature(c)
    reg = TaskRegistry()
    reg.register(a, "anyjev", task_id="safe.v1")
    assert reg.lookup(b).task_id == "safe.v1"
    assert reg.lookup(c) is None


def test_registry_hmac_detects_tampering(tmp_path):
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry()
    reg.register(q, "anyjev", task_id="known.v1")
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(reg.to_dict(hmac_key="secret")))
    loaded = TaskRegistry.load(str(path), hmac_key="secret", require_hmac=True)
    assert loaded.integrity_verified is True
    data = json.loads(path.read_text())
    data["routes"][question_signature(q)]["backend"] = "evil"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="digest mismatch|HMAC"):
        TaskRegistry.load(str(path), hmac_key="secret", require_hmac=True)


def test_direct_authority_requires_fail_closed_and_evidence():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry()
    with pytest.raises(ValueError, match="fail_closed"):
        reg.register(q, "anyjev", direct_authorized=True, min_score=0.8,
                     artifact_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", backend_fingerprint="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", calibration_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    reg.register(q, "anyjev", direct_authorized=True, fallback_policy="fail_closed", min_score=0.8,
                 artifact_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", backend_fingerprint="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", calibration_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", qualification_digest="sha256:" + "1" * 64, independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64, promotion_id="sha256:" + "1" * 64)
    assert reg.lookup(q).direct_authorized


def test_expired_route_is_not_selected():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry()
    past = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    reg.register(q, "anyjev", expires_at=past)
    assert reg.lookup(q) is None


def test_registry_checkpoint_rejects_rollback_and_equivocation(tmp_path):
    from local_jev_fabric.registry import enforce_registry_checkpoint

    checkpoint = tmp_path / "registry.checkpoint.json"
    q1 = {"type": "noul", "instructions": "One?"}
    q2 = {"type": "noul", "instructions": "Two?"}
    reg = TaskRegistry(); reg.register(q1, "anyjev")
    enforce_registry_checkpoint(reg, str(checkpoint), hmac_key="secret")

    newer = TaskRegistry(dict(reg.routes), revision=reg.revision, updated_at=reg.updated_at)
    newer.register(q2, "anyjev")
    enforce_registry_checkpoint(newer, str(checkpoint), hmac_key="secret")

    with pytest.raises(ValueError, match="rollback"):
        enforce_registry_checkpoint(reg, str(checkpoint), hmac_key="secret")

    fork = TaskRegistry(dict(newer.routes), revision=newer.revision, updated_at=newer.updated_at)
    fork.routes[question_signature(q1)] = type(next(iter(fork.routes.values())))(backend="different")
    with pytest.raises(ValueError, match="equivocation"):
        enforce_registry_checkpoint(fork, str(checkpoint), hmac_key="secret")


def test_registry_min_revision_is_enforced():
    from local_jev_fabric.registry import enforce_registry_checkpoint

    with pytest.raises(ValueError, match="below configured minimum"):
        enforce_registry_checkpoint(TaskRegistry(revision=2), None, hmac_key=None, min_revision=3)


def test_direct_authority_requires_explicit_operating_threshold():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry()
    with pytest.raises(ValueError, match="min_score"):
        reg.register(
            q, "anyjev", direct_authorized=True, fallback_policy="fail_closed",
            artifact_digest="sha256:" + "a" * 64,
            backend_fingerprint="sha256:" + "f" * 64,
            calibration_digest="sha256:" + "c" * 64,
        )
