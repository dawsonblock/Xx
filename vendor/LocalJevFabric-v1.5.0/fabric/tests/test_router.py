import pytest

from local_jev_fabric.client import BackendError
from local_jev_fabric.config import BackendConfig, FabricConfig
from local_jev_fabric.registry import TaskRegistry
from local_jev_fabric.router import FabricRouter


class FakeClient:
    def __init__(self, fail=(), invalid=()):
        self.fail = set(fail)
        self.invalid = set(invalid)
        self.calls = []

    async def manifest(self, backend):
        return {
            "served_model": backend.model,
            "artifact_bundle_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "backend_fingerprint_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "calibration_evidence_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "score_semantics": "calibrated",
            "legacy_artifacts_enabled": False,
        }

    async def ask(self, backend, payload):
        qids = tuple(payload["questions"])
        self.calls.append((backend.name, qids))
        if backend.name in self.fail:
            raise BackendError("boom")
        if backend.name in self.invalid:
            return {"model": backend.model,
                    "answers": {qid: {"type": "choice", "choice": "x", "probabilities": {"x": 1.0}, "confidence": 1.0} for qid in qids},
                    "usage": {"input_tokens": 3, "output_tokens": 0}}
        return {"model": backend.model,
                "answers": {qid: {"type": "noul", "noul": 0.9} for qid in qids},
                "usage": {"input_tokens": 3, "output_tokens": 0}}


def config():
    return FabricConfig(
        host="127.0.0.1", port=8090, model="fabric", api_key=None, registry_path=None,
        backends=(
            BackendConfig("anyjev", "http://anyjev", "a", role="specialist", score_semantics="calibrated"),
            BackendConfig("laya", "http://laya", "l"),
            BackendConfig("llm2jev", "http://llm2jev", "q"),
        ),
        generalist_order=("laya", "llm2jev"),
    )


@pytest.mark.asyncio
async def test_registered_question_uses_specialist_unseen_uses_generalist():
    q1 = {"type": "noul", "instructions": "Known?"}
    q2 = {"type": "noul", "instructions": "Unknown?"}
    reg = TaskRegistry(); reg.register(q1, "anyjev", task_id="known.v1")
    client = FakeClient()
    router = FabricRouter(config(), reg, client=client)
    result, prov = await router.evaluate({"state": "x", "model": "fabric", "questions": {"a": q1, "b": q2}})
    assert prov == {"a": "anyjev", "b": "laya"}
    assert result["usage"]["input_tokens"] == 6


@pytest.mark.asyncio
async def test_specialist_failure_falls_back_to_generalist():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(q, "anyjev")
    client = FakeClient(fail={"anyjev"})
    router = FabricRouter(config(), reg, client=client)
    _, prov = await router.evaluate({"state": "x", "model": "fabric", "questions": {"a": q}})
    assert prov["a"] == "laya"
    assert client.calls[:2] == [("anyjev", ("a",)), ("laya", ("a",))]


@pytest.mark.asyncio
async def test_fail_closed_specialist_never_weakens_to_generalist():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(q, "anyjev", fallback_policy="fail_closed")
    client = FakeClient(fail={"anyjev"})
    router = FabricRouter(config(), reg, client=client)
    with pytest.raises(BackendError, match="all backends failed"):
        await router.evaluate({"state": "x", "model": "fabric", "questions": {"a": q}})
    assert client.calls == [("anyjev", ("a",))]


@pytest.mark.asyncio
async def test_invalid_backend_answer_falls_back():
    q = {"type": "noul", "instructions": "Unknown?"}
    client = FakeClient(invalid={"laya"})
    router = FabricRouter(config(), TaskRegistry(), client=client)
    _, prov = await router.evaluate({"state": "x", "model": "fabric", "questions": {"a": q}})
    assert prov["a"] == "llm2jev"


@pytest.mark.asyncio
async def test_unseen_questions_are_batched_to_generalist():
    reg = TaskRegistry()
    client = FakeClient()
    router = FabricRouter(config(), reg, client=client)
    questions = {
        "a": {"type": "noul", "instructions": "One?"},
        "b": {"type": "noul", "instructions": "Two?"},
        "c": {"type": "noul", "instructions": "Three?"},
    }
    result, prov = await router.evaluate({"state": "x", "model": "fabric", "questions": questions})
    assert prov == {"a": "laya", "b": "laya", "c": "laya"}
    assert client.calls == [("laya", ("a", "b", "c"))]
    assert result["usage"]["input_tokens"] == 3


@pytest.mark.asyncio
async def test_direct_authority_requires_exact_calibrated_fail_closed_binding():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(
        q, "anyjev", fallback_policy="fail_closed", direct_authorized=True,
        artifact_digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", backend_fingerprint="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", calibration_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", qualification_digest="sha256:" + "1" * 64, independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64, promotion_id="sha256:" + "1" * 64, min_score=0.8,
    )
    reg.integrity_verified = True
    router = FabricRouter(config(), reg, client=FakeClient())
    result, trace = await router.evaluate_detailed({"state": "x", "model": "fabric", "questions": {"a": q}}, request_id="r1")
    assert trace["direct_authorized"] is True
    assert result["fabric"]["direct_authorized"] is True

@pytest.mark.asyncio
async def test_direct_authority_denied_on_attestation_mismatch():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(
        q, "anyjev", fallback_policy="fail_closed", direct_authorized=True,
        artifact_digest="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", backend_fingerprint="sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        calibration_digest="sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", qualification_digest="sha256:" + "1" * 64, independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64, promotion_id="sha256:" + "1" * 64, min_score=0.8,
    )
    reg.integrity_verified = True
    router = FabricRouter(config(), reg, client=FakeClient())
    result, trace = await router.evaluate_detailed({"state": "x", "model": "fabric", "questions": {"a": q}})
    assert trace["direct_authorized"] is False
    assert result["fabric"]["decisions"]["a"]["attestation_verified"] is False

@pytest.mark.asyncio
async def test_circuit_breaker_skips_repeatedly_failing_backend():
    cfg = FabricConfig(
        host="127.0.0.1", port=8090, model="fabric", api_key=None, registry_path=None,
        backends=(
            BackendConfig("laya", "http://laya", "l", failure_threshold=1, cooldown_s=60),
            BackendConfig("llm2jev", "http://llm2jev", "q"),
        ),
        generalist_order=("laya", "llm2jev"),
    )
    client = FakeClient(fail={"laya"})
    router = FabricRouter(cfg, TaskRegistry(), client=client)
    payload = {"state": "x", "model": "fabric", "questions": {"a": {"type": "noul", "instructions": "?"}}}
    _, prov1 = await router.evaluate(payload)
    _, prov2 = await router.evaluate(payload)
    assert prov1["a"] == prov2["a"] == "llm2jev"
    assert [name for name, _ in client.calls].count("laya") == 1
    assert router.breaker.snapshot()["laya"]["status"] == "open"

@pytest.mark.asyncio
async def test_expired_registered_task_refuses_generalist_downgrade():
    from datetime import datetime, timedelta, timezone
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(
        q, "anyjev", expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    )
    router = FabricRouter(config(), reg, client=FakeClient())
    with pytest.raises(ValueError, match="inactive or expired"):
        await router.evaluate({"state": "x", "model": "fabric", "questions": {"a": q}})


@pytest.mark.asyncio
async def test_direct_authority_denied_on_live_calibration_mismatch():
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(
        q, "anyjev", fallback_policy="fail_closed", direct_authorized=True,
        artifact_digest="sha256:" + "a" * 64, backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "d" * 64, qualification_digest="sha256:" + "1" * 64, independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64, promotion_id="sha256:" + "1" * 64, min_score=0.8,
    )
    reg.integrity_verified = True
    router = FabricRouter(config(), reg, client=FakeClient())
    result, trace = await router.evaluate_detailed({"state": "x", "model": "fabric", "questions": {"a": q}})
    assert trace["direct_authorized"] is False
    checks = result["fabric"]["decisions"]["a"]["attestation_checks"]
    assert checks["calibration_evidence"] is False


@pytest.mark.asyncio
async def test_fabric_emits_replay_evidence_digests():
    q = {"type": "noul", "instructions": "Unknown?"}
    router = FabricRouter(config(), TaskRegistry(), client=FakeClient())
    result, trace = await router.evaluate_detailed({"state": "x", "model": "fabric", "questions": {"a": q}}, request_id="r2")
    fabric = result["fabric"]
    assert fabric["authority_version"] == 4
    for key in ("request_sha256", "plan_sha256", "evidence_sha256"):
        assert len(fabric[key]) == 64
        int(fabric[key], 16)
        assert trace[key] == fabric[key]
