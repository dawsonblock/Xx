import pytest

from anyjev import Decider
from anyjev.backends.fake import FakeBackend
from anyjev.systemone import SystemOneEngine, compile_question


def content(state, option):
    return 3.0 if (state == "x" and option == "a") else 0.0


def test_compile_question_identity_changes_when_wording_changes():
    a = compile_question("q", {"type": "noul", "instructions": "Is this safe?"})
    b = compile_question("q", {"type": "noul", "instructions": "Should this restart?"})
    assert a.key != b.key


def test_choice_wire_identity_is_object_order_stable():
    a = compile_question("q", {"type": "choice", "instructions": "pick", "criteria": {"b": "B", "a": "A"}})
    b = compile_question("q", {"criteria": {"a": "A", "b": "B"}, "instructions": "pick", "type": "choice"})
    assert a.key == b.key
    assert a.options == ("a", "b")


def test_specialist_engine_fails_closed_without_l2_head():
    engine = SystemOneEngine(Decider(FakeBackend(content)), model="anyjev", level="auto", require_level="L2")
    with pytest.raises(Exception):
        engine.evaluate({"model": "anyjev", "state": "x", "questions": {"q": {"type": "noul", "instructions": "ok?"}}})


def test_engine_serves_exact_trained_choice_head():
    spec = {"type": "choice", "instructions": "pick", "criteria": {"a": "A", "b": "B"}}
    q = compile_question("q", spec)
    states = ["x" if i % 2 == 0 else "y" for i in range(20)]
    labels = [0 if s == "x" else 1 for s in states]
    def c(state, option): return 3.0 if ((state == "x" and option == "a") or (state == "y" and option == "b")) else 0.0
    d = Decider(FakeBackend(c))
    d.fit_head(q, states, labels, layers=[4])
    engine = SystemOneEngine(d, model="anyjev", level="auto", require_level="L2")
    out = engine.evaluate({"model": "anyjev", "state": "x", "questions": {"q": spec}})
    assert out["answers"]["q"]["type"] == "choice"
    assert out["answers"]["q"]["choice"] == "a"


def test_server_manifest_propagates_live_calibration_attestation():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from anyjev.systemone_server import create_app

    engine = SystemOneEngine(Decider(FakeBackend(content)), model="anyjev", level="auto", require_level=None)
    manifest = {
        "artifact_bundle_sha256": "a" * 64,
        "backend_fingerprint_sha256": "f" * 64,
        "calibration_evidence_sha256": "c" * 64,
        "score_semantics": "calibrated",
        "legacy_artifacts_enabled": False,
    }
    with TestClient(create_app(engine, manifest=manifest)) as client:
        got = client.get("/v1/fabric/manifest").json()
    assert got["calibration_evidence_sha256"] == "c" * 64
    assert got["score_semantics"] == "calibrated"
