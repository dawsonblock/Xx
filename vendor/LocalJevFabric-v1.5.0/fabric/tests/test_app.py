from fastapi.testclient import TestClient

from local_jev_fabric.app import create_app
from local_jev_fabric.audit import AuditLog
from local_jev_fabric.config import BackendConfig, FabricConfig
from local_jev_fabric.registry import TaskRegistry
from local_jev_fabric.router import FabricRouter


class FakeClient:
    async def ask(self, backend, payload):
        qids = tuple(payload["questions"])
        return {"model": backend.model, "answers": {qid: {"type": "noul", "noul": 0.8} for qid in qids},
                "usage": {"input_tokens": 1, "output_tokens": 0}}


async def _close():
    return None


def test_systemone_endpoint_and_audit(tmp_path):
    cfg = FabricConfig("127.0.0.1", 8090, "fabric", None, None,
                       (BackendConfig("laya", "http://laya", "l"),), ("laya",),
                       audit_log_path=str(tmp_path / "audit.jsonl"))
    reg = TaskRegistry(); router = FabricRouter(cfg, reg, client=FakeClient())
    with TestClient(create_app(cfg, reg, router, AuditLog(cfg.audit_log_path))) as client:
        r = client.post("/v1/systemone", json={"model": "fabric", "state": "x",
                                                "questions": {"q": {"type": "noul", "instructions": "ok?"}}})
        assert r.status_code == 200
        assert r.json()["answers"]["q"]["noul"] == 0.8
        assert r.json()["fabric"]["registry_sha256"] == reg.digest
        assert r.headers["x-jev-fabric-backends"] == "laya"
        assert r.headers["x-request-id"]
    ok, count, _ = AuditLog.verify(cfg.audit_log_path)
    assert ok and count == 1


class AuthorityFakeClient(FakeClient):
    async def manifest(self, backend):
        return {
            "served_model": backend.model,
            "artifact_bundle_sha256": "a" * 64,
            "backend_fingerprint_sha256": "f" * 64,
            "calibration_evidence_sha256": "c" * 64,
            "score_semantics": "calibrated",
            "legacy_artifacts_enabled": False,
        }


def test_end_to_end_specialist_authority_envelope():
    cfg = FabricConfig(
        "127.0.0.1", 8090, "fabric", None, None,
        (
            BackendConfig("anyjev", "http://anyjev", "a", role="specialist", score_semantics="calibrated"),
            BackendConfig("general", "http://general", "g"),
        ),
        ("general",),
    )
    q = {"type": "noul", "instructions": "Known?"}
    reg = TaskRegistry(); reg.register(
        q, "anyjev", fallback_policy="fail_closed", direct_authorized=True,
        artifact_digest="sha256:" + "a" * 64,
        backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "c" * 64, qualification_digest="sha256:" + "1" * 64,
        independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64,
        promotion_id="sha256:" + "1" * 64,
        min_score=0.7,
    )
    reg.integrity_verified = True
    router = FabricRouter(cfg, reg, client=AuthorityFakeClient())
    with TestClient(create_app(cfg, reg, router, AuditLog(None))) as client:
        r = client.post("/v1/systemone", json={"model": "fabric", "state": "x", "questions": {"q": q}})
    assert r.status_code == 200
    fabric = r.json()["fabric"]
    assert fabric["direct_authorized"] is True
    assert fabric["authority_version"] == 4
    assert fabric["decisions"]["q"]["attestation_checks"]["calibration_evidence"] is True
    assert r.headers["x-jev-fabric-direct-authorized"] == "true"
    assert r.headers["x-jev-fabric-evidence"] == fabric["evidence_sha256"]


def test_v14_outcome_endpoint_and_drift_endpoint(tmp_path):
    from local_jev_fabric.outcomes import OutcomeStore
    from local_jev_fabric.drift import DriftMonitor
    cfg = FabricConfig("127.0.0.1",8090,"fabric",None,None,
                       (BackendConfig("laya","http://laya","l"),),("laya",),
                       outcome_store_path=str(tmp_path/'outcomes.jsonl'))
    reg=TaskRegistry(); drift=DriftMonitor(); router=FabricRouter(cfg,reg,client=FakeClient(),drift=drift)
    with TestClient(create_app(cfg,reg,router,AuditLog(None),outcome_store=OutcomeStore(cfg.outcome_store_path),drift_monitor=drift)) as client:
        d=client.get('/v1/fabric/drift'); assert d.status_code==200 and d.json()['version']==1
        payload={'request_id':'r','question_id':'q','signature':'a'*64,'evidence_sha256':'e'*64,'correct':True,'expected_key':'yes'}
        o=client.post('/v1/fabric/outcomes',json=payload); assert o.status_code==200 and o.json()['stored'] is True
