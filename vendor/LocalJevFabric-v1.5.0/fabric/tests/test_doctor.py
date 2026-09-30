from local_jev_fabric.config import BackendConfig
from local_jev_fabric.doctor_cli import check_binding_manifest
from local_jev_fabric.registry import RouteBinding


def binding():
    return RouteBinding(
        backend="anyjev", backend_model="anyjev", fallback_policy="fail_closed", direct_authorized=True, min_score=0.8,
        artifact_digest="sha256:" + "a" * 64,
        backend_fingerprint="sha256:" + "f" * 64,
        calibration_digest="sha256:" + "c" * 64,
        qualification_digest="sha256:" + "1" * 64,
        independent_qualification_digest="sha256:" + "2" * 64, artifact_attestation_digest="sha256:" + "3" * 64,
        promotion_id="sha256:" + "1" * 64,
    )


def test_doctor_accepts_matching_live_authority_manifest():
    backend = BackendConfig("anyjev", "http://a", "anyjev", role="specialist", score_semantics="calibrated")
    manifest = {
        "served_model": "anyjev",
        "artifact_bundle_sha256": "a" * 64,
        "backend_fingerprint_sha256": "f" * 64,
        "calibration_evidence_sha256": "c" * 64,
        "score_semantics": "calibrated",
        "legacy_artifacts_enabled": False,
    }
    assert check_binding_manifest(binding(), backend, manifest) == []


def test_doctor_rejects_calibration_drift():
    backend = BackendConfig("anyjev", "http://a", "anyjev", role="specialist", score_semantics="calibrated")
    manifest = {
        "served_model": "anyjev",
        "artifact_bundle_sha256": "a" * 64,
        "backend_fingerprint_sha256": "f" * 64,
        "calibration_evidence_sha256": "d" * 64,
        "score_semantics": "calibrated",
        "legacy_artifacts_enabled": False,
    }
    assert "calibration_evidence_sha256 mismatch" in check_binding_manifest(binding(), backend, manifest)
