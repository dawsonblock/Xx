import json

from local_jev_fabric.audit import AuditLog


def test_audit_chain_detects_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append(request_id="1", request={"a": 1}, response={"b": 2}, trace={"x": 3}, registry_digest="d")
    log.append(request_id="2", request={"a": 2}, response={"b": 3}, trace={"x": 4}, registry_digest="d")
    ok, count, error = AuditLog.verify(str(path))
    assert ok and count == 2 and error is None
    lines = path.read_text().splitlines()
    row = json.loads(lines[0]); row["request_id"] = "evil"; lines[0] = json.dumps(row)
    path.write_text("\n".join(lines) + "\n")
    ok, _, _ = AuditLog.verify(str(path))
    assert not ok


def test_corrupt_existing_audit_refuses_to_continue(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(str(path))
    log.append(request_id="1", request={"a": 1}, response={"b": 2}, trace={}, registry_digest="d")
    row = json.loads(path.read_text())
    row["request_id"] = "tampered"
    path.write_text(json.dumps(row) + "\n")
    import pytest
    with pytest.raises(ValueError, match="audit log is corrupt"):
        AuditLog(str(path))


def test_hmac_checkpoint_detects_tail_truncation(tmp_path):
    import pytest

    path = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "audit.checkpoint.json"
    log = AuditLog(str(path), checkpoint_path=str(checkpoint), hmac_key="secret")
    log.append(request_id="1", request={"a": 1}, response={"b": 2}, trace={}, registry_digest="d")
    log.append(request_id="2", request={"a": 2}, response={"b": 3}, trace={}, registry_digest="d")
    lines = path.read_text().splitlines()
    path.write_text(lines[0] + "\n")
    with pytest.raises(ValueError, match="tail truncation"):
        AuditLog(str(path), checkpoint_path=str(checkpoint), hmac_key="secret")


def test_audit_checkpoint_can_advance_after_log_first_crash_window(tmp_path):
    path = tmp_path / "audit.jsonl"
    checkpoint = tmp_path / "audit.checkpoint.json"
    log = AuditLog(str(path), checkpoint_path=str(checkpoint), hmac_key="secret")
    log.append(request_id="1", request={"a": 1}, response={"b": 2}, trace={}, registry_digest="d")
    # Simulate a durable second record written after the old checkpoint by copying a valid line
    # from an uncheckpointed logger that continues the same chain.
    checkpoint_bytes = checkpoint.read_bytes()
    log.append(request_id="2", request={"a": 2}, response={"b": 3}, trace={}, registry_digest="d")
    checkpoint.write_bytes(checkpoint_bytes)
    recovered = AuditLog(str(path), checkpoint_path=str(checkpoint), hmac_key="secret")
    assert recovered._count == 2
    ok, count, error = AuditLog.verify(str(path), checkpoint_path=str(checkpoint), hmac_key="secret")
    assert ok and count == 2 and error is None
