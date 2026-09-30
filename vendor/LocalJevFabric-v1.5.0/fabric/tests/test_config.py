import pytest

from local_jev_fabric.config import load_config


def base(**extra):
    env = {"LLM2JEV_URL": "http://127.0.0.1:30000"}
    env.update(extra)
    return env


def test_non_loopback_requires_api_key():
    with pytest.raises(ValueError, match="FABRIC_API_KEY"):
        load_config(base(FABRIC_HOST="0.0.0.0"))
    cfg = load_config(base(FABRIC_HOST="0.0.0.0", FABRIC_API_KEY="secret"))
    assert cfg.api_key == "secret"


def test_loopback_can_be_keyless():
    cfg = load_config(base())
    assert cfg.host == "127.0.0.1" and cfg.api_key is None


def test_registry_checkpoint_requires_hmac_key():
    with pytest.raises(ValueError, match="registry_checkpoint_path requires registry_hmac_key"):
        load_config(base(FABRIC_REGISTRY_CHECKPOINT="/tmp/registry.cp"))


def test_audit_checkpoint_requires_hmac_key():
    with pytest.raises(ValueError, match="audit_checkpoint_path requires audit_hmac_key"):
        load_config(base(FABRIC_AUDIT_CHECKPOINT="/tmp/audit.cp"))
