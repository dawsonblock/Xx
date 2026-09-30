"""AIDE adapter against the bundled fabric's real ASGI request path."""

import pytest

from aide.rsi.jev import JevAdvisor


def test_advisor_uses_bundled_fabric_typed_choice_endpoint():
    pytest.importorskip("local_jev_fabric")
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from local_jev_fabric.app import create_app
    from local_jev_fabric.audit import AuditLog
    from local_jev_fabric.config import BackendConfig, FabricConfig
    from local_jev_fabric.registry import TaskRegistry
    from local_jev_fabric.router import FabricRouter

    class FakeBackend:
        seen = []

        async def ask(self, backend, payload):
            self.seen.append(payload)
            answers = {}
            for question_id, question in payload["questions"].items():
                choices = list(question["criteria"])
                answers[question_id] = {
                    "type": "choice",
                    "choice": choices[0],
                    "confidence": 0.9,
                    "probabilities": {
                        choice: 0.9 if choice == choices[0] else 0.1 / (len(choices) - 1)
                        for choice in choices
                    },
                }
            return {"model": backend.model, "answers": answers,
                    "usage": {"input_tokens": 1, "output_tokens": 1}}

    cfg = FabricConfig(
        "127.0.0.1", 8090, "fabric", None, None,
        (BackendConfig("general", "http://general", "g"),), ("general",),
    )
    registry = TaskRegistry()
    backend = FakeBackend()
    router = FabricRouter(cfg, registry, client=backend)
    with TestClient(create_app(cfg, registry, router, AuditLog(None))) as client:
        def post(_url, **kwargs):
            return client.post("/v1/systemone", json=kwargs["json"], headers=kwargs["headers"])

        advisor = JevAdvisor(enabled=True, model="fabric", failure_influence=True, post_fn=post)
        repairability, advice = advisor.repairability(
            fail_class="runtime", error="shape mismatch password=hunter2",
        )

    assert repairability == "repairable"
    assert advice is not None and advice.error is None
    assert advice.backend == "general"
    assert advice.authoritative is False
    assert advice.request_id and advice.evidence_sha256
    assert "hunter2" not in str(backend.seen)
