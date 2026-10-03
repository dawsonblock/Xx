from __future__ import annotations

import hashlib
import http.client
import json
import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from aide.rsi.state import RSIStateStore, _RemoteStateAnchor
from aide.rsi.statistics import (
    MULTITASK_MIN_TASKS,
    MULTITASK_PROTOCOL_SHA256,
    StatisticalBudget,
)
from rsi_anchor_service import (
    AnchorHTTPServer,
    CheckpointStore,
    load_token_digests,
    new_bearer_credential,
)


@pytest.fixture
def running_anchor(tmp_path: Path):
    anchor_id = "test-experiment"
    token, token_sha256 = new_bearer_credential(anchor_id)
    auth_path = tmp_path / "anchor-auth.json"
    auth_path.write_text(json.dumps({anchor_id: token_sha256}))
    auth_path.chmod(0o600)
    store = CheckpointStore(tmp_path / "anchor.sqlite3")
    server = AnchorHTTPServer(("127.0.0.1", 0), store, load_token_digests(auth_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "anchor_id": anchor_id,
            "token": token,
            "url": f"http://127.0.0.1:{server.server_port}",
            "store": store,
            "database": tmp_path / "anchor.sqlite3",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_anchor_cas_is_monotonic_authenticated_and_append_only(running_anchor):
    anchor = running_anchor
    client = _RemoteStateAnchor(anchor["url"], anchor["token"], anchor["anchor_id"])
    assert client.read() is None

    first_digest = "a" * 64
    client.advance(
        previous_revision=0,
        previous_sha256=None,
        revision=1,
        sha256=first_digest,
    )
    assert client.read() == {"revision": 1, "sha256": first_digest}

    with pytest.raises(RuntimeError, match="HTTP 409"):
        client.advance(
            previous_revision=0,
            previous_sha256=None,
            revision=1,
            sha256="b" * 64,
        )
    with pytest.raises(RuntimeError, match="HTTP 400"):
        client.advance(
            previous_revision=1,
            previous_sha256=first_digest,
            revision=3,
            sha256="c" * 64,
        )
    with pytest.raises(RuntimeError, match="HTTP 409"):
        client.advance(
            previous_revision=1,
            previous_sha256="d" * 64,
            revision=2,
            sha256="e" * 64,
        )
    assert client.read() == {"revision": 1, "sha256": first_digest}

    wrong_token = _RemoteStateAnchor(anchor["url"], "wrong-token", anchor["anchor_id"])
    assert wrong_token.read() is None
    with pytest.raises(RuntimeError, match="HTTP 404"):
        wrong_token.advance(
            previous_revision=1,
            previous_sha256=first_digest,
            revision=2,
            sha256="f" * 64,
        )

    assert anchor["store"].history_count(anchor["anchor_id"]) == 1
    connection = sqlite3.connect(anchor["database"])
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM anchor_history")
    finally:
        connection.close()

    connection = http.client.HTTPConnection(
        "127.0.0.1", int(anchor["url"].rsplit(":", 1)[1])
    )
    connection.request(
        "DELETE",
        f"/v1/checkpoints/{anchor['anchor_id']}",
        headers={"Authorization": f"Bearer {anchor['token']}"},
    )
    assert connection.getresponse().status == 405
    connection.close()


def test_only_one_concurrent_cas_update_wins(running_anchor):
    anchor = running_anchor

    def attempt(digest: str) -> str:
        client = _RemoteStateAnchor(anchor["url"], anchor["token"], anchor["anchor_id"])
        try:
            client.advance(
                previous_revision=0,
                previous_sha256=None,
                revision=1,
                sha256=digest,
            )
            return "committed"
        except RuntimeError as exc:
            assert "HTTP 409" in str(exc)
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, ["1" * 64, "2" * 64]))
    assert sorted(results) == ["committed", "conflict"]
    assert anchor["store"].read(anchor["anchor_id"])["revision"] == 1
    assert anchor["store"].history_count(anchor["anchor_id"]) == 1


def test_failed_history_append_rolls_back_the_head_transaction(running_anchor):
    anchor = running_anchor
    connection = sqlite3.connect(anchor["database"])
    try:
        connection.execute(
            "CREATE TRIGGER inject_append_failure BEFORE INSERT ON anchor_history "
            "BEGIN SELECT RAISE(ABORT, 'injected pre-commit failure'); END"
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(sqlite3.IntegrityError, match="injected pre-commit failure"):
        anchor["store"].advance(
            anchor_id=anchor["anchor_id"],
            previous_revision=0,
            previous_sha256=None,
            revision=1,
            sha256="a" * 64,
        )
    assert anchor["store"].read(anchor["anchor_id"]) is None

    connection = sqlite3.connect(anchor["database"])
    try:
        connection.execute("DROP TRIGGER inject_append_failure")
        connection.commit()
    finally:
        connection.close()
    assert anchor["store"].advance(
        anchor_id=anchor["anchor_id"],
        previous_revision=0,
        previous_sha256=None,
        revision=1,
        sha256="b" * 64,
    )
    assert anchor["store"].read(anchor["anchor_id"]) == {
        "revision": 1,
        "sha256": "b" * 64,
    }


def test_anchor_persists_across_service_store_restart(running_anchor):
    anchor = running_anchor
    client = _RemoteStateAnchor(anchor["url"], anchor["token"], anchor["anchor_id"])
    digest = hashlib.sha256(b"durable checkpoint").hexdigest()
    client.advance(
        previous_revision=0,
        previous_sha256=None,
        revision=1,
        sha256=digest,
    )

    reopened = CheckpointStore(anchor["database"])
    assert reopened.read(anchor["anchor_id"]) == {"revision": 1, "sha256": digest}
    assert reopened.history_count(anchor["anchor_id"]) == 1


def test_service_refuses_inconsistent_database_head(running_anchor):
    anchor = running_anchor
    client = _RemoteStateAnchor(anchor["url"], anchor["token"], anchor["anchor_id"])
    digest = hashlib.sha256(b"head").hexdigest()
    client.advance(
        previous_revision=0,
        previous_sha256=None,
        revision=1,
        sha256=digest,
    )
    connection = sqlite3.connect(anchor["database"])
    try:
        connection.execute(
            "UPDATE anchor_heads SET revision = 2 WHERE anchor_id = ?",
            (anchor["anchor_id"],),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ValueError, match="head does not match"):
        CheckpointStore(anchor["database"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX authorization-file mode bits")
def test_service_rejects_world_readable_authorization_file(tmp_path: Path):
    auth_path = tmp_path / "auth.json"
    _token, digest = new_bearer_credential("private-test")
    auth_path.write_text(json.dumps({"private-test": digest}))
    auth_path.chmod(0o644)
    with pytest.raises(ValueError, match="mode 0600"):
        load_token_digests(auth_path)


def test_one_hundred_state_transitions_reject_restored_revision_twenty(
    running_anchor, monkeypatch, tmp_path: Path
):
    monkeypatch.setenv(
        "AIDE_RSI_EVALUATION_HMAC_KEY", "test-only-anchor-key-with-at-least-32-bytes"
    )
    anchor = running_anchor
    state_path = tmp_path / "experiment" / "state.json"
    store = RSIStateStore(
        state_path,
        require_attestation=True,
        anchor_url=anchor["url"],
        anchor_token=anchor["token"],
        anchor_id=anchor["anchor_id"],
    )
    store.write(
        phase="IDLE",
        current_round=0,
        canary_attempt_count=0,
        canary_experiment_alpha=0.05,
        statistical_protocol_sha256=MULTITASK_PROTOCOL_SHA256,
        statistical_budget=StatisticalBudget.initial(0.05).to_dict(),
        consumed_canary_sample_ids=[],
        consumed_canary_panel_sha256=[],
        consumed_canary_task_sha256=[],
    )
    snapshot_at_20 = None
    for revision in range(1, 101):
        current = store.load()
        next_budget = StatisticalBudget.from_dict(
            current["statistical_budget"]
        ).reserve(
            panel_sha256=hashlib.sha256(f"panel-{revision}".encode()).hexdigest(),
            protocol_sha256=MULTITASK_PROTOCOL_SHA256,
        )
        sample_content = hashlib.sha256(f"canary-input-{revision}".encode()).hexdigest()
        store.write(
            phase="LIVE_RUNNING",
            current_round=revision,
            canary_attempt_count=revision,
            statistical_budget=next_budget.to_dict(),
            consumed_canary_panel_sha256=[
                *current.get("consumed_canary_panel_sha256", []),
                next_budget.panel_sha256,
            ],
            consumed_canary_task_sha256=[
                *current.get("consumed_canary_task_sha256", []),
                *[
                    hashlib.sha256(f"task-{revision}-{index}".encode()).hexdigest()
                    for index in range(MULTITASK_MIN_TASKS)
                ],
            ],
            consumed_canary_sample_ids=[
                *current["consumed_canary_sample_ids"],
                f"canary-{revision:03d}",
            ],
            consumed_canary_sample_content_sha256=[
                *current.get("consumed_canary_sample_content_sha256", []),
                sample_content,
            ],
        )
        if revision == 20:
            snapshot_at_20 = state_path.read_bytes()
    assert snapshot_at_20 is not None
    final = store.load()
    assert final["statistical_budget"]["attempt_index"] == 100
    assert final["statistical_budget"]["remaining_alpha"] == pytest.approx(0.04)
    assert len(final["consumed_canary_sample_ids"]) == 100
    assert len(final["consumed_canary_sample_content_sha256"]) == 100
    assert anchor["store"].read(anchor["anchor_id"])["revision"] == 101
    assert anchor["store"].history_count(anchor["anchor_id"]) == 101

    state_path.write_bytes(snapshot_at_20)
    with pytest.raises(ValueError, match="external anchor"):
        store.load()


@pytest.mark.parametrize("commit_before_error", [False, True])
def test_restart_recovers_exact_local_write_when_anchor_put_is_interrupted(
    running_anchor, monkeypatch, tmp_path: Path, commit_before_error: bool
):
    monkeypatch.setenv(
        "AIDE_RSI_EVALUATION_HMAC_KEY", "test-only-anchor-key-with-at-least-32-bytes"
    )
    anchor = running_anchor
    state_path = tmp_path / f"state-{commit_before_error}.json"
    store = RSIStateStore(
        state_path,
        require_attestation=True,
        anchor_url=anchor["url"],
        anchor_token=anchor["token"],
        anchor_id=anchor["anchor_id"],
    )
    real_advance = store.anchor.advance

    def interrupted_advance(**kwargs):
        if commit_before_error:
            real_advance(**kwargs)
        raise RuntimeError("simulated client interruption")

    monkeypatch.setattr(store.anchor, "advance", interrupted_advance)
    with pytest.raises(RuntimeError, match="simulated client interruption"):
        store.write(phase="LIVE_RUNNING", current_round=1)

    restarted = RSIStateStore(
        state_path,
        require_attestation=True,
        anchor_url=anchor["url"],
        anchor_token=anchor["token"],
        anchor_id=anchor["anchor_id"],
    )
    recovered = restarted.load()
    assert recovered["anchor_revision"] == 1
    assert anchor["store"].read(anchor["anchor_id"])["revision"] == 1
