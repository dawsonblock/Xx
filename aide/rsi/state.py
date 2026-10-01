from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .evidence import has_valid_rsi_state, sign_rsi_state

VALID_PHASES = {
    "IDLE",
    "CANARY_RUNNING",
    "LIVE_RUNNING",
    "WORLD_COMMITTED",
    "POLICY_EVALUATING",
    "CANDIDATE_PENDING",
    "COMPLETED",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _RemoteStateAnchor:
    """Small HTTPS client for an operator-managed monotonic checkpoint service."""

    def __init__(self, base_url: str, token: str, anchor_id: str):
        parsed = urlparse(base_url)
        if parsed.scheme != "https" and parsed.hostname not in {
            "127.0.0.1",
            "localhost",
            "::1",
        }:
            raise ValueError("state anchor URL must use HTTPS or loopback HTTP")
        if (
            not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not token
        ):
            raise ValueError("state anchor requires a URL and bearer token")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", anchor_id):
            raise ValueError("state anchor ID contains unsupported characters")
        self.url = base_url.rstrip("/") + "/v1/checkpoints/" + anchor_id
        self.token = token
        self.opener = urllib.request.build_opener(_NoRedirect())

    def read(self) -> dict[str, Any] | None:
        request = urllib.request.Request(
            self.url, headers={"Authorization": f"Bearer {self.token}"}
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                raw = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise RuntimeError(
                f"state anchor read failed with HTTP {exc.code}"
            ) from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("state anchor could not be reached or parsed") from exc
        if (
            not isinstance(raw, dict)
            or isinstance(raw.get("revision"), bool)
            or not isinstance(raw.get("revision"), int)
            or not isinstance(raw.get("sha256"), str)
            or len(raw["sha256"]) != 64
            or any(c not in "0123456789abcdef" for c in raw["sha256"])
        ):
            raise RuntimeError("state anchor returned an invalid checkpoint")
        return raw

    def advance(
        self,
        *,
        previous_revision: int,
        previous_sha256: str | None,
        revision: int,
        sha256: str,
    ) -> None:
        body = json.dumps(
            {
                "previous_revision": previous_revision,
                "previous_sha256": previous_sha256,
                "revision": revision,
                "sha256": sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        request = urllib.request.Request(
            self.url,
            data=body,
            method="PUT",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
            },
        )
        try:
            with self.opener.open(request, timeout=5) as response:
                if response.status not in (200, 201, 204):
                    raise RuntimeError("state anchor rejected checkpoint")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"state anchor rejected checkpoint with HTTP {exc.code}"
            ) from exc
        except OSError as exc:
            raise RuntimeError("state anchor could not be reached") from exc


@contextmanager
def rsi_writer_lock(path: str | Path):
    """Hold the single-controller lock for one RSI run."""
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError("RSI writer lock must be a regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another RSI controller holds the writer lock") from exc
        yield
    finally:
        os.close(fd)


class RSIStateStore:
    """Atomically persisted round state used for deterministic crash recovery."""

    def __init__(
        self,
        path: str | Path,
        *,
        require_attestation: bool = False,
        anchor_url: str | None = None,
        anchor_token: str | None = None,
        anchor_id: str | None = None,
    ):
        self.path = Path(path)
        self.require_attestation = bool(require_attestation)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if anchor_url and not self.require_attestation:
            raise ValueError(
                "external state anchoring requires authenticated RSI state"
            )
        if anchor_url and not anchor_id:
            raise ValueError("external state anchoring requires a stable anchor ID")
        self.anchor_id = (
            anchor_id
            or hashlib.sha256(str(self.path.resolve()).encode("utf-8")).hexdigest()
        )
        self.anchor = (
            _RemoteStateAnchor(anchor_url, anchor_token or "", self.anchor_id)
            if anchor_url
            else None
        )

    def _verify_anchor(self, raw: dict[str, Any]) -> None:
        if self.anchor is None:
            return
        if raw.get("anchor_id") != self.anchor_id:
            raise ValueError("RSI state does not match configured external anchor")
        revision = raw.get("anchor_revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise ValueError("RSI state has an invalid external anchor revision")
        digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        checkpoint = self.anchor.read()
        if checkpoint is not None and checkpoint.get("revision") == revision:
            if checkpoint.get("sha256") != digest:
                raise ValueError("RSI state differs from external monotonic anchor")
            return
        previous_revision = raw.get("anchor_previous_revision")
        previous_digest = raw.get("anchor_previous_sha256")
        remote_revision = 0 if checkpoint is None else checkpoint.get("revision")
        remote_digest = None if checkpoint is None else checkpoint.get("sha256")
        if (
            remote_revision != revision - 1
            or previous_revision != remote_revision
            or previous_digest != remote_digest
        ):
            raise ValueError("RSI state is behind or conflicts with external anchor")
        # Complete an interrupted local-write/remote-advance pair. The signed
        # local state can only roll the anchor forward from its recorded parent.
        self.anchor.advance(
            previous_revision=remote_revision,
            previous_sha256=remote_digest,
            revision=revision,
            sha256=digest,
        )

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            if self.anchor is not None and self.anchor.read() is not None:
                raise ValueError(
                    "anchored RSI state is missing from the local directory"
                )
            return {"schema_version": 1, "phase": "IDLE", "next_round": 0}
        raw = json.loads(self.path.read_text())
        if not isinstance(raw, dict):
            raise TypeError("RSI state must be a JSON object")
        if "state_attestation_hmac_sha256" in raw:
            if not has_valid_rsi_state(raw):
                raise ValueError("RSI state has an invalid host attestation")
        elif self.require_attestation:
            raise ValueError("trusted RSI state is missing its host attestation")
        if raw.get("phase") not in VALID_PHASES:
            raise ValueError(f"invalid RSI phase: {raw.get('phase')}")
        self._verify_anchor(raw)
        return raw

    def write(self, **updates: Any) -> dict[str, Any]:
        raw = self.load()
        raw.update(updates)
        raw.setdefault("schema_version", 1)
        previous_revision = int(raw.get("anchor_revision", 0))
        previous_digest = (
            hashlib.sha256(self.path.read_bytes()).hexdigest()
            if self.anchor is not None and self.path.exists()
            else None
        )
        if self.anchor is not None:
            raw.update(
                anchor_id=self.anchor_id,
                anchor_revision=previous_revision + 1,
                anchor_previous_revision=previous_revision,
                anchor_previous_sha256=previous_digest,
            )
        if self.require_attestation or "state_attestation_hmac_sha256" in raw:
            raw = sign_rsi_state(raw)
        if raw.get("phase") not in VALID_PHASES:
            raise ValueError(f"invalid RSI phase: {raw.get('phase')}")
        data = (json.dumps(raw, indent=2, sort_keys=True, default=str) + "\n").encode()
        fd, tmp = tempfile.mkstemp(
            prefix=self.path.name + ".", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            try:
                dfd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(dfd)
                finally:
                    os.close(dfd)
            except OSError:
                pass
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
        if self.anchor is not None:
            self.anchor.advance(
                previous_revision=previous_revision,
                previous_sha256=previous_digest,
                revision=previous_revision + 1,
                sha256=hashlib.sha256(data).hexdigest(),
            )
        return raw
