from __future__ import annotations

import hashlib
import http.client
import json
import math
import os
import re
import ssl
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .statistics import (
    MULTITASK_MIN_TASKS,
    StatisticalBudget,
    statistical_epoch_sha256,
)

if os.name == "nt":
    import msvcrt
else:
    import fcntl

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


class _RemoteStateAnchor:
    """Small HTTPS client for an operator-managed monotonic checkpoint service."""

    _MAX_RESPONSE_BYTES = 64 * 1024

    def __init__(
        self,
        base_url: str,
        token: str,
        anchor_id: str,
        tls_certificate_sha256: str | None = None,
    ):
        parsed = urlsplit(base_url)
        if parsed.scheme.lower() not in {"https", "http"}:
            raise ValueError("state anchor URL must use HTTPS or loopback HTTP")
        if parsed.scheme.lower() != "https" and parsed.hostname not in {
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
            or not re.fullmatch(r"[!-~]+", token)
        ):
            raise ValueError("state anchor requires a URL and bearer token")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", anchor_id):
            raise ValueError("state anchor ID contains unsupported characters")
        scheme = parsed.scheme.lower()
        raw_hostname = parsed.hostname or ""
        hostname = (
            raw_hostname.lower()
            if ":" in raw_hostname
            else raw_hostname.encode("idna").decode("ascii").lower()
        )
        port = parsed.port
        if port == (443 if scheme == "https" else 80):
            port = None
        host = f"[{hostname}]" if ":" in hostname else hostname
        netloc = host if port is None else f"{host}:{port}"
        path = parsed.path.rstrip("/")
        self.base_url = f"{scheme}://{netloc}{path}"
        if tls_certificate_sha256 is not None:
            tls_certificate_sha256 = tls_certificate_sha256.lower()
            if not re.fullmatch(r"[0-9a-f]{64}", tls_certificate_sha256):
                raise ValueError("state anchor TLS certificate pin must be SHA-256")
        if scheme == "https" and tls_certificate_sha256 is None:
            raise ValueError(
                "HTTPS state anchoring requires an out-of-band TLS certificate SHA-256 pin"
            )
        if scheme != "https" and tls_certificate_sha256 is not None:
            raise ValueError("TLS certificate pin is only valid for HTTPS anchors")
        self.tls_certificate_sha256 = tls_certificate_sha256
        authority = json.dumps(
            {
                "base_url": self.base_url,
                "tls_certificate_sha256": self.tls_certificate_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.authority_sha256 = hashlib.sha256(authority).hexdigest()
        self.request_path = path + "/v1/checkpoints/" + anchor_id
        self.token = token

    def _request(self, method: str, body: bytes | None = None) -> tuple[int, bytes]:
        parsed = urlsplit(self.base_url)
        hostname = parsed.hostname or ""
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(
                hostname,
                parsed.port,
                timeout=5,
                context=ssl.create_default_context(),
            )
        else:
            connection = http.client.HTTPConnection(hostname, parsed.port, timeout=5)
        try:
            connection.connect()
            if parsed.scheme == "https":
                sock = connection.sock
                if sock is None:
                    raise RuntimeError("state anchor TLS connection has no socket")
                certificate = sock.getpeercert(binary_form=True)
                if not certificate:
                    raise RuntimeError("state anchor did not present a TLS certificate")
                certificate_sha256 = hashlib.sha256(certificate).hexdigest()
                if certificate_sha256 != self.tls_certificate_sha256:
                    raise RuntimeError("state anchor TLS certificate pin mismatch")
            headers = {"Authorization": f"Bearer {self.token}"}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, self.request_path, body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(self._MAX_RESPONSE_BYTES + 1)
            if len(payload) > self._MAX_RESPONSE_BYTES:
                raise RuntimeError("state anchor response exceeds size limit")
            return response.status, payload
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise RuntimeError("state anchor could not be reached") from exc
        finally:
            connection.close()

    def read(self) -> dict[str, Any] | None:
        try:
            status, payload = self._request("GET")
            if status == 404:
                return None
            if status != 200:
                raise RuntimeError(f"state anchor read failed with HTTP {status}")
            raw = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("state anchor returned invalid JSON") from exc
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
        status, _payload = self._request("PUT", body=body)
        if status not in (200, 201, 204):
            raise RuntimeError(f"state anchor rejected checkpoint with HTTP {status}")


@contextmanager
def rsi_writer_lock(path: str | Path):
    """Hold the single-controller lock for one RSI run."""
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(lock_path, flags, 0o600)
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RuntimeError("RSI writer lock must be a regular file")
        try:
            if os.name == "nt":
                # msvcrt locks a byte range. Ensure byte zero exists, then lock
                # that stable range for the lifetime of the controller.
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"\0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError as exc:
            raise RuntimeError("another RSI controller holds the writer lock") from exc
        yield
    finally:
        if locked:
            try:
                if os.name == "nt":
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
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
        anchor_tls_certificate_sha256: str | None = None,
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
            _RemoteStateAnchor(
                anchor_url,
                anchor_token or "",
                self.anchor_id,
                anchor_tls_certificate_sha256,
            )
            if anchor_url
            else None
        )

    def _verify_anchor(self, raw: dict[str, Any]) -> None:
        anchored = bool(
            raw.get("anchor_required")
            or "anchor_id" in raw
            or "anchor_authority_sha256" in raw
            or "anchor_revision" in raw
        )
        if anchored and self.anchor is None:
            raise ValueError(
                "anchored RSI state requires its configured external anchor"
            )
        if self.anchor is None:
            return
        if not anchored:
            if self.anchor.read() is not None:
                raise ValueError(
                    "unanchored RSI state conflicts with an existing external anchor"
                )
            return
        if anchored and not raw.get("anchor_authority_sha256"):
            raise ValueError(
                "anchored RSI state must be migrated to a pinned anchor authority"
            )
        if raw.get("anchor_id") != self.anchor_id:
            raise ValueError("RSI state does not match configured external anchor")
        if (
            anchored
            and raw.get("anchor_authority_sha256") != self.anchor.authority_sha256
        ):
            raise ValueError("RSI state does not match configured anchor authority")
        if (
            raw.get("anchor_tls_certificate_sha256")
            != self.anchor.tls_certificate_sha256
        ):
            raise ValueError("RSI state does not match configured anchor TLS pin")
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
        attempt_count = raw.get("canary_attempt_count", 0)
        if (
            isinstance(attempt_count, bool)
            or not isinstance(attempt_count, int)
            or attempt_count < 0
        ):
            raise ValueError("durable canary attempt count is invalid")
        if "canary_experiment_alpha" in raw:
            alpha = raw["canary_experiment_alpha"]
            if (
                isinstance(alpha, bool)
                or not isinstance(alpha, (int, float))
                or not math.isfinite(alpha)
                or not 0 < alpha < 1
            ):
                raise ValueError("durable canary experiment alpha is invalid")
        if "canary_gate_policy_sha256" in raw and not re.fullmatch(
            r"[0-9a-f]{64}", str(raw["canary_gate_policy_sha256"])
        ):
            raise ValueError("durable canary gate policy digest is invalid")
        if "statistical_protocol_sha256" in raw and not re.fullmatch(
            r"[0-9a-f]{64}", str(raw["statistical_protocol_sha256"])
        ):
            raise ValueError("durable statistical protocol digest is invalid")
        if "statistical_epoch_sha256" in raw:
            epoch_digest = raw["statistical_epoch_sha256"]
            if not isinstance(epoch_digest, str) or not re.fullmatch(
                r"[0-9a-f]{64}", epoch_digest
            ):
                raise ValueError("durable statistical epoch digest is invalid")
            if (
                "canary_experiment_alpha" not in raw
                or "statistical_protocol_sha256" not in raw
                or epoch_digest
                != statistical_epoch_sha256(
                    raw["canary_experiment_alpha"],
                    raw["statistical_protocol_sha256"],
                )
            ):
                raise ValueError("durable statistical epoch binding is invalid")
        if "statistical_budget" in raw:
            budget = StatisticalBudget.from_dict(raw["statistical_budget"])
            if budget.attempt_index != attempt_count:
                raise ValueError(
                    "durable statistical budget does not match the canary attempt counter"
                )
            if (
                "canary_experiment_alpha" not in raw
                or budget.family_alpha != raw["canary_experiment_alpha"]
            ):
                raise ValueError(
                    "durable statistical budget does not match the experiment alpha"
                )
            if (
                budget.protocol_sha256 is not None
                and budget.protocol_sha256 != raw.get("statistical_protocol_sha256")
            ):
                raise ValueError(
                    "durable statistical protocol does not match the latest alpha reservation"
                )
            if budget.panel_sha256 is not None and budget.panel_sha256 not in raw.get(
                "consumed_canary_panel_sha256", []
            ):
                raise ValueError("statistical budget panel was not durably consumed")
        for name in (
            "consumed_canary_sample_ids",
            "consumed_canary_sample_content_sha256",
            "consumed_canary_public_input_sha256",
            "consumed_canary_sample_identity_sha256",
            "consumed_canary_panel_sha256",
            "consumed_canary_task_sha256",
        ):
            values = raw.get(name, [])
            if (
                not isinstance(values, list)
                or any(not isinstance(value, str) or not value for value in values)
                or len(values) != len(set(values))
            ):
                raise ValueError(f"durable {name} is invalid")
            if name != "consumed_canary_sample_ids" and any(
                not re.fullmatch(r"[0-9a-f]{64}", value) for value in values
            ):
                raise ValueError(f"durable {name} contains an invalid SHA-256 value")
        self._verify_anchor(raw)
        return raw

    def write(self, **updates: Any) -> dict[str, Any]:
        raw = self.load()
        protected_anchor_fields = {
            "anchor_required",
            "anchor_id",
            "anchor_authority_sha256",
            "anchor_tls_certificate_sha256",
            "anchor_revision",
            "anchor_previous_revision",
            "anchor_previous_sha256",
        }
        if protected_anchor_fields.intersection(updates):
            raise ValueError("external anchor state fields are controller-managed")
        current_attempt_count = raw.get("canary_attempt_count", 0)
        next_attempt_count = updates.get("canary_attempt_count", current_attempt_count)
        if (
            isinstance(next_attempt_count, bool)
            or not isinstance(next_attempt_count, int)
            or next_attempt_count < current_attempt_count
        ):
            raise ValueError("canary attempt count cannot decrease or be invalid")
        current_alpha = raw.get("canary_experiment_alpha")
        next_alpha = updates.get("canary_experiment_alpha", current_alpha)
        if "canary_experiment_alpha" in updates and next_alpha is None:
            raise ValueError("canary experiment alpha must be finite and in (0, 1)")
        if next_alpha is not None and (
            isinstance(next_alpha, bool)
            or not isinstance(next_alpha, (int, float))
            or not math.isfinite(next_alpha)
            or not 0 < next_alpha < 1
        ):
            raise ValueError("canary experiment alpha must be finite and in (0, 1)")
        if current_alpha is not None and next_alpha != current_alpha:
            raise ValueError("canary experiment alpha is immutable for this run")
        current_protocol = raw.get("statistical_protocol_sha256")
        next_protocol = updates.get("statistical_protocol_sha256", current_protocol)
        if current_protocol is not None and next_protocol != current_protocol:
            raise ValueError("statistical protocol is immutable within an experiment")
        if "statistical_protocol_sha256" in updates and (
            not isinstance(next_protocol, str)
            or not re.fullmatch(r"[0-9a-f]{64}", next_protocol)
        ):
            raise ValueError("statistical protocol digest must be a SHA-256 value")
        current_epoch = raw.get("statistical_epoch_sha256")
        next_epoch = updates.get("statistical_epoch_sha256", current_epoch)
        if current_epoch is not None and next_epoch != current_epoch:
            raise ValueError("statistical epoch is immutable within an experiment")
        if "statistical_epoch_sha256" in updates and (
            not isinstance(next_epoch, str)
            or not re.fullmatch(r"[0-9a-f]{64}", next_epoch)
            or next_alpha is None
            or next_protocol is None
            or next_epoch != statistical_epoch_sha256(next_alpha, next_protocol)
        ):
            raise ValueError("statistical epoch must bind alpha and protocol")
        current_budget_data = raw.get("statistical_budget")
        next_budget_data = updates.get("statistical_budget", current_budget_data)
        if current_budget_data is not None or next_budget_data is not None:
            next_budget = StatisticalBudget.from_dict(next_budget_data)
            if next_budget.attempt_index != next_attempt_count:
                raise ValueError(
                    "statistical budget attempt index must match the canary counter"
                )
            if current_budget_data is not None:
                current_budget = StatisticalBudget.from_dict(current_budget_data)
                if next_budget.attempt_index == current_budget.attempt_index:
                    if next_budget != current_budget:
                        raise ValueError(
                            "statistical budget cannot change without a reservation"
                        )
                elif next_budget.attempt_index == current_budget.attempt_index + 1:
                    consumed_panels = updates.get(
                        "consumed_canary_panel_sha256",
                        raw.get("consumed_canary_panel_sha256", []),
                    )
                    consumed_tasks = updates.get(
                        "consumed_canary_task_sha256",
                        raw.get("consumed_canary_task_sha256", []),
                    )
                    if (
                        next_budget.panel_sha256 is None
                        or next_budget.protocol_sha256 is None
                        or next_budget.protocol_sha256 != next_protocol
                        or next_budget.panel_sha256 not in consumed_panels
                        or next_budget.panel_sha256
                        in raw.get("consumed_canary_panel_sha256", [])
                        or len(
                            set(consumed_tasks)
                            - set(raw.get("consumed_canary_task_sha256", []))
                        )
                        < MULTITASK_MIN_TASKS
                        or next_budget
                        != current_budget.reserve(
                            panel_sha256=next_budget.panel_sha256,
                            protocol_sha256=next_budget.protocol_sha256,
                        )
                    ):
                        raise ValueError(
                            "statistical budget reservation is not the exact next panel allocation"
                        )
                else:
                    raise ValueError(
                        "statistical budget attempt index can advance only once"
                    )
            else:
                expected_migration = StatisticalBudget.migrate_legacy(
                    next_budget.family_alpha, next_budget.attempt_index
                )
                if next_budget != expected_migration:
                    raise ValueError(
                        "new statistical budget must be initial or conservatively migrated"
                    )
            if next_budget.family_alpha != next_alpha:
                raise ValueError(
                    "statistical budget family alpha must match the configured experiment alpha"
                )
        current_gate_policy = raw.get("canary_gate_policy_sha256")
        next_gate_policy = updates.get("canary_gate_policy_sha256", current_gate_policy)
        if current_gate_policy is not None and next_gate_policy != current_gate_policy:
            raise ValueError("canary gate policy is immutable for this run")
        if "canary_gate_policy_sha256" in updates and (
            not isinstance(next_gate_policy, str)
            or not re.fullmatch(r"[0-9a-f]{64}", next_gate_policy)
        ):
            raise ValueError("canary gate policy digest must be a SHA-256 value")
        for name in (
            "consumed_canary_sample_ids",
            "consumed_canary_sample_content_sha256",
            "consumed_canary_public_input_sha256",
            "consumed_canary_sample_identity_sha256",
            "consumed_canary_panel_sha256",
            "consumed_canary_task_sha256",
        ):
            if name in updates:
                previous = raw.get(name, [])
                next_values = updates[name]
                if (
                    not isinstance(next_values, list)
                    or any(
                        not isinstance(value, str) or not value for value in next_values
                    )
                    or len(next_values) != len(set(next_values))
                    or not set(previous) <= set(next_values)
                ):
                    raise ValueError(f"durable {name} cannot decrease or duplicate")
                if name != "consumed_canary_sample_ids" and any(
                    not isinstance(value, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in next_values
                ):
                    raise ValueError(
                        f"durable {name} contains an invalid SHA-256 value"
                    )
        raw.update(updates)
        raw.setdefault("schema_version", 1)
        previous_revision = int(raw.get("anchor_revision", 0))
        previous_digest = None
        if (
            self.anchor is not None
            and self.path.exists()
            and raw.get("anchor_required")
        ):
            previous_digest = hashlib.sha256(self.path.read_bytes()).hexdigest()
        if self.anchor is not None:
            raw.update(
                anchor_required=True,
                anchor_id=self.anchor_id,
                anchor_authority_sha256=self.anchor.authority_sha256,
                anchor_tls_certificate_sha256=self.anchor.tls_certificate_sha256,
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
