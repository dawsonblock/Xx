from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .registry import atomic_write_json, canonical_json

GENESIS = "0" * 64
AUDIT_CHECKPOINT_VERSION = 1


def hmac_compare(a: str, b: str) -> bool:
    return secrets.compare_digest(a, b)


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _checkpoint_mac(payload: Mapping[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


class AuditLog:
    """Append-only JSONL decision log with a SHA-256 chain and optional HMAC-sealed head.

    The chain detects in-log tampering. When ``checkpoint_path`` and ``hmac_key`` are configured,
    the sealed head additionally detects tail truncation relative to the last durable checkpoint.
    Raw prompts/states are never written; only digests and routing evidence are stored.
    """

    def __init__(self, path: str | None, *, checkpoint_path: str | None = None,
                 hmac_key: str | None = None):
        self.path = Path(path) if path else None
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else None
        self.hmac_key = hmac_key
        self._lock = threading.Lock()
        if self.checkpoint_path is not None and not self.hmac_key:
            raise ValueError("audit checkpoint requires an HMAC key")
        self._last_hash, self._count, hashes = self._recover_state()
        self._verify_or_advance_checkpoint(hashes)

    def _recover_state(self) -> tuple[str, int, dict[int, str]]:
        if self.path is None or not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS, 0, {0: GENESIS}
        prev = GENESIS
        count = 0
        hashes: dict[int, str] = {0: GENESIS}
        for line_no, line in enumerate(self.path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except Exception as exc:
                raise ValueError(f"audit log is corrupt at line {line_no}: invalid JSON") from exc
            got = record.pop("record_hash", None)
            if record.get("prev_hash") != prev:
                raise ValueError(f"audit log is corrupt at line {line_no}: previous hash mismatch")
            expected = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
            if not isinstance(got, str) or not hmac_compare(got, expected):
                raise ValueError(f"audit log is corrupt at line {line_no}: record hash mismatch")
            prev = got
            count += 1
            hashes[count] = got
        return prev, count, hashes

    def _load_checkpoint(self) -> dict[str, Any] | None:
        if self.checkpoint_path is None or not self.checkpoint_path.exists():
            return None
        raw = json.loads(self.checkpoint_path.read_text())
        if int(raw.get("version", 0)) != AUDIT_CHECKPOINT_VERSION:
            raise ValueError("unsupported audit checkpoint version")
        payload = {k: raw.get(k) for k in ("version", "records", "last_hash", "updated_at")}
        integrity = raw.get("integrity")
        if not isinstance(integrity, Mapping) or integrity.get("algorithm") != "hmac-sha256":
            raise ValueError("audit checkpoint missing HMAC integrity")
        expected = _checkpoint_mac(payload, self.hmac_key or "")
        if not hmac_compare(str(integrity.get("mac") or ""), expected):
            raise ValueError("audit checkpoint HMAC verification failed")
        return raw

    def _checkpoint_value(self) -> dict[str, Any]:
        payload = {
            "version": AUDIT_CHECKPOINT_VERSION,
            "records": self._count,
            "last_hash": self._last_hash,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        return {
            **payload,
            "integrity": {"algorithm": "hmac-sha256", "mac": _checkpoint_mac(payload, self.hmac_key or "")},
        }

    def _write_checkpoint(self) -> None:
        if self.checkpoint_path is not None:
            atomic_write_json(self.checkpoint_path, self._checkpoint_value())

    def _verify_or_advance_checkpoint(self, hashes: Mapping[int, str]) -> None:
        if self.checkpoint_path is None:
            return
        checkpoint = self._load_checkpoint()
        if checkpoint is None:
            self._write_checkpoint()
            return
        records = int(checkpoint.get("records") or 0)
        last_hash = str(checkpoint.get("last_hash") or "")
        if self._count < records:
            raise ValueError(
                f"audit log tail truncation detected: log has {self._count} records, checkpoint requires {records}"
            )
        if hashes.get(records) != last_hash:
            raise ValueError("audit log/checkpoint mismatch: checkpointed chain head is not present")
        # If a crash happened after the log fsync but before checkpoint replacement, advance safely.
        if self._count > records:
            self._write_checkpoint()

    def append(self, *, request_id: str, request: Mapping[str, Any], response: Mapping[str, Any],
               trace: Mapping[str, Any], registry_digest: str) -> dict[str, Any] | None:
        if self.path is None:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "request_id": request_id,
                "request_sha256": digest_json(request),
                "response_sha256": digest_json(response),
                "registry_sha256": registry_digest,
                "trace": trace,
                "prev_hash": self._last_hash,
            }
            record_hash = hashlib.sha256(canonical_json(record).encode("utf-8")).hexdigest()
            record["record_hash"] = record_hash
            line = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            self._last_hash = record_hash
            self._count += 1
            self._write_checkpoint()
            return record

    @staticmethod
    def verify(path: str, *, checkpoint_path: str | None = None,
               hmac_key: str | None = None) -> tuple[bool, int, str | None]:
        try:
            log = AuditLog(path, checkpoint_path=checkpoint_path, hmac_key=hmac_key)
            return True, log._count, None
        except Exception as exc:
            return False, 0, str(exc)
