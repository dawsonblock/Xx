"""Small SQLite-backed monotonic state-anchor service.

Run this service outside the experiment directory and under a separate
administrative identity. Remote listeners require TLS; loopback HTTP is
reserved for local development and protocol tests.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import ssl
import stat
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_ANCHOR_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_REQUEST_BYTES = 16 * 1024


class AnchorConflict(Exception):
    """The proposed checkpoint is not the exact next state transition."""


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_json_object(data: bytes) -> dict[str, Any]:
    value = json.loads(data, object_pairs_hook=_strict_json_object)
    if not isinstance(value, dict):
        raise TypeError("JSON body must be an object")
    return value


def _valid_digest(value: Any, *, nullable: bool = False) -> bool:
    return (value is None and nullable) or (
        isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))
    )


class CheckpointStore:
    """Crash-durable compare-and-swap checkpoint store with an audit chain."""

    def __init__(self, database_path: str | Path):
        self.path = Path(database_path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not stat.S_ISDIR(self.path.parent.stat().st_mode):
            raise ValueError("anchor database parent must be a directory")
        if os.name != "nt" and stat.S_IMODE(self.path.parent.stat().st_mode) & 0o077:
            raise ValueError(
                "anchor database directory must have mode 0700 or stricter"
            )
        if self.path.is_symlink():
            raise ValueError("anchor database must not be a symlink")
        if not self.path.exists():
            descriptor = os.open(
                self.path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            os.close(descriptor)
        if not stat.S_ISREG(self.path.stat().st_mode):
            raise ValueError("anchor database must be a regular file")
        if os.name != "nt":
            os.chmod(self.path, 0o600)
        self._initialize()
        self.verify_integrity()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA fullfsync = ON")
        connection.execute("PRAGMA checkpoint_fullfsync = ON")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS anchor_heads (
                    anchor_id TEXT PRIMARY KEY,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS anchor_history (
                    anchor_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision >= 1),
                    previous_revision INTEGER NOT NULL CHECK (previous_revision >= 0),
                    previous_sha256 TEXT,
                    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
                    committed_at TEXT NOT NULL,
                    PRIMARY KEY (anchor_id, revision)
                );
                CREATE TRIGGER IF NOT EXISTS anchor_history_no_update
                BEFORE UPDATE ON anchor_history
                BEGIN
                    SELECT RAISE(ABORT, 'anchor history is append-only');
                END;
                CREATE TRIGGER IF NOT EXISTS anchor_history_no_delete
                BEFORE DELETE ON anchor_history
                BEGIN
                    SELECT RAISE(ABORT, 'anchor history is append-only');
                END;
                """)
        finally:
            connection.close()

    def read(self, anchor_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT revision, sha256 FROM anchor_heads WHERE anchor_id = ?",
                (anchor_id,),
            ).fetchone()
            if row is None:
                return None
            return {"revision": int(row["revision"]), "sha256": row["sha256"]}
        finally:
            connection.close()

    def verify_integrity(self) -> None:
        """Refuse service startup when the head and append-only history diverge."""
        connection = self._connect()
        try:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise ValueError("anchor database failed SQLite integrity_check")
            heads = connection.execute(
                "SELECT anchor_id, revision, sha256 FROM anchor_heads ORDER BY anchor_id"
            ).fetchall()
            orphan = connection.execute(
                "SELECT 1 FROM anchor_history h "
                "LEFT JOIN anchor_heads a ON a.anchor_id = h.anchor_id "
                "WHERE a.anchor_id IS NULL LIMIT 1"
            ).fetchone()
            if orphan is not None:
                raise ValueError("anchor audit history contains an orphaned ID")
            for head in heads:
                expected_revision = 1
                previous_sha256 = None
                for row in connection.execute(
                    "SELECT revision, previous_revision, previous_sha256, sha256 "
                    "FROM anchor_history WHERE anchor_id = ? ORDER BY revision",
                    (head["anchor_id"],),
                ):
                    if (
                        row["revision"] != expected_revision
                        or row["previous_revision"] != expected_revision - 1
                        or row["previous_sha256"] != previous_sha256
                        or not _valid_digest(row["sha256"])
                    ):
                        raise ValueError(
                            "anchor database audit history is missing or inconsistent"
                        )
                    previous_sha256 = row["sha256"]
                    expected_revision += 1
                if (
                    expected_revision - 1 != head["revision"]
                    or previous_sha256 != head["sha256"]
                ):
                    raise ValueError(
                        "anchor database head does not match append-only history"
                    )
        finally:
            connection.close()

    def advance(
        self,
        *,
        anchor_id: str,
        previous_revision: int,
        previous_sha256: str | None,
        revision: int,
        sha256: str,
    ) -> bool:
        """Commit one CAS step; return True only when initializing an ID."""
        if (
            not _ANCHOR_ID_RE.fullmatch(anchor_id)
            or isinstance(previous_revision, bool)
            or not isinstance(previous_revision, int)
            or isinstance(revision, bool)
            or not isinstance(revision, int)
            or previous_revision < 0
            or revision > 2**63 - 1
            or revision != previous_revision + 1
            or not _valid_digest(previous_sha256, nullable=True)
            or not _valid_digest(sha256)
            or (previous_revision == 0) != (previous_sha256 is None)
        ):
            raise ValueError("invalid checkpoint transition")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            current = connection.execute(
                "SELECT revision, sha256 FROM anchor_heads WHERE anchor_id = ?",
                (anchor_id,),
            ).fetchone()
            current_revision = 0 if current is None else int(current["revision"])
            current_sha256 = None if current is None else current["sha256"]
            if (
                current_revision != previous_revision
                or current_sha256 != previous_sha256
            ):
                connection.rollback()
                raise AnchorConflict("checkpoint compare-and-swap conflict")

            committed_at = dt.datetime.now(dt.timezone.utc).isoformat(
                timespec="microseconds"
            )
            if current is None:
                connection.execute(
                    "INSERT INTO anchor_heads(anchor_id, revision, sha256, updated_at) "
                    "VALUES (?, ?, ?, ?)",
                    (anchor_id, revision, sha256, committed_at),
                )
            else:
                connection.execute(
                    "UPDATE anchor_heads SET revision = ?, sha256 = ?, updated_at = ? "
                    "WHERE anchor_id = ?",
                    (revision, sha256, committed_at, anchor_id),
                )
            connection.execute(
                "INSERT INTO anchor_history "
                "(anchor_id, revision, previous_revision, previous_sha256, sha256, committed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    anchor_id,
                    revision,
                    previous_revision,
                    previous_sha256,
                    sha256,
                    committed_at,
                ),
            )
            connection.commit()
            return current is None
        except Exception:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def history_count(self, anchor_id: str) -> int:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM anchor_history WHERE anchor_id = ?",
                (anchor_id,),
            ).fetchone()
            return int(row["count"])
        finally:
            connection.close()


def load_token_digests(auth_path: str | Path) -> dict[str, str]:
    """Load private ``{anchor_id: sha256(bearer_token)}`` authorization data."""
    path = Path(auth_path)
    if path.is_symlink():
        raise ValueError("anchor authorization file must not be a symlink")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("anchor authorization file must be a regular file")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError(
                "anchor authorization file must have mode 0600 or stricter"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            raise ValueError("anchor authorization file exceeds 64 KiB")
        raw = _parse_json_object(data)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > 10000:
        raise ValueError("anchor authorization file must contain 1 to 10000 IDs")
    for anchor_id, digest in raw.items():
        if not isinstance(anchor_id, str) or not _ANCHOR_ID_RE.fullmatch(anchor_id):
            raise ValueError("anchor authorization file has an invalid ID")
        if not _valid_digest(digest):
            raise ValueError("anchor authorization values must be lowercase SHA-256")
    return raw


def new_bearer_credential(anchor_id: str) -> tuple[str, str]:
    if not _ANCHOR_ID_RE.fullmatch(anchor_id):
        raise ValueError("invalid anchor ID")
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode("ascii")).hexdigest()


class AnchorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        store: CheckpointStore,
        token_digests: dict[str, str],
    ):
        self.store = store
        self.token_digests = dict(token_digests)
        super().__init__(server_address, _AnchorRequestHandler)


class _AnchorRequestHandler(BaseHTTPRequestHandler):
    server: AnchorHTTPServer
    protocol_version = "HTTP/1.1"
    server_version = "RSI-State-Anchor"
    sys_version = ""

    def _respond(
        self, status: int, payload: bytes = b"", content_type: str = "application/json"
    ) -> None:
        self.close_connection = True
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        if payload:
            self.send_header("Content-Type", content_type)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _json(self, status: int, value: dict[str, Any]) -> None:
        self._respond(
            status,
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        )

    def _path_id(self) -> str | None:
        parsed = urlsplit(self.path)
        prefix = "/v1/checkpoints/"
        if parsed.query or parsed.fragment or not parsed.path.startswith(prefix):
            return None
        anchor_id = parsed.path[len(prefix) :]
        if not _ANCHOR_ID_RE.fullmatch(anchor_id):
            return None
        return anchor_id

    def _authorized(self, anchor_id: str) -> bool:
        expected = self.server.token_digests.get(anchor_id)
        header = self.headers.get("Authorization", "")
        if expected is None or not header.startswith("Bearer "):
            return False
        token = header[len("Bearer ") :]
        if not token or not re.fullmatch(r"[!-~]+", token):
            return False
        provided = hashlib.sha256(token.encode("ascii")).hexdigest()
        return hmac.compare_digest(provided, expected)

    def do_GET(self) -> None:
        anchor_id = self._path_id()
        if anchor_id is None or not self._authorized(anchor_id):
            self._respond(404)
            return
        try:
            checkpoint = self.server.store.read(anchor_id)
        except sqlite3.Error:
            self._respond(503)
            return
        if checkpoint is None:
            self._respond(404)
            return
        self._json(200, checkpoint)

    def do_PUT(self) -> None:
        anchor_id = self._path_id()
        if anchor_id is None or not self._authorized(anchor_id):
            self._respond(404)
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._respond(400)
            return
        content_lengths = self.headers.get_all("Content-Length", [])
        if len(content_lengths) != 1:
            self._respond(400)
            return
        length = content_lengths[0]
        if not length.isascii() or not length.isdecimal():
            self._respond(411)
            return
        if len(length) > 5:
            self._respond(413)
            return
        body_length = int(length)
        if body_length > _MAX_REQUEST_BYTES:
            self._respond(413)
            return
        try:
            request = _parse_json_object(self.rfile.read(body_length))
            if set(request) != {
                "previous_revision",
                "previous_sha256",
                "revision",
                "sha256",
            }:
                raise ValueError("checkpoint request fields are invalid")
            previous_revision = request["previous_revision"]
            revision = request["revision"]
            if (
                isinstance(previous_revision, bool)
                or not isinstance(previous_revision, int)
                or isinstance(revision, bool)
                or not isinstance(revision, int)
                or previous_revision < 0
                or revision > 2**63 - 1
                or revision != previous_revision + 1
                or not _valid_digest(request["previous_sha256"], nullable=True)
                or not _valid_digest(request["sha256"])
                or (previous_revision == 0) != (request["previous_sha256"] is None)
            ):
                raise ValueError(
                    "checkpoint request is not a valid one-step transition"
                )
        except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self._respond(400)
            return
        try:
            created = self.server.store.advance(
                anchor_id=anchor_id,
                previous_revision=previous_revision,
                previous_sha256=request["previous_sha256"],
                revision=revision,
                sha256=request["sha256"],
            )
        except AnchorConflict:
            self._respond(409)
            return
        except ValueError:
            self._respond(400)
            return
        except sqlite3.Error:
            self._respond(503)
            return
        self._respond(201 if created else 204)

    def do_POST(self) -> None:
        self._respond(405)

    def do_DELETE(self) -> None:
        self._respond(405)

    def do_PATCH(self) -> None:
        self._respond(405)

    def log_message(self, fmt: str, *args: Any) -> None:
        # Authorization headers and bearer values are never logged.
        super().log_message(fmt, *args)


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(
    *,
    host: str,
    port: int,
    database_path: str | Path,
    auth_path: str | Path,
    tls_certificate: str | Path | None = None,
    tls_private_key: str | Path | None = None,
) -> None:
    if bool(tls_certificate) != bool(tls_private_key):
        raise ValueError("TLS requires both a certificate and a private key")
    if not _is_loopback(host) and not (tls_certificate and tls_private_key):
        raise ValueError("non-loopback anchor listeners require TLS")
    if not 1 <= port <= 65535:
        raise ValueError("port must be in [1, 65535]")

    os.umask(0o077)
    store = CheckpointStore(database_path)
    token_digests = load_token_digests(auth_path)
    server = AnchorHTTPServer((host, port), store, token_digests)
    if tls_certificate and tls_private_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(tls_certificate), str(tls_private_key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(
        f"RSI checkpoint anchor listening on {host}:{port} "
        f"({'TLS' if tls_certificate else 'loopback HTTP'})",
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AIDE RSI monotonic state anchor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    token_parser = subparsers.add_parser(
        "token", help="generate one scoped bearer credential"
    )
    token_parser.add_argument("anchor_id")
    serve_parser = subparsers.add_parser("serve", help="run the checkpoint service")
    serve_parser.add_argument("--database", required=True)
    serve_parser.add_argument("--auth-file", required=True)
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8765)
    serve_parser.add_argument("--tls-certificate")
    serve_parser.add_argument("--tls-private-key")
    args = parser.parse_args(argv)
    try:
        if args.command == "token":
            token, digest = new_bearer_credential(args.anchor_id)
            print(
                json.dumps(
                    {"anchor_id": args.anchor_id, "token": token, "sha256": digest}
                )
            )
            print(
                "Store the token only with the experiment controller; put its SHA-256 in the private auth file.",
                file=sys.stderr,
            )
            return 0
        serve(
            host=args.host,
            port=args.port,
            database_path=args.database,
            auth_path=args.auth_file,
            tls_certificate=args.tls_certificate,
            tls_private_key=args.tls_private_key,
        )
    except (OSError, ValueError, sqlite3.Error) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
