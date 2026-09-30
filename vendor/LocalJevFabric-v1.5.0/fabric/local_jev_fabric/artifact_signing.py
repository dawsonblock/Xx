from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .registry import canonical_json

ATTESTATION_VERSION=1


def _sha256(value: bytes) -> str:
    return "sha256:"+hashlib.sha256(value).hexdigest()


def key_id(public_key: Ed25519PublicKey) -> str:
    raw=public_key.public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    return _sha256(raw)


def generate_keypair(private_path: str | Path, public_path: str | Path) -> tuple[str,str]:
    private=Ed25519PrivateKey.generate(); public=private.public_key()
    priv=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    pub=public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    Path(private_path).write_bytes(priv); Path(public_path).write_bytes(pub)
    try: Path(private_path).chmod(0o600); Path(public_path).chmod(0o644)
    except OSError: pass
    return key_id(public),_sha256(pub)


def _load_private(path: str | Path) -> Ed25519PrivateKey:
    key=serialization.load_pem_private_key(Path(path).read_bytes(),password=None)
    if not isinstance(key,Ed25519PrivateKey): raise ValueError("private key is not Ed25519")
    return key


def _load_public(path: str | Path) -> Ed25519PublicKey:
    key=serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key,Ed25519PublicKey): raise ValueError("public key is not Ed25519")
    return key


def create_attestation(*, digest: str, kind: str, private_key_path: str | Path,
                       metadata: Mapping[str,Any] | None=None) -> dict[str,Any]:
    if not isinstance(digest,str) or not digest.startswith("sha256:") or len(digest)!=71:
        raise ValueError("digest must be sha256:<64 hex chars>")
    int(digest[7:],16)
    private=_load_private(private_key_path); public=private.public_key()
    payload={"version":ATTESTATION_VERSION,"kind":str(kind),"digest":digest.lower(),
             "metadata":dict(metadata or {}),"signer_key_id":key_id(public)}
    raw=canonical_json(payload).encode(); sig=private.sign(raw)
    return {**payload,"signature":{"algorithm":"ed25519","value":base64.b64encode(sig).decode()}}


def verify_attestation(value: Mapping[str,Any], public_key_path: str | Path, *, expected_kind: str | None=None) -> dict[str,Any]:
    if int(value.get("version",0))!=ATTESTATION_VERSION: raise ValueError("unsupported artifact attestation version")
    payload={k:value.get(k) for k in ("version","kind","digest","metadata","signer_key_id")}
    public=_load_public(public_key_path)
    if payload["signer_key_id"]!=key_id(public): raise ValueError("artifact attestation signer key mismatch")
    if expected_kind is not None and payload["kind"]!=expected_kind: raise ValueError("artifact attestation kind mismatch")
    sig=value.get("signature")
    if not isinstance(sig,Mapping) or sig.get("algorithm")!="ed25519": raise ValueError("artifact attestation lacks Ed25519 signature")
    try: public.verify(base64.b64decode(str(sig.get("value") or "")),canonical_json(payload).encode())
    except Exception as exc: raise ValueError("artifact attestation signature verification failed") from exc
    digest=str(payload.get("digest") or "")
    if not digest.startswith("sha256:") or len(digest)!=71: raise ValueError("artifact attestation digest is invalid")
    return dict(payload)


def attestation_digest(value: Mapping[str,Any]) -> str:
    return _sha256(canonical_json(value).encode())
