"""Artifact identity and model/tokenizer compatibility checks for AnyJev L1/L2 artifacts.

The original AnyJev artifacts were keyed by a model name and question hash. That is too weak for
an L2 head because the head reads an internal hidden-state representation. This module creates a
stable, JSON-serialisable fingerprint from the model revision/config, tokenizer/chat template and
feature geometry. It intentionally avoids hashing multi-gigabyte weight files at runtime; when a
backend exposes a concrete commit/revision that value is included and should be pinned in production.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Mapping

BINDING_VERSION = 1


def _jsonable(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(k): _jsonable(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if hasattr(value, "to_dict"):
        try:
            return _jsonable(value.to_dict())
        except Exception:
            pass
    return str(value)


def _digest(value: Any) -> str:
    payload = json.dumps(_jsonable(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def backend_fingerprint(backend: Any) -> Dict[str, Any]:
    """Return a stable compatibility fingerprint for an AnyJev backend.

    Backends can provide ``artifact_fingerprint()`` for a stronger implementation. The fallback
    captures the fields AnyJev can inspect portably. This is compatibility evidence, not a
    cryptographic attestation that every weight byte is unchanged.
    """
    custom = getattr(backend, "artifact_fingerprint", None)
    if callable(custom):
        result = dict(custom())
        result.setdefault("binding_version", BINDING_VERSION)
        result.setdefault("backend_name", getattr(backend, "name", type(backend).__name__))
        result["fingerprint_sha256"] = _digest({k: v for k, v in result.items() if k != "fingerprint_sha256"})
        return result

    tok = getattr(backend, "tokenizer", None)
    model = getattr(backend, "model", None)
    config = getattr(model, "config", None)
    config_dict = None
    if config is not None:
        try:
            config_dict = config.to_dict()
        except Exception:
            config_dict = str(config)

    chat_template = getattr(tok, "chat_template", None) if tok is not None else None
    special_tokens = getattr(tok, "special_tokens_map", None) if tok is not None else None
    vocab_size = getattr(tok, "vocab_size", None) if tok is not None else None
    commit = getattr(config, "_commit_hash", None) if config is not None else None
    revision = getattr(backend, "revision", None)
    quantization = getattr(config, "quantization_config", None) if config is not None else None

    result: Dict[str, Any] = {
        "binding_version": BINDING_VERSION,
        "backend_name": getattr(backend, "name", type(backend).__name__),
        "backend_class": f"{type(backend).__module__}.{type(backend).__qualname__}",
        "revision": revision,
        "commit": commit,
        "n_layers": int(getattr(backend, "n_layers", 0) or 0),
        "hidden_size": int(getattr(backend, "hidden_size", 0) or 0),
        "dtype": str(getattr(backend, "dtype", "")) or None,
        "model_config_sha256": _digest(config_dict) if config_dict is not None else None,
        "quantization_sha256": _digest(quantization) if quantization is not None else None,
        "tokenizer_class": f"{type(tok).__module__}.{type(tok).__qualname__}" if tok is not None else None,
        "tokenizer_vocab_size": int(vocab_size) if isinstance(vocab_size, int) else None,
        "tokenizer_special_tokens_sha256": _digest(special_tokens) if special_tokens is not None else None,
        "chat_template_sha256": hashlib.sha256(str(chat_template).encode("utf-8")).hexdigest()
        if chat_template is not None else None,
    }
    result["fingerprint_sha256"] = _digest(result)
    return result


def assert_binding_compatible(
    backend: Any,
    artifact: Mapping[str, Any],
    *,
    allow_legacy: bool = False,
) -> None:
    """Fail closed when an artifact is not bound to the active backend.

    Older AnyJev artifacts have no ``binding`` object. They remain usable only when callers opt
    in with ``allow_legacy=True``. New artifacts compare the fingerprint hash and critical geometry.
    """
    binding = artifact.get("binding")
    if not isinstance(binding, Mapping):
        if allow_legacy:
            return
        raise ValueError(
            "artifact has no model/tokenizer binding; refuse legacy unverified artifact. "
            "Set allow_legacy_artifacts=True only after independently validating it."
        )
    current = backend_fingerprint(backend)
    expected = binding.get("fingerprint_sha256")
    actual = current.get("fingerprint_sha256")
    if expected != actual:
        raise ValueError(
            "artifact/backend fingerprint mismatch: hidden-state ABI may have changed "
            f"({expected!s} != {actual!s})"
        )

    for field in ("n_layers", "hidden_size"):
        ev = binding.get(field)
        av = current.get(field)
        if ev not in (None, 0) and av not in (None, 0) and int(ev) != int(av):
            raise ValueError(f"artifact/backend {field} mismatch ({ev} != {av})")
