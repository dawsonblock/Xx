from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class BackendConfig:
    name: str
    url: str
    model: str
    role: str = "generalist"  # specialist | generalist
    api_key: str | None = None
    timeout_s: float = 8.0
    min_concentration: float = 0.0
    score_semantics: str = "concentration"  # concentration | calibrated
    failure_threshold: int = 3
    cooldown_s: float = 30.0
    max_concurrency: int = 4
    attestation_ttl_s: float = 60.0

    def __post_init__(self) -> None:
        if self.role not in {"specialist", "generalist"}:
            raise ValueError(f"backend {self.name}: role must be specialist or generalist")
        if not self.url.startswith(("http://", "https://")):
            raise ValueError(f"backend {self.name}: url must be http(s)")
        if not 0.0 <= self.min_concentration <= 1.0:
            raise ValueError(f"backend {self.name}: min_concentration must be in [0,1]")
        if self.score_semantics not in {"concentration", "calibrated"}:
            raise ValueError(f"backend {self.name}: score_semantics must be concentration or calibrated")
        if self.failure_threshold < 1:
            raise ValueError(f"backend {self.name}: failure_threshold must be >= 1")
        if self.cooldown_s < 0:
            raise ValueError(f"backend {self.name}: cooldown_s must be >= 0")
        if self.max_concurrency < 1:
            raise ValueError(f"backend {self.name}: max_concurrency must be >= 1")
        if self.attestation_ttl_s < 0:
            raise ValueError(f"backend {self.name}: attestation_ttl_s must be >= 0")

    @property
    def endpoint(self) -> str:
        return self.url.rstrip("/") + "/v1/systemone"


@dataclass(frozen=True)
class FabricConfig:
    host: str
    port: int
    model: str
    api_key: str | None
    registry_path: str | None
    backends: tuple[BackendConfig, ...]
    generalist_order: tuple[str, ...]
    registry_hmac_key: str | None = None
    require_registry_hmac: bool = False
    registry_min_revision: int = 0
    registry_checkpoint_path: str | None = None
    audit_log_path: str | None = None
    audit_checkpoint_path: str | None = None
    audit_hmac_key: str | None = None
    promotion_journal_path: str | None = None
    shadow_journal_path: str | None = None
    outcome_store_path: str | None = None
    drift_profile_path: str | None = None
    drift_window: int = 100
    drift_min_samples: int = 30
    drift_degraded_z: float = 2.5
    drift_disabled_z: float = 4.0
    drift_degraded_js: float = 0.15
    drift_disabled_js: float = 0.30
    include_provenance: bool = True
    capability_manifest_path: str | None = None
    escalation_error_cost: float = 1.0
    escalation_cost_weight: float = 0.02
    escalation_latency_weight: float = 0.01
    escalation_min_expected_gain: float = 0.0
    replay_store_path: str | None = None
    telemetry_path: str | None = None

    def __post_init__(self) -> None:
        if self.registry_min_revision < 0:
            raise ValueError("registry_min_revision must be >= 0")
        if self.registry_checkpoint_path and not self.registry_hmac_key:
            raise ValueError("registry_checkpoint_path requires registry_hmac_key")
        if self.audit_checkpoint_path and not self.audit_hmac_key:
            raise ValueError("audit_checkpoint_path requires audit_hmac_key")
        if self.drift_window < 5 or self.drift_min_samples < 5:
            raise ValueError("drift_window and drift_min_samples must be >= 5")
        if self.drift_min_samples > self.drift_window:
            raise ValueError("drift_min_samples cannot exceed drift_window")
        if min(self.escalation_error_cost, self.escalation_cost_weight, self.escalation_latency_weight, self.escalation_min_expected_gain) < 0:
            raise ValueError("escalation cost parameters must be >= 0")

    @property
    def by_name(self) -> dict[str, BackendConfig]:
        return {b.name: b for b in self.backends}


def _env(name: str, default: str | None = None, env: Mapping[str, str] | None = None) -> str | None:
    source = os.environ if env is None else env
    value = source.get(name, default)
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def is_loopback_host(host: str) -> bool:
    h = host.strip().lower().strip("[]")
    return h in {"localhost", "::1", "0:0:0:0:0:0:0:1"} or (h.startswith("127.") and len(h.split(".")) == 4)


def _bool_env(name: str, default: bool = False, env: Mapping[str, str] | None = None) -> bool:
    value = _env(name, None, env)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _default_backends(env: Mapping[str, str] | None) -> list[dict]:
    out: list[dict] = []
    specs = (
        ("anyjev", "ANYJEV_URL", "ANYJEV_MODEL", "specialist", "ANYJEV_API_KEY"),
        ("laya", "LAYA_URL", "LAYA_MODEL", "generalist", "LAYA_API_KEY"),
        ("llm2jev", "LLM2JEV_URL", "LLM2JEV_MODEL", "generalist", "LLM2JEV_API_KEY"),
    )
    defaults = {"ANYJEV_MODEL": "anyjev", "LAYA_MODEL": "laya", "LLM2JEV_MODEL": "qwen-local"}
    for name, url_key, model_key, role, key_key in specs:
        url = _env(url_key, None, env)
        if not url:
            continue
        prefix = name.upper()
        out.append({
            "name": name,
            "url": url,
            "model": _env(model_key, defaults[model_key], env),
            "role": role,
            "api_key": _env(key_key, None, env),
            "score_semantics": _env(f"{prefix}_SCORE_SEMANTICS", "calibrated" if name == "anyjev" else "concentration", env),
            "failure_threshold": int(_env(f"{prefix}_FAILURE_THRESHOLD", "3", env) or "3"),
            "cooldown_s": float(_env(f"{prefix}_COOLDOWN_S", "30", env) or "30"),
            "max_concurrency": int(_env(f"{prefix}_MAX_CONCURRENCY", "4", env) or "4"),
            "attestation_ttl_s": float(_env(f"{prefix}_ATTESTATION_TTL_S", "60", env) or "60"),
        })
    return out


def load_config(env: Mapping[str, str] | None = None) -> FabricConfig:
    raw = _env("FABRIC_BACKENDS_JSON", None, env)
    specs = json.loads(raw) if raw else _default_backends(env)
    if not isinstance(specs, list):
        raise ValueError("FABRIC_BACKENDS_JSON must be a JSON array")
    backends = tuple(BackendConfig(**item) for item in specs)
    if not backends:
        raise ValueError("configure at least one backend (FABRIC_BACKENDS_JSON or *_URL variables)")
    names = [b.name for b in backends]
    if len(names) != len(set(names)):
        raise ValueError("backend names must be unique")

    default_order = [b.name for b in backends if b.role == "generalist"]
    order_raw = _env("FABRIC_GENERALIST_ORDER", ",".join(default_order), env) or ""
    order = tuple(x.strip() for x in order_raw.split(",") if x.strip())
    unknown = [x for x in order if x not in names]
    if unknown:
        raise ValueError(f"FABRIC_GENERALIST_ORDER references unknown backends: {unknown}")
    if not order:
        raise ValueError("at least one generalist backend is required for unseen questions/failover")

    host = _env("FABRIC_HOST", "127.0.0.1", env) or "127.0.0.1"
    api_key = _env("FABRIC_API_KEY", None, env)
    if not is_loopback_host(host) and not api_key and not _bool_env("FABRIC_ALLOW_UNAUTHENTICATED_NETWORK", False, env):
        raise ValueError("non-loopback FABRIC_HOST requires FABRIC_API_KEY; set FABRIC_ALLOW_UNAUTHENTICATED_NETWORK=true only for deliberate insecure exposure")
    return FabricConfig(
        host=host,
        port=int(_env("FABRIC_PORT", "8090", env) or "8090"),
        model=_env("FABRIC_MODEL", "local-jev-fabric", env) or "local-jev-fabric",
        api_key=api_key,
        registry_path=_env("FABRIC_REGISTRY", None, env),
        backends=backends,
        generalist_order=order,
        registry_hmac_key=_env("FABRIC_REGISTRY_HMAC_KEY", None, env),
        require_registry_hmac=_bool_env("FABRIC_REGISTRY_REQUIRE_HMAC", False, env),
        registry_min_revision=int(_env("FABRIC_REGISTRY_MIN_REVISION", "0", env) or "0"),
        registry_checkpoint_path=_env("FABRIC_REGISTRY_CHECKPOINT", None, env),
        audit_log_path=_env("FABRIC_AUDIT_LOG", None, env),
        audit_checkpoint_path=_env("FABRIC_AUDIT_CHECKPOINT", None, env),
        audit_hmac_key=_env("FABRIC_AUDIT_HMAC_KEY", None, env),
        promotion_journal_path=_env("FABRIC_PROMOTION_JOURNAL", None, env),
        shadow_journal_path=_env("FABRIC_SHADOW_JOURNAL", None, env),
        outcome_store_path=_env("FABRIC_OUTCOMES", None, env),
        drift_profile_path=_env("FABRIC_DRIFT_PROFILE", None, env),
        drift_window=int(_env("FABRIC_DRIFT_WINDOW", "100", env) or "100"),
        drift_min_samples=int(_env("FABRIC_DRIFT_MIN_SAMPLES", "30", env) or "30"),
        drift_degraded_z=float(_env("FABRIC_DRIFT_DEGRADED_Z", "2.5", env) or "2.5"),
        drift_disabled_z=float(_env("FABRIC_DRIFT_DISABLED_Z", "4.0", env) or "4.0"),
        drift_degraded_js=float(_env("FABRIC_DRIFT_DEGRADED_JS", "0.15", env) or "0.15"),
        drift_disabled_js=float(_env("FABRIC_DRIFT_DISABLED_JS", "0.30", env) or "0.30"),
        include_provenance=_bool_env("FABRIC_INCLUDE_PROVENANCE", True, env),
        capability_manifest_path=_env("FABRIC_CAPABILITY_MANIFEST", None, env),
        escalation_error_cost=float(_env("FABRIC_ESCALATION_ERROR_COST", "1.0", env) or "1.0"),
        escalation_cost_weight=float(_env("FABRIC_ESCALATION_COST_WEIGHT", "0.02", env) or "0.02"),
        escalation_latency_weight=float(_env("FABRIC_ESCALATION_LATENCY_WEIGHT", "0.01", env) or "0.01"),
        escalation_min_expected_gain=float(_env("FABRIC_ESCALATION_MIN_EXPECTED_GAIN", "0.0", env) or "0.0"),
        replay_store_path=_env("FABRIC_REPLAY_STORE", None, env),
        telemetry_path=_env("FABRIC_TELEMETRY_JSONL", None, env),
    )
