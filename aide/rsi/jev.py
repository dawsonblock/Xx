from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

import requests


_SECRET_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b", re.I),
    re.compile(
        r"(?i)\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|FABRIC_API_KEY|API_KEY|TOKEN|SECRET)\s*[=:]\s*[^\s,;]+"
    ),
]

_FAILURE_SIGNALS = {
    "timeout": r"\b(?:timeout|timed out|deadline)\b",
    "resource": r"\b(?:memory|out of memory|oom|resource exhausted|disk full)\b",
    "syntax": r"\b(?:syntax|indentation|compile|parse error)\b",
    "dependency": r"\b(?:import|module|package|dependency|not installed)\b",
    "missing_data": r"\b(?:file not found|missing data|no such file|keyerror)\b",
    "permission": r"\b(?:permission|access denied|read.only|sandbox)\b",
    "shape": r"\b(?:shape|dimension|dtype|broadcast)\b",
    "numerical": r"\b(?:nan|overflow|underflow|divide by zero|singular)\b",
}


def _failure_summary(
    fail_class: str, error: str | None, analysis: str | None
) -> dict[str, Any]:
    """Expose only fixed categories; arbitrary execution text stays local."""
    allowed = {
        "timeout",
        "resource",
        "compile",
        "permission",
        "dependency",
        "runtime",
        "evaluation",
    }
    category = (
        str(fail_class).lower() if str(fail_class).lower() in allowed else "other"
    )
    text = f"{error or ''}\n{analysis or ''}".lower()
    return {
        "observed_failure_class": category,
        "signals": [
            name
            for name, pattern in _FAILURE_SIGNALS.items()
            if re.search(pattern, text)
        ],
        "has_error": bool(error),
        "has_analysis": bool(analysis),
    }


def _redact_text(value: Any, *, limit: int = 6000) -> str:
    text = str(value or "")
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[REDACTED]", text)
    if len(text) > limit:
        text = text[:limit] + "…[truncated]"
    return text


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True)
class JevChoiceAdvice:
    question_id: str
    choice: str
    confidence: float
    probabilities: dict[str, float]
    authoritative: bool = False
    request_id: str | None = None
    evidence_sha256: str | None = None
    backend: str | None = None
    state_sha256: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class JevAdvisoryLog:
    """Privacy-minimized JSONL record of JEV advice.

    Raw prompts/state are not written.  Each row stores a state hash plus the typed
    decision, confidence and fabric evidence identifiers.  This is deliberately an
    *advisory* audit stream and is never a promotion authority source.
    """

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None

    def append(
        self,
        event: str,
        advice: JevChoiceAdvice,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "ts": time.time(),
            "event": event,
            "advice": advice.to_dict(),
            "metadata": dict(metadata or {}),
        }
        data = json.dumps(row, sort_keys=True, default=str) + "\n"
        with self.path.open("a", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass


class JevAdvisor:
    """Bounded LocalJevFabric/SystemOne client for AIDE-DREAM-RSI.

    The advisor can influence only the *repairability classification* of an already
    observed failed node, and only when confidence clears a configured threshold.
    Branch ranking, model routing and verification-depth calls are shadow/advisory by
    default.  JEV therefore cannot add legal actions, execute tools, alter replay
    history, promote policies, change evaluators, or bypass the sandbox.
    """

    FAILURE_CRITERIA = {
        "repairable_implementation": "The core direction may still be sound; this is a local implementation, syntax, shape/layout, numerical, or runtime bug that can plausibly be repaired.",
        "resource_or_timeout": "The attempt failed primarily because of time, memory, process, or other resource pressure and may be repairable by implementation changes.",
        "environment_dependency": "The failure comes from missing dependencies/data, permissions, sandbox policy, unavailable hardware, or environment mismatch rather than evidence for the algorithmic direction.",
        "structural_algorithm": "The observed evidence indicates the core approach or algorithmic direction itself is invalid or inappropriate, not merely mis-implemented.",
        "uncertain": "The available evidence is insufficient to classify the failure safely.",
    }

    MODEL_ROUTE_CRITERIA = {
        "keep_default": "Use the configured default coding model.",
        "fast_coder": "A fast low-cost coder is sufficient for a local or mechanical change.",
        "reasoning_coder": "Use the stronger reasoning coder because the proposed change requires deeper architectural or algorithmic reasoning.",
    }

    VERIFICATION_CRITERIA = {
        "fast": "Use the minimum normal verification path; the change is local and low-risk.",
        "normal": "Use the standard evaluator and regression checks.",
        "extended": "Use additional verification because the change is broad, risky, ambiguous, or close to an authority/promotion boundary.",
    }

    def __init__(
        self,
        *,
        enabled: bool = False,
        endpoint: str = "http://127.0.0.1:8090/v1/systemone",
        model: str = "local-jev-fabric",
        api_key: str | None = None,
        timeout_s: float = 1.5,
        confidence_threshold: float = 0.72,
        fail_open: bool = True,
        max_state_chars: int = 12000,
        failure_classification: bool = True,
        failure_influence: bool = False,
        shadow_action_ranking: bool = True,
        shadow_model_routing: bool = False,
        shadow_verification_depth: bool = False,
        log: JevAdvisoryLog | None = None,
        post_fn: Callable[..., Any] | None = None,
    ):
        self.enabled = bool(enabled)
        self.endpoint = endpoint.rstrip("/")
        if not self.endpoint.endswith("/v1/systemone"):
            self.endpoint += "/v1/systemone"
        self.model = str(model)
        self.api_key = api_key
        self.timeout_s = max(0.05, float(timeout_s))
        self.confidence_threshold = min(1.0, max(0.0, float(confidence_threshold)))
        self.fail_open = bool(fail_open)
        self.max_state_chars = max(512, int(max_state_chars))
        self.failure_classification_enabled = bool(failure_classification)
        self.failure_influence = bool(failure_influence)
        self.shadow_action_ranking_enabled = bool(shadow_action_ranking)
        self.shadow_model_routing_enabled = bool(shadow_model_routing)
        self.shadow_verification_depth_enabled = bool(shadow_verification_depth)
        self.log = log or JevAdvisoryLog(None)
        self._post_fn = post_fn or requests.post

    @classmethod
    def from_config(
        cls, cfg: Any, *, log_path: str | Path | None = None
    ) -> "JevAdvisor":
        api_key = None
        api_key_env = str(getattr(cfg, "api_key_env", "FABRIC_API_KEY") or "")
        if api_key_env:
            api_key = os.environ.get(api_key_env)
        return cls(
            enabled=bool(getattr(cfg, "enabled", False)),
            endpoint=str(
                getattr(cfg, "endpoint", "http://127.0.0.1:8090/v1/systemone")
            ),
            model=str(getattr(cfg, "model", "local-jev-fabric")),
            api_key=api_key,
            timeout_s=float(getattr(cfg, "timeout_s", 1.5)),
            confidence_threshold=float(getattr(cfg, "confidence_threshold", 0.72)),
            fail_open=bool(getattr(cfg, "fail_open", True)),
            max_state_chars=int(getattr(cfg, "max_state_chars", 12000)),
            failure_classification=bool(getattr(cfg, "failure_classification", True)),
            failure_influence=bool(getattr(cfg, "failure_influence", False)),
            shadow_action_ranking=bool(getattr(cfg, "shadow_action_ranking", True)),
            shadow_model_routing=bool(getattr(cfg, "shadow_model_routing", False)),
            shadow_verification_depth=bool(
                getattr(cfg, "shadow_verification_depth", False)
            ),
            log=JevAdvisoryLog(log_path),
        )

    def _ask_choice(
        self,
        *,
        question_id: str,
        state: Any,
        instructions: str,
        criteria: Mapping[str, str],
    ) -> JevChoiceAdvice:
        safe_state = _redact_text(state, limit=self.max_state_chars)
        state_hash = _stable_hash(safe_state)
        if not self.enabled:
            return JevChoiceAdvice(
                question_id, "", 0.0, {}, state_sha256=state_hash, error="disabled"
            )
        payload = {
            "state": safe_state,
            "model": self.model,
            "questions": {
                question_id: {
                    "type": "choice",
                    "instructions": str(instructions),
                    "criteria": dict(criteria),
                }
            },
        }
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        try:
            response = self._post_fn(
                self.endpoint, json=payload, headers=headers, timeout=self.timeout_s
            )
            status = int(getattr(response, "status_code", 200))
            if status >= 400:
                raise RuntimeError(
                    f"SystemOne HTTP {status}: {_redact_text(getattr(response, 'text', ''), limit=600)}"
                )
            body = response.json()
            if not isinstance(body, Mapping):
                raise ValueError("SystemOne response is not an object")
            answers = body.get("answers")
            if not isinstance(answers, Mapping) or not isinstance(
                answers.get(question_id), Mapping
            ):
                raise ValueError("SystemOne response missing typed answer")
            answer = dict(answers[question_id])
            if answer.get("type") != "choice":
                raise ValueError("SystemOne answer type mismatch")
            choice = str(answer.get("choice", ""))
            if choice not in criteria:
                raise ValueError(f"SystemOne returned undeclared choice {choice!r}")
            probs_raw = answer.get("probabilities")
            if not isinstance(probs_raw, Mapping) or set(probs_raw) != set(criteria):
                raise ValueError("SystemOne probability keys do not match criteria")
            probs = {str(k): float(v) for k, v in probs_raw.items()}
            if (
                any((not 0.0 <= x <= 1.0) for x in probs.values())
                or abs(sum(probs.values()) - 1.0) > 0.02
            ):
                raise ValueError("SystemOne probabilities are invalid")
            confidence = float(answer.get("confidence", max(probs.values())))
            if not 0.0 <= confidence <= 1.0:
                raise ValueError("SystemOne confidence is invalid")
            fabric = (
                body.get("fabric") if isinstance(body.get("fabric"), Mapping) else {}
            )
            decisions = (
                fabric.get("decisions")
                if isinstance(fabric, Mapping)
                and isinstance(fabric.get("decisions"), Mapping)
                else {}
            )
            qmeta = (
                decisions.get(question_id)
                if isinstance(decisions, Mapping)
                and isinstance(decisions.get(question_id), Mapping)
                else {}
            )
            backend = (
                str(qmeta.get("backend"))
                if qmeta and qmeta.get("backend") is not None
                else None
            )
            return JevChoiceAdvice(
                question_id=question_id,
                choice=choice,
                confidence=confidence,
                probabilities=probs,
                # Even if LocalJevFabric says direct_authorized, AIDE-RSI treats the
                # result as non-authoritative.  This field is informational only.
                authoritative=False,
                request_id=(
                    str(fabric.get("request_id"))
                    if fabric and fabric.get("request_id")
                    else None
                ),
                evidence_sha256=(
                    str(fabric.get("evidence_sha256"))
                    if fabric and fabric.get("evidence_sha256")
                    else None
                ),
                backend=backend,
                state_sha256=state_hash,
            )
        except Exception as exc:
            advice = JevChoiceAdvice(
                question_id,
                "",
                0.0,
                {},
                state_sha256=state_hash,
                error=_redact_text(repr(exc), limit=700),
            )
            if self.fail_open:
                return advice
            raise RuntimeError(f"JEV advisory request failed: {advice.error}") from exc

    def classify_failure(
        self, *, fail_class: str, error: str | None, analysis: str | None = None
    ) -> JevChoiceAdvice | None:
        if not (self.enabled and self.failure_classification_enabled):
            return None
        state = _failure_summary(fail_class, error, analysis)
        state["constraint"] = (
            "Classify only the observed failure. Do not infer hidden results or propose an action."
        )
        advice = self._ask_choice(
            question_id="dream.failure_class.v1",
            state=state,
            instructions=(
                "Classify the observed AIDE attempt failure for search-control purposes. "
                "Prefer uncertain when evidence is weak. This answer cannot grant execution authority."
            ),
            criteria=self.FAILURE_CRITERIA,
        )
        self.log.append(
            "failure_classification",
            advice,
            metadata={"observed_fail_class": state["observed_failure_class"]},
        )
        return advice

    def repairability(
        self, *, fail_class: str, error: str | None, analysis: str | None = None
    ) -> tuple[str | None, JevChoiceAdvice | None]:
        advice = self.classify_failure(
            fail_class=fail_class, error=error, analysis=analysis
        )
        if (
            advice is None
            or advice.error
            or advice.confidence < self.confidence_threshold
        ):
            return None, advice
        if not self.failure_influence:
            return None, advice
        if advice.choice in {"repairable_implementation", "resource_or_timeout"}:
            return "repairable", advice
        if advice.choice in {"environment_dependency", "structural_algorithm"}:
            return "hard", advice
        return "uncertain", advice

    @staticmethod
    def _prefix_summary(state: Mapping[str, Any]) -> dict[str, Any]:
        observed = state.get("observed") or {}
        rows: list[dict[str, Any]] = []
        if isinstance(observed, Mapping):
            for obs in sorted(
                observed.values(),
                key=lambda x: (getattr(x, "step", 0), getattr(x, "id", "")),
            )[-24:]:
                rows.append(
                    {
                        "id": str(getattr(obs, "id", "")),
                        "parent": str(getattr(obs, "parent_id", "")),
                        "depth": int(getattr(obs, "depth", 0) or 0),
                        "score": getattr(obs, "score", None),
                        "valid": bool(getattr(obs, "valid", False)),
                        "fail_class": str(getattr(obs, "fail_class", "")),
                        "delta_vs_parent": getattr(obs, "delta_vs_parent", None),
                        "repairability": getattr(obs, "repairability", None),
                    }
                )
        return {
            "observed": rows,
            "probes": int(state.get("probes", len(rows)) or 0),
            "support_score": float(state.get("support_score", 1.0) or 0.0),
            "maximize": bool(state.get("maximize", True)),
        }

    def shadow_rank_actions(
        self, state: Mapping[str, Any], deterministic_batch: list[str]
    ) -> JevChoiceAdvice | None:
        if not (self.enabled and self.shadow_action_ranking_enabled):
            return None
        legal = list(state.get("legal_actions") or [])
        if not legal:
            return None
        # Bound question cardinality; this is a shadow diagnostic, not a source of
        # legal actions. Deterministic policy keeps authority over the batch.
        legal = legal[:24]
        criteria: dict[str, str] = {}
        for a in legal:
            aid = str(a.get("action_id"))
            kind = str(a.get("kind"))
            parent = str(a.get("parent_id"))
            criteria[aid] = (
                "Open a new independent search root"
                if kind == "open_root"
                else f"Refine the currently revealed frontier {parent}"
            )
        advice = self._ask_choice(
            question_id="dream.branch_action.v1",
            state={
                "prefix": self._prefix_summary(state),
                "deterministic_batch": list(deterministic_batch),
            },
            instructions=(
                "Choose the single most promising currently legal search action from the declared criteria. "
                "Use only the revealed prefix. The result is shadow advice and cannot add actions or override the deterministic DREAM policy."
            ),
            criteria=criteria,
        )
        self.log.append(
            "action_ranking_shadow",
            advice,
            metadata={
                "deterministic_batch": list(deterministic_batch),
                "agreement": bool(
                    deterministic_batch and advice.choice == deterministic_batch[0]
                ),
            },
        )
        return advice

    def shadow_model_route(self, context: Mapping[str, Any]) -> JevChoiceAdvice | None:
        if not (self.enabled and self.shadow_model_routing_enabled):
            return None
        advice = self._ask_choice(
            question_id="dream.model_route.v1",
            state=dict(context),
            instructions=(
                "Select the coding-model tier appropriate for this already-authorized generation request. "
                "This is shadow advice only and cannot change model authority or execute a tool."
            ),
            criteria=self.MODEL_ROUTE_CRITERIA,
        )
        self.log.append("model_route_shadow", advice)
        return advice

    def shadow_verification_depth(
        self, context: Mapping[str, Any]
    ) -> JevChoiceAdvice | None:
        if not (self.enabled and self.shadow_verification_depth_enabled):
            return None
        advice = self._ask_choice(
            question_id="dream.verification_depth.v1",
            state=dict(context),
            instructions=(
                "Select an appropriate verification depth for this candidate. "
                "This is shadow advice only; the fixed evaluator and qualification gates remain authoritative."
            ),
            criteria=self.VERIFICATION_CRITERIA,
        )
        self.log.append("verification_depth_shadow", advice)
        return advice

    def doctor(self) -> dict[str, Any]:
        advice = self._ask_choice(
            question_id="dream.doctor.v1",
            state="AIDE-DREAM-RSI JEV integration connectivity check.",
            instructions="Return the declared healthy option.",
            criteria={
                "healthy": "The SystemOne service can answer a typed bounded choice."
            },
        )
        return {
            "enabled": self.enabled,
            "endpoint": self.endpoint,
            "ok": advice.choice == "healthy" and not advice.error,
            "advice": advice.to_dict(),
        }
