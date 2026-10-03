"""Jev/SystemOne wire adapter for AnyJev.

This module intentionally compiles a SystemOne question into one exact AnyJev Question. The full
question JSON becomes part of the question text, so L2 artifact identity changes whenever the
instructions, criteria, or descriptions change. That makes the HTTP boundary compatible with the
hardened exact-task routing contract.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np

from anyjev.question import Question
from anyjev.result import Decision


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def compile_question(question_id: str, spec: Mapping[str, Any]) -> Question:
    typ = spec.get("type")
    # The canonical wire spec is included verbatim in the semantic task identity. Option labels are
    # still exposed separately because the AnyJev readout needs the candidate vocabulary.
    text = "SystemOne question: " + canonical_json(dict(spec))
    if typ == "choice":
        criteria = spec.get("criteria")
        if not isinstance(criteria, Mapping) or len(criteria) < 2:
            raise ValueError(f"choice question {question_id!r} needs at least two criteria")
        options = sorted((str(k) for k in criteria.keys()))
        return Question.choice(text, options, name=question_id)
    if typ == "noul":
        criteria = spec.get("criteria")
        if criteria is not None and not isinstance(criteria, Mapping):
            raise ValueError(f"noul question {question_id!r} criteria must be an object")
        return Question.noul(text, name=question_id)
    if typ == "score":
        criteria = spec.get("criteria")
        if not isinstance(criteria, Sequence) or isinstance(criteria, (str, bytes)):
            raise ValueError(f"score question {question_id!r} criteria must be an array")
        if not 2 <= len(criteria) <= 10:
            raise ValueError(f"score question {question_id!r} needs 2 to 10 levels")
        # Keep the original level descriptions in the options. The wire answer still uses integer
        # levels, not these strings.
        return Question.score(text, levels=[canonical_json(x) for x in criteria], name=question_id)
    raise ValueError(f"question {question_id!r} type must be choice, score, or noul")


def compile_questions(specs: Mapping[str, Any]) -> list[Question]:
    out = []
    for qid, spec in specs.items():
        if not isinstance(qid, str) or not qid:
            raise ValueError("question IDs must be non-empty strings")
        if not isinstance(spec, Mapping):
            raise ValueError(f"question {qid!r} must be an object")
        out.append(compile_question(qid, spec))
    if not out:
        raise ValueError("questions must not be empty")
    return out


def _choice_answer(decision: Decision) -> dict[str, Any]:
    return {"type": "choice", "choice": decision.argmax, "confidence": decision.confidence,
            "probabilities": decision.distribution}


def _noul_answer(decision: Decision) -> dict[str, Any]:
    return {"type": "noul", "noul": decision.p_true}


def _score_answer(decision: Decision, spec: Mapping[str, Any]) -> dict[str, Any]:
    criteria = list(spec["criteria"])
    probs = {str(i): float(p) for i, p in enumerate(decision.probs)}
    score = float(np.dot(np.arange(len(decision.probs), dtype=float), decision.probs))
    return {"type": "score", "score": score, "confidence": decision.confidence,
            "legend": {str(i): v for i, v in enumerate(criteria)}, "probabilities": probs}


def answer_to_systemone(decision: Decision, spec: Mapping[str, Any]) -> dict[str, Any]:
    typ = spec.get("type")
    if typ == "choice":
        return _choice_answer(decision)
    if typ == "noul":
        return _noul_answer(decision)
    if typ == "score":
        return _score_answer(decision, spec)
    raise ValueError(f"unsupported question type {typ!r}")


@dataclass
class SystemOneEngine:
    decider: Any
    model: str = "anyjev"
    level: str = "auto"
    require_level: str | None = "L2"

    def evaluate(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if payload.get("model") != self.model:
            raise LookupError("The requested model does not exist")
        if "state" not in payload:
            raise ValueError("state is required")
        specs = payload.get("questions")
        if not isinstance(specs, Mapping):
            raise ValueError("questions must be an object")
        questions = compile_questions(specs)
        result = self.decider.decide(payload["state"], questions, level=self.level, require=self.require_level)
        answers = {q.id: answer_to_systemone(result[q.id], specs[q.id]) for q in questions}
        return {"model": self.model, "answers": answers, "usage": {"input_tokens": 0, "output_tokens": 0}}
