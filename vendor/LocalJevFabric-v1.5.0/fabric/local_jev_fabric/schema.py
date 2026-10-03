from __future__ import annotations

from typing import Any, Mapping


class AnswerValidationError(ValueError):
    pass


def _prob(value: Any, name: str) -> float:
    try:
        x = float(value)
    except (TypeError, ValueError) as exc:
        raise AnswerValidationError(f"{name} must be numeric") from exc
    if not 0.0 <= x <= 1.0:
        raise AnswerValidationError(f"{name} must be in [0,1]")
    return x


def validate_answer(question: Mapping[str, Any], answer: Mapping[str, Any]) -> dict[str, Any]:
    qtype = question.get("type")
    atype = answer.get("type")
    if qtype != atype:
        raise AnswerValidationError(f"answer type {atype!r} does not match question type {qtype!r}")

    out = dict(answer)
    if qtype == "noul":
        out["noul"] = _prob(answer.get("noul"), "noul")
        return out

    if qtype == "choice":
        criteria = question.get("criteria")
        if not isinstance(criteria, Mapping) or not criteria:
            raise AnswerValidationError("choice question criteria must be a non-empty object")
        choice = answer.get("choice")
        if choice not in criteria:
            raise AnswerValidationError(f"choice {choice!r} is not a declared criterion")
        probabilities = answer.get("probabilities")
        if not isinstance(probabilities, Mapping):
            raise AnswerValidationError("choice probabilities must be an object")
        keys = set(probabilities)
        expected = set(criteria)
        if keys != expected:
            raise AnswerValidationError("choice probability keys do not match criteria")
        probs = {str(k): _prob(v, f"probabilities[{k!r}]") for k, v in probabilities.items()}
        total = sum(probs.values())
        if abs(total - 1.0) > 0.02:
            raise AnswerValidationError(f"choice probabilities must sum to ~1 (got {total:.6f})")
        out["probabilities"] = probs
        out["confidence"] = _prob(answer.get("confidence", max(probs.values())), "confidence")
        return out

    if qtype == "score":
        out["confidence"] = _prob(answer.get("confidence"), "confidence")
        score = answer.get("score")
        if not isinstance(score, (int, float)):
            raise AnswerValidationError("score answer must contain a numeric score")
        out["score"] = float(score)
        return out

    raise AnswerValidationError(f"unsupported question type {qtype!r}")
