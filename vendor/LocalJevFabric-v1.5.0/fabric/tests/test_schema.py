import pytest

from local_jev_fabric.schema import AnswerValidationError, validate_answer


def test_choice_schema_rejects_wrong_keys():
    q = {"type": "choice", "instructions": "Pick", "criteria": {"a": "A", "b": "B"}}
    with pytest.raises(AnswerValidationError):
        validate_answer(q, {"type": "choice", "choice": "a", "probabilities": {"a": 1.0}, "confidence": 1.0})


def test_noul_rejects_out_of_range():
    with pytest.raises(AnswerValidationError):
        validate_answer({"type": "noul", "instructions": "?"}, {"type": "noul", "noul": 1.2})
