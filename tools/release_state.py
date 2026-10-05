"""Fail-closed release qualification state transitions."""

from __future__ import annotations

from enum import StrEnum


class ReleaseState(StrEnum):
    DEVELOPMENT = "DEVELOPMENT"
    SOURCE_FROZEN = "SOURCE_FROZEN"
    SOURCE_QUALIFICATION_IN_PROGRESS = "SOURCE_QUALIFICATION_IN_PROGRESS"
    SOURCE_QUALIFIED = "SOURCE_QUALIFIED"
    BUILD_IN_PROGRESS = "BUILD_IN_PROGRESS"
    ARTIFACTS_BUILT = "ARTIFACTS_BUILT"
    ARTIFACTS_QUALIFIED = "ARTIFACTS_QUALIFIED"
    RELEASE_QUALIFIED = "RELEASE_QUALIFIED"
    RELEASED = "RELEASED"


_TRANSITIONS = {
    ReleaseState.DEVELOPMENT: frozenset({ReleaseState.SOURCE_FROZEN}),
    ReleaseState.SOURCE_FROZEN: frozenset(
        {ReleaseState.SOURCE_QUALIFICATION_IN_PROGRESS}
    ),
    ReleaseState.SOURCE_QUALIFICATION_IN_PROGRESS: frozenset(
        {ReleaseState.SOURCE_QUALIFIED}
    ),
    ReleaseState.SOURCE_QUALIFIED: frozenset({ReleaseState.BUILD_IN_PROGRESS}),
    ReleaseState.BUILD_IN_PROGRESS: frozenset({ReleaseState.ARTIFACTS_BUILT}),
    ReleaseState.ARTIFACTS_BUILT: frozenset({ReleaseState.ARTIFACTS_QUALIFIED}),
    ReleaseState.ARTIFACTS_QUALIFIED: frozenset({ReleaseState.RELEASE_QUALIFIED}),
    ReleaseState.RELEASE_QUALIFIED: frozenset({ReleaseState.RELEASED}),
    ReleaseState.RELEASED: frozenset(),
}


def transition(current: ReleaseState | str, target: ReleaseState | str) -> ReleaseState:
    try:
        current_state = ReleaseState(current)
        target_state = ReleaseState(target)
    except ValueError as error:
        raise ValueError("unknown release state") from error
    if target_state not in _TRANSITIONS[current_state]:
        raise ValueError(
            f"illegal release transition: {current_state} -> {target_state}"
        )
    return target_state
