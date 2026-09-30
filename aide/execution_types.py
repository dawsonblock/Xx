"""Small execution result types shared by the runner and sandbox layers."""

from dataclasses import dataclass


@dataclass
class ExecutionResult:
    """Result record that does not import the full AIDE runtime."""

    term_out: list[str]
    exec_time: float
    exc_type: str | None
    exc_info: dict | None = None
    exc_stack: list[tuple] | None = None
