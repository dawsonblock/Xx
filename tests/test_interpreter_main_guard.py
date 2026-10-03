"""Regression tests for the interpreter's execution globals.

Agent-generated code very often wraps its body in the standard
`if __name__ == "__main__":` guard. If the interpreter execs that code with an
empty globals dict, `__name__` resolves through builtins to "builtins", the
guard is False, and the body never runs -- silently, with a clean exit code and
no traceback. See issue #62.
"""

import tempfile
from pathlib import Path

import pytest

from aide.interpreter import Interpreter


@pytest.fixture
def interpreter():
    workdir = Path(tempfile.mkdtemp())
    (workdir / "working").mkdir(exist_ok=True)
    interp = Interpreter(workdir, timeout=60)
    yield interp
    interp.cleanup_session()


def test_dunder_name_is_main(interpreter):
    """`__name__` must be "__main__", as it is when running `python runfile.py`."""
    result = interpreter.run('print(f"name={__name__}")', True)
    assert "name=__main__" in "".join(result.term_out)


def test_main_guard_body_runs(interpreter):
    """The `if __name__ == "__main__":` guard must fire, so main() executes.

    Without it the script exits 0 with no output and no exception -- the agent
    sees a "successful" run that printed no metric.
    """
    code = "\n".join(
        [
            "def main():",
            '    print("CV RMSLE: 0.280261")',
            "",
            'if __name__ == "__main__":',
            "    main()",
        ]
    )
    result = interpreter.run(code, True)
    assert result.exc_type is None
    assert "CV RMSLE: 0.280261" in "".join(result.term_out)


def test_builtins_available(interpreter):
    """Builtins must resolve inside the exec'd script."""
    result = interpreter.run("print(len([1, 2, 3]), max(4, 5))", True)
    assert "3 5" in "".join(result.term_out)


def test_plain_module_level_code_still_works(interpreter):
    """Scripts without a guard must be unaffected by the fix."""
    result = interpreter.run('print("no guard here")', True)
    assert "no guard here" in "".join(result.term_out)


def test_exception_still_reported(interpreter):
    """Errors inside a guarded main() must still surface as exceptions."""
    code = "\n".join(
        [
            "def main():",
            '    raise ValueError("boom")',
            "",
            'if __name__ == "__main__":',
            "    main()",
        ]
    )
    result = interpreter.run(code, True)
    assert result.exc_type == "ValueError"
    assert "boom" in "".join(result.term_out)
