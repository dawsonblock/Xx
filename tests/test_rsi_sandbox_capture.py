import sys
from pathlib import Path

from aide.rsi.sandbox import SecureInterpreter


def test_candidate_cannot_redirect_host_output_capture_to_host_file(tmp_path: Path):
    secret = tmp_path / "host-secret.txt"
    secret.write_text("HOST_SECRET_SENTINEL")
    work = tmp_path / "candidate"
    work.mkdir()
    sandbox = SecureInterpreter(tmp_path, mode="process", allow_insecure_process=True)

    code = (
        "import time\n"
        "from pathlib import Path\n"
        # Let the host establish its pipe drainers before replacing the old
        # workspace capture path. The final host result read must still use its
        # private capture file, never this candidate-controlled symlink.
        "time.sleep(0.1)\n"
        "Path('.stdout').unlink(missing_ok=True)\n"
        f"Path('.stdout').symlink_to({str(secret)!r})\n"
        "print('candidate output')\n"
    )
    result = sandbox._run_subprocess(
        [sys.executable, "-c", code], work, backend="test", cwd=work
    )

    output = "".join(result.term_out)
    assert "candidate output" in output
    assert "HOST_SECRET_SENTINEL" not in output
    assert secret.read_text() == "HOST_SECRET_SENTINEL"
    assert not list(tmp_path.glob("rsi-capture-*"))
