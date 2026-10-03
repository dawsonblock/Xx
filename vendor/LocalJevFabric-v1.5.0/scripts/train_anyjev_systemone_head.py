#!/usr/bin/env python3
"""Fit one hardened AnyJev L2 head for an exact SystemOne question.

JSONL rows must contain {"state": <JSON-or-text>, "label": ...}. Choice labels may be the
option name or integer index; noul labels may be true/false, yes/no, or 0/1; score labels are
integer level indices. Re-run with --merge to add another exact task to the same bound bundle.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from anyjev import Decider
from anyjev.backends.hf import HFBackend
from anyjev.systemone import compile_question


def rows(path: str) -> list[dict[str, Any]]:
    out = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict) or "state" not in obj or "label" not in obj:
            raise SystemExit(f"{path}:{n}: expected object with state and label")
        out.append(obj)
    if not out:
        raise SystemExit("no training rows")
    return out


def label_index(q, value: Any) -> int:
    if q.kind == "choice":
        if isinstance(value, int) and not isinstance(value, bool):
            idx = value
        else:
            try:
                idx = q.options.index(str(value))
            except ValueError as exc:
                raise ValueError(f"unknown choice label {value!r}; expected one of {q.options}") from exc
    elif q.kind == "noul":
        if isinstance(value, bool):
            idx = 0 if value else 1  # AnyJev noul options are (Yes, No)
        elif isinstance(value, int) and value in (0, 1):
            idx = value
        else:
            text = str(value).strip().lower()
            if text in {"yes", "true", "y"}:
                idx = 0
            elif text in {"no", "false", "n"}:
                idx = 1
            else:
                raise ValueError(f"invalid noul label {value!r}")
    else:
        idx = int(value)
    if not 0 <= idx < q.k:
        raise ValueError(f"label index {idx} outside [0,{q.k - 1}]")
    return idx


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--revision", default=None, help="pin an immutable revision in production")
    ap.add_argument("--question", required=True, help="JSON file containing one SystemOne question object")
    ap.add_argument("--question-id", default="task")
    ap.add_argument("--labels", required=True, help="JSONL: {state,label}")
    ap.add_argument("--output", required=True)
    ap.add_argument("--merge", action="store_true", help="load the existing output bundle first and add this head")
    ap.add_argument("--device", default="cuda")
    ap.add_argument("--dtype", default="bfloat16")
    ap.add_argument("--batch-size", type=int, default=16)
    ap.add_argument("--layer", type=int, action="append", help="candidate absolute layer; repeat for several")
    args = ap.parse_args()

    spec = json.loads(Path(args.question).read_text())
    if not isinstance(spec, dict):
        raise SystemExit("--question must contain a JSON object")
    q = compile_question(args.question_id, spec)
    data = rows(args.labels)
    states = [x["state"] for x in data]
    labels = [label_index(q, x["label"]) for x in data]

    backend = HFBackend(args.model, device=args.device, dtype=args.dtype,
                        batch_size=args.batch_size, revision=args.revision)
    decider = Decider(backend)
    out = Path(args.output)
    if args.merge and out.exists():
        decider.load_artifacts(str(out))
    art = decider.fit_head(q, states, labels, layers=args.layer)
    decider.save_artifacts(str(out))
    print(json.dumps({
        "output": str(out), "question_key": q.key, "question_id": q.id,
        "n_labels": len(labels), "method": art.get("method"), "layer_abs": art.get("layer_abs"),
        "oof_acc": (art.get("cv") or {}).get("oof_acc"), "binding": art.get("binding"),
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
