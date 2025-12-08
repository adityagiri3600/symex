from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import Optional
from .executor import Executor
from .example import run_example
from .x86_lifter import lift_linear_x86


def run_example_command() -> int:
    lines = run_example()
    for line in lines:
        print(line)
    return 0


def run_analyze_bytes(path: Path, frame_size: int) -> int:
    data = path.read_bytes()
    program = lift_linear_x86(data, frame_size=frame_size)
    executor = Executor()
    bugs = executor.run(program)
    if not bugs:
        print("no bugs found")
        return 0
    for bug in bugs:
        print(bug.to_string())
        print()
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="symexec")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_example = sub.add_parser("example")
    p_example.set_defaults(func=lambda args: run_example_command())

    p_analyze = sub.add_parser("analyze-bytes")
    p_analyze.add_argument("path", type=Path)
    p_analyze.add_argument("--frame-size", type=int, default=64)
    p_analyze.set_defaults(
        func=lambda args: run_analyze_bytes(args.path, args.frame_size)
    )

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
