from __future__ import annotations
import argparse
from pathlib import Path
from typing import Optional, List
import subprocess
import tempfile
from .executor import Executor
from .example import run_example
from .x86_lifter import lift_linear_x86


def run_example_command(debug: bool) -> int:
    lines = run_example()
    for line in lines:
        print(line)
    return 0


def _print_bugs(bugs) -> int:
    if not bugs:
        print("no bugs found")
        return 0
    for bug in bugs:
        print(bug.to_string())
        print()
    return 0


def run_analyze_bytes(path: Path, frame_size: int, debug: bool) -> int:
    data = path.read_bytes()
    program = lift_linear_x86(data, frame_size=frame_size)
    executor = Executor(debug=debug)
    bugs = executor.run(program)
    return _print_bugs(bugs)


def run_analyze_c(path: Path, frame_size: int, cc: str, debug: bool, extra_cflags: Optional[List[str]] = None) -> int:
    if extra_cflags is None:
        extra_cflags = []
    with tempfile.TemporaryDirectory() as tmpdir:
        o_path = Path(tmpdir) / "tmp.o"
        bin_path = Path(tmpdir) / "tmp.bin"
        cmd_compile = [cc, "-O0", "-fno-omit-frame-pointer", "-c", str(path), "-o", str(o_path)]
        cmd_compile.extend(extra_cflags)
        subprocess.run(cmd_compile, check=True)
        cmd_objcopy = ["objcopy", "-O", "binary", "--only-section=.text", str(o_path), str(bin_path)]
        subprocess.run(cmd_objcopy, check=True)
        data = bin_path.read_bytes()
    program = lift_linear_x86(data, frame_size=frame_size)
    executor = Executor(debug=debug)
    bugs = executor.run(program)
    return _print_bugs(bugs)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="symexec")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_example = sub.add_parser("example")
    p_example.add_argument("--debug", action="store_true")
    p_example.set_defaults(func=lambda args: run_example_command(args.debug))

    p_analyze_bytes = sub.add_parser("analyze-bytes")
    p_analyze_bytes.add_argument("path", type=Path)
    p_analyze_bytes.add_argument("--frame-size", type=int, default=64)
    p_analyze_bytes.add_argument("--debug", action="store_true")
    p_analyze_bytes.set_defaults(
        func=lambda args: run_analyze_bytes(args.path, args.frame_size, args.debug)
    )

    p_analyze_c = sub.add_parser("analyze-c")
    p_analyze_c.add_argument("path", type=Path)
    p_analyze_c.add_argument("--frame-size", type=int, default=64)
    p_analyze_c.add_argument("--cc", type=str, default="gcc")
    p_analyze_c.add_argument("--debug", action="store_true")
    p_analyze_c.set_defaults(
        func=lambda args: run_analyze_c(args.path, args.frame_size, args.cc, args.debug)
    )

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
