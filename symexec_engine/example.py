from __future__ import annotations
from typing import List
from .ir import (
    Program,
    BasicBlock,
    Input,
    Const,
    BinOp,
    BinOpKind,
    Sext,
    Load,
    Return,
)
from .executor import Executor


def build_example_program() -> Program:
    block = BasicBlock(name="entry")
    instructions = []
    instructions.append(Input(dest="idx", bits=32))
    instructions.append(Sext(dest="idx64", src="idx", dest_bits=64))
    instructions.append(Const(dest="arr_base", bits=64, value=0))
    instructions.append(Const(dest="elem_size", bits=64, value=4))
    instructions.append(
        BinOp(
            op=BinOpKind.MUL,
            dest="offset",
            lhs="idx64",
            rhs="elem_size",
            bits=64,
        )
    )
    instructions.append(
        BinOp(
            op=BinOpKind.ADD,
            dest="addr",
            lhs="arr_base",
            rhs="offset",
            bits=64,
        )
    )
    instructions.append(Load(dest="val", addr="addr", size=4))
    instructions.append(Return(value="val"))
    block.instructions = instructions
    program = Program(blocks={"entry": block}, entry="entry", frame_size=32)
    return program


def run_example() -> List[str]:
    program = build_example_program()
    executor = Executor()
    bugs = executor.run(program)
    lines: List[str] = []
    if not bugs:
        lines.append("no bugs found")
    else:
        for bug in bugs:
            lines.append(bug.to_string())
    return lines
