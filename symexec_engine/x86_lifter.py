from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Tuple
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM
from .ir import (
    Program,
    BasicBlock,
    Input,
    Const,
    BinOp,
    BinOpKind,
    Return,
)


@dataclass
class RegisterSSA:
    versions: Dict[str, int]

    def __init__(self) -> None:
        self.versions = {}

    def _next_version(self, name: str) -> str:
        current = self.versions.get(name, 0) + 1
        self.versions[name] = current
        return f"{name}_{current}"

    def _current_version(self, name: str) -> str:
        if name not in self.versions:
            v = self._next_version(name)
            return v
        return f"{name}_{self.versions[name]}"

    def write(self, reg_name: str) -> str:
        return self._next_version(reg_name)

    def read(self, reg_name: str) -> str:
        return self._current_version(reg_name)


def reg_name_from_id(reg_id: int) -> str:
    return f"r{reg_id}"


def lift_linear_x86(code: bytes, frame_size: int = 64) -> Program:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    block = BasicBlock(name="entry")
    ssa = RegisterSSA()
    instructions: List = []
    arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    for reg in arg_regs:
        dest = ssa.write(reg)
        bits = 64
        instructions.append(Input(dest=dest, bits=bits))
    for insn in md.disasm(code, 0):
        mnem = insn.mnemonic
        ops = insn.operands
        if mnem == "mov" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                dst_name = ssa.write(reg_name_from_id(dst.reg))
                src_name = ssa.read(reg_name_from_id(src.reg))
                instructions.append(
                    BinOp(
                        op=BinOpKind.ADD,
                        dest=dst_name,
                        lhs=src_name,
                        rhs=0,
                        bits=64,
                    )
                )
            elif dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = ssa.write(reg_name_from_id(dst.reg))
                instructions.append(
                    Const(
                        dest=dst_name,
                        bits=64,
                        value=src.imm,
                    )
                )
            else:
                raise NotImplementedError("mov variant not supported")
        elif mnem == "add" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                dst_name = ssa.write(reg_name_from_id(dst.reg))
                lhs = ssa.read(reg_name_from_id(dst.reg))
                rhs = ssa.read(reg_name_from_id(src.reg))
                instructions.append(
                    BinOp(
                        op=BinOpKind.ADD,
                        dest=dst_name,
                        lhs=lhs,
                        rhs=rhs,
                        bits=64,
                    )
                )
            elif dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = ssa.write(reg_name_from_id(dst.reg))
                lhs = ssa.read(reg_name_from_id(dst.reg))
                rhs_imm = src.imm
                instructions.append(
                    BinOp(
                        op=BinOpKind.ADD,
                        dest=dst_name,
                        lhs=lhs,
                        rhs=rhs_imm,
                        bits=64,
                    )
                )
            else:
                raise NotImplementedError("add variant not supported")
        elif mnem == "sub" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = ssa.write(reg_name_from_id(dst.reg))
                lhs = ssa.read(reg_name_from_id(dst.reg))
                rhs_imm = src.imm
                instructions.append(
                    BinOp(
                        op=BinOpKind.SUB,
                        dest=dst_name,
                        lhs=lhs,
                        rhs=rhs_imm,
                        bits=64,
                    )
                )
            else:
                raise NotImplementedError("sub variant not supported")
        elif mnem == "ret":
            ret_reg = ssa.read("rax")
            instructions.append(Return(value=ret_reg))
            break
        else:
            raise NotImplementedError(f"unsupported instruction {mnem}")
    block.instructions = instructions
    program = Program(blocks={"entry": block}, entry="entry", frame_size=frame_size)
    return program
