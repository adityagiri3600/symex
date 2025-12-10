from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_REG, X86_OP_IMM, X86_OP_MEM
from .ir import (
    Cmp,
    CmpOpKind,
    Program,
    BasicBlock,
    Input,
    Const,
    BinOp,
    BinOpKind,
    Load,
    Store,
    Return,
    Assume,
)


CANONICAL_REGS: Dict[str, str] = {
    "al": "rax",
    "ah": "rax",
    "ax": "rax",
    "eax": "rax",
    "rax": "rax",
    "bl": "rbx",
    "bh": "rbx",
    "bx": "rbx",
    "ebx": "rbx",
    "rbx": "rbx",
    "cl": "rcx",
    "ch": "rcx",
    "cx": "rcx",
    "ecx": "rcx",
    "rcx": "rcx",
    "dl": "rdx",
    "dh": "rdx",
    "dx": "rdx",
    "edx": "rdx",
    "rdx": "rdx",
    "sil": "rsi",
    "si": "rsi",
    "esi": "rsi",
    "rsi": "rsi",
    "dil": "rdi",
    "di": "rdi",
    "edi": "rdi",
    "rdi": "rdi",
    "bpl": "rbp",
    "bp": "rbp",
    "ebp": "rbp",
    "rbp": "rbp",
    "spl": "rsp",
    "sp": "rsp",
    "esp": "rsp",
    "rsp": "rsp",
    "r8b": "r8",
    "r8w": "r8",
    "r8d": "r8",
    "r8": "r8",
    "r9b": "r9",
    "r9w": "r9",
    "r9d": "r9",
    "r9": "r9",
    "r10b": "r10",
    "r10w": "r10",
    "r10d": "r10",
    "r10": "r10",
    "r11b": "r11",
    "r11w": "r11",
    "r11d": "r11",
    "r11": "r11",
    "r12b": "r12",
    "r12w": "r12",
    "r12d": "r12",
    "r12": "r12",
    "r13b": "r13",
    "r13w": "r13",
    "r13d": "r13",
    "r13": "r13",
    "r14b": "r14",
    "r14w": "r14",
    "r14d": "r14",
    "r14": "r14",
    "r15b": "r15",
    "r15w": "r15",
    "r15d": "r15",
    "r15": "r15",
}


def canonical_reg(name: str) -> str:
    return CANONICAL_REGS.get(name, name)


@dataclass
class RegisterSSA:
    versions: Dict[str, int]

    def __init__(self) -> None:
        self.versions = {}

    def _next(self, base: str) -> str:
        v = self.versions.get(base, 0) + 1
        self.versions[base] = v
        return f"{base}_{v}"

    def write(self, name: str) -> str:
        base = canonical_reg(name)
        return self._next(base)

    def read_existing(self, name: str) -> Optional[str]:
        base = canonical_reg(name)
        if base not in self.versions:
            return None
        return f"{base}_{self.versions[base]}"

    def read(self, name: str) -> str:
        base = canonical_reg(name)
        if base not in self.versions:
            return self._next(base)
        return f"{base}_{self.versions[base]}"


@dataclass
class StackSlots:
    slots: Dict[int, str]

    def __init__(self) -> None:
        self.slots = {}

    def store(self, disp: int, value: str) -> None:
        self.slots[disp] = value

    def load(self, disp: int) -> Optional[str]:
        return self.slots.get(disp)


def _ensure_reg_input(
    ssa: RegisterSSA,
    insns: List,
    reg_name: str,
    width_bits: int = 64,
) -> str:
    existing = ssa.read_existing(reg_name)
    if existing is not None:
        return existing
    dest = ssa.write(reg_name)
    insns.append(Input(dest=dest, bits=width_bits))
    return dest


def _stack_addr_expr(md: Cs, ssa: RegisterSSA, insns: List, mem, frame_size: int) -> str:
    base_const = frame_size + mem.disp
    base_name = ssa.write("stack_base")
    insns.append(Const(dest=base_name, bits=64, value=base_const))
    addr_name = base_name
    if mem.index != 0:
        idx_name = canonical_reg(md.reg_name(mem.index))
        idx_ssa = _ensure_reg_input(ssa, insns, idx_name, 64)
        scale = mem.scale if mem.scale != 0 else 1
        mul_name = ssa.write("idx_mul")
        insns.append(
            BinOp(
                op=BinOpKind.MUL,
                dest=mul_name,
                lhs=idx_ssa,
                rhs=scale,
                bits=64,
            )
        )
        addr_ssa = ssa.write("addr")
        insns.append(
            BinOp(
                op=BinOpKind.ADD,
                dest=addr_ssa,
                lhs=base_name,
                rhs=mul_name,
                bits=64,
            )
        )
        addr_name = addr_ssa
    return addr_name


def lift_linear_x86(code: bytes, frame_size: int = 64) -> Program:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    block = BasicBlock(name="entry")
    ssa = RegisterSSA()
    stack = StackSlots()
    insns: List = []

    arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
    for reg in arg_regs:
        dest = ssa.write(reg)
        insns.append(Input(dest=dest, bits=64))

    inferred_frame_size: Optional[int] = None
    pending_test_reg: Optional[str] = None

    for insn in md.disasm(code, 0):
        mnem = insn.mnemonic
        ops = insn.operands

        if mnem in ("endbr64", "nop"):
            continue

        mem_with_segment = False
        for op in ops:
            if op.type == X86_OP_MEM and op.mem.segment != 0:
                mem_with_segment = True
                break
        if mem_with_segment:
            continue

        if mnem == "test" and len(ops) == 2:
            if ops[0].type == X86_OP_REG and ops[1].type == X86_OP_REG:
                reg0 = canonical_reg(md.reg_name(ops[0].reg))
                reg1 = canonical_reg(md.reg_name(ops[1].reg))
                if reg0 == reg1:
                    pending_test_reg = reg0
                    continue
            pending_test_reg = None
            continue

        if mnem == "sub" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                reg_name = canonical_reg(md.reg_name(dst.reg))
                if reg_name == "rsp" and src.imm > 0:
                    inferred_frame_size = int(src.imm)
                    continue

        if mnem == "push" and len(ops) == 1:
            continue

        if mnem == "leave":
            continue

        if mnem == "cdqe":
            continue
        
        if mnem in ("jns", "jge"):
            if pending_test_reg is not None:
                reg_name = pending_test_reg
                idx_ssa = _ensure_reg_input(ssa, insns, reg_name, 64)
                cmp_name = ssa.write("cmp")
                insns.append(
                    Cmp(
                        op=CmpOpKind.SGE,
                        dest=cmp_name,
                        lhs=idx_ssa,
                        rhs=0,
                        bits=64,
                    )
                )
                insns.append(Assume(cond=cmp_name))
                pending_test_reg = None
                continue
            continue


        if mnem == "mov" and len(ops) == 2:
            dst, src = ops[0], ops[1]

            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                dst_name_raw = md.reg_name(dst.reg)
                src_name_raw = md.reg_name(src.reg)
                dst_name = canonical_reg(dst_name_raw)
                src_name = canonical_reg(src_name_raw)
                if dst_name == "rbp" and src_name == "rsp":
                    continue
                _ensure_reg_input(ssa, insns, src_name, 64)
                dst_ssa = ssa.write(dst_name)
                src_ssa = ssa.read(src_name)
                insns.append(
                    BinOp(
                        op=BinOpKind.ADD,
                        dest=dst_ssa,
                        lhs=src_ssa,
                        rhs=0,
                        bits=64,
                    )
                )
                continue

            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = canonical_reg(md.reg_name(dst.reg))
                dst_ssa = ssa.write(dst_name)
                insns.append(
                    Const(
                        dest=dst_ssa,
                        bits=64,
                        value=src.imm,
                    )
                )
                continue

            if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
                base_name = canonical_reg(md.reg_name(dst.mem.base)) if dst.mem.base != 0 else ""
                if base_name == "rbp" and dst.mem.index == 0:
                    src_name = canonical_reg(md.reg_name(src.reg))
                    src_ssa = _ensure_reg_input(ssa, insns, src_name, 64)
                    stack.store(dst.mem.disp, src_ssa)
                    continue
                if base_name == "rbp":
                    addr_name = _stack_addr_expr(
                        md=md,
                        ssa=ssa,
                        insns=insns,
                        mem=dst.mem,
                        frame_size=inferred_frame_size or frame_size,
                    )
                    src_name = canonical_reg(md.reg_name(src.reg))
                    src_ssa = _ensure_reg_input(ssa, insns, src_name, 64)
                    size = dst.size if dst.size > 0 else 8
                    insns.append(
                        Store(
                            addr=addr_name,
                            value=src_ssa,
                            size=size,
                        )
                    )
                    continue
                continue

            if dst.type == X86_OP_MEM and src.type == X86_OP_IMM:
                base_name = canonical_reg(md.reg_name(dst.mem.base)) if dst.mem.base != 0 else ""
                if base_name == "rbp" and dst.mem.index == 0:
                    tmp_name = ssa.write("slot_imm")
                    insns.append(Const(dest=tmp_name, bits=64, value=src.imm))
                    stack.store(dst.mem.disp, tmp_name)
                    continue
                continue

            if dst.type == X86_OP_REG and src.type == X86_OP_MEM:
                base_name = canonical_reg(md.reg_name(src.mem.base)) if src.mem.base != 0 else ""
                if base_name == "rbp" and src.mem.index == 0:
                    dst_name = canonical_reg(md.reg_name(dst.reg))
                    dst_ssa = ssa.write(dst_name)
                    slot_val = stack.load(src.mem.disp)
                    if slot_val is not None:
                        insns.append(
                            BinOp(
                                op=BinOpKind.ADD,
                                dest=dst_ssa,
                                lhs=slot_val,
                                rhs=0,
                                bits=64,
                            )
                        )
                        continue
                    tmp_name = ssa.write("stack_load")
                    insns.append(Const(dest=tmp_name, bits=64, value=0))
                    insns.append(
                        BinOp(
                            op=BinOpKind.ADD,
                            dest=dst_ssa,
                            lhs=tmp_name,
                            rhs=0,
                            bits=64,
                        )
                    )
                    continue
                if base_name == "rbp":
                    addr_name = _stack_addr_expr(
                        md=md,
                        ssa=ssa,
                        insns=insns,
                        mem=src.mem,
                        frame_size=inferred_frame_size or frame_size,
                    )
                    dst_name = canonical_reg(md.reg_name(dst.reg))
                    dst_ssa = ssa.write(dst_name)
                    size = src.size if src.size > 0 else 8
                    insns.append(
                        Load(
                            dest=dst_ssa,
                            addr=addr_name,
                            size=size,
                        )
                    )
                    continue
                continue

            continue

        if mnem == "xor" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_REG:
                dst_name = canonical_reg(md.reg_name(dst.reg))
                src_name = canonical_reg(md.reg_name(src.reg))
                if dst_name == src_name:
                    dst_ssa = ssa.write(dst_name)
                    insns.append(Const(dest=dst_ssa, bits=64, value=0))
                    continue
            continue

        if mnem == "add" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = canonical_reg(md.reg_name(dst.reg))
                _ensure_reg_input(ssa, insns, dst_name, 64)
                lhs = ssa.read(dst_name)
                rhs = src.imm
                dst_ssa = ssa.write(dst_name)
                insns.append(
                    BinOp(
                        op=BinOpKind.ADD,
                        dest=dst_ssa,
                        lhs=lhs,
                        rhs=rhs,
                        bits=64,
                    )
                )
                continue
            continue

        if mnem == "sub" and len(ops) == 2:
            dst, src = ops[0], ops[1]
            if dst.type == X86_OP_REG and src.type == X86_OP_IMM:
                dst_name = canonical_reg(md.reg_name(dst.reg))
                _ensure_reg_input(ssa, insns, dst_name, 64)
                lhs = ssa.read(dst_name)
                rhs = src.imm
                dst_ssa = ssa.write(dst_name)
                insns.append(
                    BinOp(
                        op=BinOpKind.SUB,
                        dest=dst_ssa,
                        lhs=lhs,
                        rhs=rhs,
                        bits=64,
                    )
                )
                continue
            continue

        if mnem == "je":
            continue

        if mnem == "call":
            rax_name = _ensure_reg_input(ssa, insns, "rax", 64)
            insns.append(Return(value=rax_name))
            break

        if mnem == "ret":
            rax_name = _ensure_reg_input(ssa, insns, "rax", 64)
            insns.append(Return(value=rax_name))
            break

    block.instructions = insns
    fs = inferred_frame_size if inferred_frame_size is not None else frame_size
    program = Program(blocks={"entry": block}, entry="entry", frame_size=fs)
    return program
