from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Union


class Instr:
    pass


@dataclass
class Input(Instr):
    dest: str
    bits: int

@dataclass
class Assume(Instr):
    cond: str

@dataclass
class Const(Instr):
    dest: str
    bits: int
    value: int


class BinOpKind(str, Enum):
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    AND = "and"
    OR = "or"
    XOR = "xor"


@dataclass
class BinOp(Instr):
    op: BinOpKind
    dest: str
    lhs: Union[str, int]
    rhs: Union[str, int]
    bits: int


class CmpOpKind(str, Enum):
    EQ = "eq"
    NE = "ne"
    SLT = "slt"
    SLE = "sle"
    SGT = "sgt"
    SGE = "sge"
    ULT = "ult"
    ULE = "ule"
    UGT = "ugt"
    UGE = "uge"


@dataclass
class Cmp(Instr):
    op: CmpOpKind
    dest: str
    lhs: Union[str, int]
    rhs: Union[str, int]
    bits: int


@dataclass
class Sext(Instr):
    dest: str
    src: str
    dest_bits: int


@dataclass
class Load(Instr):
    dest: str
    addr: str
    size: int


@dataclass
class Store(Instr):
    addr: str
    value: str
    size: int


@dataclass
class Assert(Instr):
    cond: str
    message: str


@dataclass
class CondBr(Instr):
    cond: str
    true_target: str
    false_target: str


@dataclass
class Jump(Instr):
    target: str


@dataclass
class Return(Instr):
    value: Optional[str] = None


@dataclass
class BasicBlock:
    name: str
    instructions: List[Instr] = field(default_factory=list)


@dataclass
class Program:
    blocks: Dict[str, BasicBlock]
    entry: str
    frame_size: int
