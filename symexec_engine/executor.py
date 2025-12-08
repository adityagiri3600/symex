from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Union, Optional
import z3
from .ir import (
    Program,
    BasicBlock,
    Instr,
    Input,
    Const,
    BinOp,
    BinOpKind,
    Cmp,
    CmpOpKind,
    Sext,
    Load,
    Store,
    Assert,
    CondBr,
    Jump,
    Return,
)
from .bugs import BugReport


@dataclass
class SymbolicState:
    block: str
    vars: Dict[str, z3.ExprRef] = field(default_factory=dict)
    types: Dict[str, Union[int, str]] = field(default_factory=dict)
    path_cond: List[z3.BoolRef] = field(default_factory=list)
    inputs: List[str] = field(default_factory=list)


class Executor:
    def _expr_for_operand(
        self,
        state: SymbolicState,
        operand: Union[str, int],
        bits: Optional[int] = None,
        expect_bool: bool = False,
    ) -> z3.ExprRef:
        if isinstance(operand, str):
            if operand not in state.vars:
                raise KeyError(f"unknown variable {operand}")
            return state.vars[operand]
        if expect_bool:
            return z3.BoolVal(bool(operand))
        if bits is None:
            raise ValueError("bits required for integer operand")
        return z3.BitVecVal(operand, bits)

    def _clone_state(self, state: SymbolicState) -> SymbolicState:
        return SymbolicState(
            block=state.block,
            vars=dict(state.vars),
            types=dict(state.types),
            path_cond=list(state.path_cond),
            inputs=list(state.inputs),
        )

    def _check_sat(self, constraints: List[z3.BoolRef]) -> Optional[z3.ModelRef]:
        solver = z3.Solver()
        for c in constraints:
            solver.add(c)
        result = solver.check()
        if result == z3.sat:
            return solver.model()
        return None

    def _extract_inputs(self, state: SymbolicState, model: z3.ModelRef) -> Dict[str, int]:
        values: Dict[str, int] = {}
        for name in state.inputs:
            expr = state.vars[name]
            val = model.eval(expr, model_completion=True)
            if isinstance(val, z3.BitVecNumRef):
                values[name] = val.as_long()
            elif isinstance(val, z3.IntNumRef):
                values[name] = val.as_long()
            else:
                if z3.is_true(val):
                    values[name] = 1
                else:
                    values[name] = 0
        return values

    def _record_bug(
        self,
        program: Program,
        state: SymbolicState,
        kind: str,
        message: str,
        bug_condition: z3.BoolRef,
        addr_expr: Optional[z3.ExprRef] = None,
    ) -> Optional[BugReport]:
        constraints = list(state.path_cond)
        constraints.append(bug_condition)
        model = self._check_sat(constraints)
        if model is None:
            return None
        inputs = self._extract_inputs(state, model)
        addr_value: Optional[int] = None
        if addr_expr is not None:
            v = model.eval(addr_expr, model_completion=True)
            if isinstance(v, z3.BitVecNumRef):
                addr_value = v.as_long()
        path_strings = [str(c) for c in state.path_cond]
        return BugReport(
            kind=kind,
            message=message,
            inputs=inputs,
            addr_value=addr_value,
            path_constraints=path_strings,
        )

    def _exec_instr(
        self,
        program: Program,
        state: SymbolicState,
        instr: Instr,
        bugs: List[BugReport],
        worklist: List[SymbolicState],
    ) -> str:
        if isinstance(instr, Input):
            bv = z3.BitVec(instr.dest, instr.bits)
            state.vars[instr.dest] = bv
            state.types[instr.dest] = instr.bits
            state.inputs.append(instr.dest)
            return "continue"

        if isinstance(instr, Const):
            bv = z3.BitVecVal(instr.value, instr.bits)
            state.vars[instr.dest] = bv
            state.types[instr.dest] = instr.bits
            return "continue"

        if isinstance(instr, Sext):
            src = state.vars[instr.src]
            src_bits = state.types[instr.src]
            if not isinstance(src_bits, int):
                raise TypeError("sext source must be bitvector")
            if instr.dest_bits <= src_bits:
                raise ValueError("dest_bits must be greater than source width")
            ext = z3.SignExt(instr.dest_bits - src_bits, src)
            state.vars[instr.dest] = ext
            state.types[instr.dest] = instr.dest_bits
            return "continue"

        if isinstance(instr, BinOp):
            lhs = self._expr_for_operand(state, instr.lhs, bits=instr.bits)
            rhs = self._expr_for_operand(state, instr.rhs, bits=instr.bits)
            if instr.op == BinOpKind.ADD:
                res = lhs + rhs
            elif instr.op == BinOpKind.SUB:
                res = lhs - rhs
            elif instr.op == BinOpKind.MUL:
                res = lhs * rhs
            elif instr.op == BinOpKind.AND:
                res = lhs & rhs
            elif instr.op == BinOpKind.OR:
                res = lhs | rhs
            elif instr.op == BinOpKind.XOR:
                res = lhs ^ rhs
            else:
                raise NotImplementedError(f"unsupported binop {instr.op}")
            state.vars[instr.dest] = res
            state.types[instr.dest] = instr.bits
            return "continue"

        if isinstance(instr, Cmp):
            lhs = self._expr_for_operand(state, instr.lhs, bits=instr.bits)
            rhs = self._expr_for_operand(state, instr.rhs, bits=instr.bits)
            if instr.op == CmpOpKind.EQ:
                res = lhs == rhs
            elif instr.op == CmpOpKind.NE:
                res = lhs != rhs
            elif instr.op == CmpOpKind.SLT:
                res = z3.SLT(lhs, rhs)
            elif instr.op == CmpOpKind.SLE:
                res = z3.SLE(lhs, rhs)
            elif instr.op == CmpOpKind.SGT:
                res = z3.SGT(lhs, rhs)
            elif instr.op == CmpOpKind.SGE:
                res = z3.SGE(lhs, rhs)
            elif instr.op == CmpOpKind.ULT:
                res = z3.ULT(lhs, rhs)
            elif instr.op == CmpOpKind.ULE:
                res = z3.ULE(lhs, rhs)
            elif instr.op == CmpOpKind.UGT:
                res = z3.UGT(lhs, rhs)
            elif instr.op == CmpOpKind.UGE:
                res = z3.UGE(lhs, rhs)
            else:
                raise NotImplementedError(f"unsupported cmp {instr.op}")
            state.vars[instr.dest] = res
            state.types[instr.dest] = "bool"
            return "continue"

        if isinstance(instr, Load):
            addr_expr = self._expr_for_operand(state, instr.addr, bits=64)
            size_bv = z3.BitVecVal(instr.size, 64)
            frame_limit = z3.BitVecVal(program.frame_size, 64)
            zero = z3.BitVecVal(0, 64)
            ok0 = z3.ULE(zero, addr_expr)
            ok1 = z3.ULE(addr_expr + size_bv, frame_limit)
            ok = z3.And(ok0, ok1)
            bug_cond = z3.Not(ok)
            bug = self._record_bug(
                program=program,
                state=state,
                kind="OOB_LOAD",
                message=f"out-of-bounds load of {instr.size} bytes",
                bug_condition=bug_cond,
                addr_expr=addr_expr,
            )
            if bug is not None:
                bugs.append(bug)
            dest_bits = instr.size * 8
            val = z3.BitVec(instr.dest, dest_bits)
            state.vars[instr.dest] = val
            state.types[instr.dest] = dest_bits
            return "continue"

        if isinstance(instr, Store):
            addr_expr = self._expr_for_operand(state, instr.addr, bits=64)
            size_bv = z3.BitVecVal(instr.size, 64)
            frame_limit = z3.BitVecVal(program.frame_size, 64)
            zero = z3.BitVecVal(0, 64)
            ok0 = z3.ULE(zero, addr_expr)
            ok1 = z3.ULE(addr_expr + size_bv, frame_limit)
            ok = z3.And(ok0, ok1)
            bug_cond = z3.Not(ok)
            bug = self._record_bug(
                program=program,
                state=state,
                kind="OOB_STORE",
                message=f"out-of-bounds store of {instr.size} bytes",
                bug_condition=bug_cond,
                addr_expr=addr_expr,
            )
            if bug is not None:
                bugs.append(bug)
            return "continue"

        if isinstance(instr, Assert):
            cond = self._expr_for_operand(state, instr.cond, expect_bool=True)
            bug_cond = z3.Not(cond)
            bug = self._record_bug(
                program=program,
                state=state,
                kind="ASSERT_FAIL",
                message=instr.message,
                bug_condition=bug_cond,
            )
            if bug is not None:
                bugs.append(bug)
            return "continue"

        if isinstance(instr, CondBr):
            cond = self._expr_for_operand(state, instr.cond, expect_bool=True)
            true_state = self._clone_state(state)
            true_state.block = instr.true_target
            true_state.path_cond.append(cond)
            false_state = self._clone_state(state)
            false_state.block = instr.false_target
            false_state.path_cond.append(z3.Not(cond))
            if self._check_sat(true_state.path_cond) is not None:
                worklist.append(true_state)
            if self._check_sat(false_state.path_cond) is not None:
                worklist.append(false_state)
            return "stop"

        if isinstance(instr, Jump):
            state.block = instr.target
            worklist.append(state)
            return "stop"

        if isinstance(instr, Return):
            return "stop"

        raise NotImplementedError(f"unsupported instruction {type(instr)}")

    def run(self, program: Program) -> List[BugReport]:
        bugs: List[BugReport] = []
        initial = SymbolicState(block=program.entry)
        worklist: List[SymbolicState] = [initial]
        while worklist:
            state = worklist.pop()
            while True:
                block = program.blocks[state.block]
                progressed = False
                for instr in block.instructions:
                    action = self._exec_instr(program, state, instr, bugs, worklist)
                    progressed = True
                    if action == "stop":
                        break
                if not progressed or action == "stop":
                    break
        return bugs
