from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class BugReport:
    kind: str
    message: str
    inputs: Dict[str, int]
    addr_value: Optional[int] = None
    path_constraints: List[str] = field(default_factory=list)

    def to_string(self) -> str:
        lines: List[str] = [f"[BUG] {self.kind}: {self.message}"]
        if self.addr_value is not None:
            lines.append(f"  address = {self.addr_value}")
        if self.inputs:
            lines.append("  inputs:")
            for name, value in self.inputs.items():
                lines.append(f"    {name} = {value}")
        if self.path_constraints:
            lines.append("  path:")
            for c in self.path_constraints:
                lines.append(f"    {c}")
        return "\n".join(lines)
