from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Principal:
    id: str
    kind: str = "user"  # user | agent
    roles: tuple[str, ...] = ()
    acts_for: str | None = None
