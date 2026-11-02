from __future__ import annotations

from typing import Any


def check_preconditions(preconditions: tuple[dict[str, Any], ...], obj: dict | None) -> str | None:
    """Return a failure reason or None. Preconditions read the target's current state."""
    if obj is None:
        return "target does not exist"
    for p in preconditions:
        prop = p["property"]
        cur = obj.get(prop)
        if "equals" in p and cur != p["equals"]:
            return f"precondition failed: {prop} must equal {p['equals']!r}"
        if "not_equals" in p and cur == p["not_equals"]:
            return f"precondition failed: {prop} must not equal {p['not_equals']!r}"
    return None
