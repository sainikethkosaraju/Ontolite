"""Check / list_objects / who_can over userset rewrites.

Semantics: monotone rewrites (this, computed, ttu, union, intersection) are evaluated top-down as a
LEAST fixpoint: a cyclic dependency contributes false (so group nesting cycles are harmless). A cycle
met while evaluating an exclusion is semantically undefined and raises `CycleUnderExclusion`; depth
beyond `max_depth` raises `DepthExceeded`. Callers treat any AuthzError as DENY (fail closed).
Results are memoised per check only when no cycle was cut beneath them (a cut result may be an
under-approximation that is only valid in its own context), and across checks by
(tuple revision, data version, object, relation, user)."""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from ontolite.authz.model import (
    TTU,
    Computed,
    Exclusion,
    Intersection,
    LinkSet,
    Namespace,
    This,
    Union_,
)
from ontolite.authz.tuples import TupleStore


class AuthzError(RuntimeError):
    """Evaluation could not be completed; the caller MUST deny."""


class DepthExceeded(AuthzError):
    pass


class CycleUnderExclusion(AuthzError):
    pass


class LinkProvider(Protocol):
    def related(self, obj_type: str, obj_id: str, link: str, inverse: bool) -> list[str]: ...
    def version(self) -> int: ...


@dataclass
class _Ctx:
    at: int
    user: str
    memo: dict[tuple[str, str], bool] = field(default_factory=dict)
    stack: list[tuple[str, str]] = field(default_factory=list)
    levels: dict[tuple[str, str], int] = field(default_factory=dict)  # exclusion depth at frame entry
    cuts: int = 0
    in_exclusion: int = 0
    steps: int = 0


def split_obj(o: str) -> tuple[str, str]:
    t, _, i = o.partition(":")
    return t, i


class Authz:
    def __init__(self, namespaces: dict[str, Namespace], tuples: TupleStore,
                 links: LinkProvider | None = None, max_depth: int = 32, max_steps: int = 200_000,
                 cache_size: int = 50_000) -> None:
        self.ns, self.tuples, self.links = namespaces, tuples, links
        self.max_depth, self.max_steps = max_depth, max_steps
        self._cache: OrderedDict[tuple, bool] = OrderedDict()
        self.cache_size = cache_size
        self.cache_hits = 0

    # ------------------------------------------------------------------ public API
    def check(self, obj: str, relation: str, user: str, at: int | None = None) -> bool:
        """Does `user` (e.g. "user:alice") have `relation` on `obj` (e.g. "company:123")?"""
        at = self.tuples.revision if at is None else at
        key = (at, self.links.version() if self.links else 0, obj, relation, user)
        if key in self._cache:
            self.cache_hits += 1
            self._cache.move_to_end(key)
            return self._cache[key]
        res = self._eval_rel(obj, relation, _Ctx(at, user))
        self._cache[key] = res
        if len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)
        return res

    def list_objects(self, obj_type: str, relation: str, user: str, candidates: Iterable[str],
                     at: int | None = None) -> set[str]:
        """Candidate ids of `obj_type` on which `user` has `relation`. The caller supplies the
        candidate universe (every id of that type in the data store)."""
        at = self.tuples.revision if at is None else at
        return {c for c in candidates if self.check(f"{obj_type}:{c}", relation, user, at)}

    def who_can(self, obj: str, relation: str, at: int | None = None) -> set[str]:
        """All known plain users (appearing as subjects) with `relation` on `obj`."""
        at = self.tuples.revision if at is None else at
        pool = self.tuples.users(at)
        return {u for u in pool if self.check(obj, relation, u, at)}

    # ------------------------------------------------------------------ evaluation
    def _eval_rel(self, obj: str, rel: str, ctx: _Ctx) -> bool:
        key = (obj, rel)
        if key in ctx.memo:
            return ctx.memo[key]
        if key in ctx.stack:
            if ctx.in_exclusion > ctx.levels[key]:  # an exclusion lies ON the cycle path
                raise CycleUnderExclusion(f"cycle through {obj}#{rel} passes through an exclusion")
            ctx.cuts += 1
            return False
        if len(ctx.stack) >= self.max_depth:
            raise DepthExceeded(f"depth {self.max_depth} exceeded at {obj}#{rel}")
        ctx.steps += 1
        if ctx.steps > self.max_steps:
            raise DepthExceeded("evaluation budget exceeded")
        otype, _ = split_obj(obj)
        ns = self.ns.get(otype)
        if ns is None or rel not in ns.relations:
            return False  # unknown namespace/relation grants nothing
        cuts_before = ctx.cuts
        ctx.stack.append(key)
        ctx.levels[key] = ctx.in_exclusion
        try:
            res = self._eval(ns.relations[rel], obj, rel, ctx)
        finally:
            ctx.stack.pop()
            ctx.levels.pop(key, None)
        if ctx.cuts == cuts_before or not ctx.stack:
            ctx.memo[key] = res
        return res

    def _eval(self, rw, obj: str, rel: str, ctx: _Ctx) -> bool:
        if isinstance(rw, This):
            for subj in self.tuples.read(obj, rel, ctx.at):
                if subj == ctx.user or (subj.endswith(":*") and subj.split(":")[0] == ctx.user.split(":")[0]):
                    return True
                if "#" in subj:
                    sobj, srel = subj.split("#", 1)
                    if self._eval_rel(sobj, srel, ctx):
                        return True
            return False
        if isinstance(rw, Computed):
            return self._eval_rel(obj, rw.relation, ctx)
        if isinstance(rw, TTU):
            for target in self._tupleset(obj, rw.tupleset, ctx):
                if self._eval_rel(target, rw.relation, ctx):
                    return True
            return False
        if isinstance(rw, Union_):
            return any(self._eval(c, obj, rel, ctx) for c in rw.children)
        if isinstance(rw, Intersection):
            return all(self._eval(c, obj, rel, ctx) for c in rw.children)
        if isinstance(rw, Exclusion):
            ctx.in_exclusion += 1
            try:
                return self._eval(rw.base, obj, rel, ctx) and not self._eval(rw.subtract, obj, rel, ctx)
            finally:
                ctx.in_exclusion -= 1
        if isinstance(rw, LinkSet):  # a bare link used as a relation has no users of its own
            return False
        raise AuthzError(f"unhandled rewrite {rw!r}")

    def _tupleset(self, obj: str, tupleset: str, ctx: _Ctx) -> list[str]:
        otype, oid = split_obj(obj)
        ns = self.ns.get(otype)
        rw = ns.relations.get(tupleset) if ns else None
        out = [s for s in self.tuples.read(obj, tupleset, ctx.at) if "#" not in s and not s.endswith(":*")]
        if isinstance(rw, LinkSet):
            if self.links is None:
                raise AuthzError("link-backed tupleset without a link provider")
            out += [f"{rw.target}:{i}" for i in self.links.related(otype, oid, rw.name, rw.inverse)]
        elif rw is not None and not isinstance(rw, This):
            raise AuthzError(f"{otype}.{tupleset} is not a tupleset (must be `this` or `link`)")
        return out
