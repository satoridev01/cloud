"""The finding contract and the control registry.

A control inspects the tenant and returns the findings it produced — an empty list means it passed.
Every finding names the objects it is about (`affected`), so a reader can go straight to the policy,
account or app, and carries the raw facts it was decided from (`evidence`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

SEVERITIES = ("critical", "high", "medium", "low", "info")


class NotEvaluated(Exception):
    """A control could not run: a missing Graph permission, or data the tenant does not expose."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class NotApplicable(Exception):
    """A control does not apply to this tenant, e.g. it needs a licence the tenant does not have."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Affected:
    """One object a finding is about."""

    type: str
    id: str
    name: str
    portal_url: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"type": self.type, "id": self.id, "name": self.name}
        if self.portal_url:
            out["portalUrl"] = self.portal_url
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Reference:
    framework: str
    id: str
    url: str | None = None

    def to_json(self) -> dict[str, Any]:
        out = {"framework": self.framework, "id": self.id}
        if self.url:
            out["url"] = self.url
        return out


@dataclass
class Finding:
    title: str
    severity: str
    description: str
    remediation: str
    affected: list[Affected] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    # Set by the runner from the control, unless the control overrides it for this finding.
    resource: str | None = None


@dataclass
class Control:
    id: str
    title: str
    category: str
    check: Callable[[Any], list[Finding]]
    # What the control needs to be meaningful: a licence tier, and the Graph permissions it reads with.
    licence: str | None = None
    permissions: tuple[str, ...] = ()
    references: tuple[Reference, ...] = ()


REGISTRY: list[Control] = []


def control(
    id: str,
    title: str,
    category: str,
    *,
    licence: str | None = None,
    permissions: tuple[str, ...] = (),
    references: tuple[Reference, ...] = (),
) -> Callable[[Callable[[Any], list[Finding]]], Callable[[Any], list[Finding]]]:
    """Register a control check."""

    def wrap(fn: Callable[[Any], list[Finding]]) -> Callable[[Any], list[Finding]]:
        REGISTRY.append(Control(id, title, category, fn, licence, permissions, references))
        return fn

    return wrap


def cisa(id: str) -> Reference:
    return Reference("CISA SCuBA", id, "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md")


def cis(id: str) -> Reference:
    return Reference("CIS Microsoft 365 Foundations", id)


def maester(id: str) -> Reference:
    return Reference("Maester", id, f"https://maester.dev/docs/tests/{id}")


def listing(names: list[str], limit: int = 5) -> str:
    """'A, B and C' — capped, with how many more were left out."""
    names = [n for n in names if n]
    if not names:
        return ""
    shown = names[:limit]
    rest = len(names) - len(shown)
    if rest:
        return f"{', '.join(shown)} and {rest} more"
    if len(shown) == 1:
        return shown[0]
    return f"{', '.join(shown[:-1])} and {shown[-1]}"


LOCATION_LIMIT = 30


def resource_line(noun: str, plural: str, affected: list[Affected]) -> str:
    """The one-line location of a finding: the object, or how many and which."""
    if not affected:
        return noun
    if len(affected) == 1:
        return f"{noun}: {affected[0].name}"
    # The location names every object; only a very long list is cut (the rest stay in `affected`).
    return f"{len(affected)} {plural}: {listing([a.name for a in affected], limit=LOCATION_LIMIT)}"
