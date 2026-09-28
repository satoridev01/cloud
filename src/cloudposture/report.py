"""Run the controls against a tenant and build the assessment document.

The document's `findings` array is the ingest contract: each entry has id, title, severity, resource,
description and remediation as plain, finished prose, plus `affected` (the objects, with portal links)
and `evidence` (the facts it was decided from). A control that could not run is listed under
`controls` with its reason and never becomes a finding."""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import __version__
from .context import Tenant
from .model import REGISTRY, SEVERITIES, Control, Finding, NotApplicable, NotEvaluated, resource_line

SCHEMA = "https://github.com/satoridev01/cloud#assessment-v1"

NOUNS = {
    "conditionalAccessPolicy": ("Conditional Access policy", "Conditional Access policies"),
    "user": ("Account", "accounts"),
    "servicePrincipal": ("Application", "applications"),
    "application": ("App registration", "app registrations"),
    "directoryRole": ("Directory role", "directory roles"),
    "group": ("Group", "groups"),
    "domain": ("Domain", "domains"),
    "authenticationMethod": ("Authentication method", "authentication methods"),
    "tenantSetting": ("Tenant setting", "tenant settings"),
    "tenant": ("Tenant", "tenants"),
}


def _resource(f: Finding) -> str:
    if f.resource:
        return f.resource
    kinds = {a.type for a in f.affected}
    if len(kinds) == 1:
        noun, plural = NOUNS.get(next(iter(kinds)), ("Object", "objects"))
        return resource_line(noun, plural, f.affected)
    return resource_line("Object", "objects", f.affected)


def _finding_json(c: Control, f: Finding, index: int, total: int) -> dict[str, Any]:
    return {
        "id": c.id if total == 1 else f"{c.id}.{index + 1}",
        "control": c.id,
        "category": c.category,
        "title": f.title,
        "severity": f.severity if f.severity in SEVERITIES else "medium",
        "resource": _resource(f),
        "description": f.description,
        "remediation": f.remediation,
        "affected": [a.to_json() for a in f.affected],
        "evidence": f.evidence,
        "references": [r.to_json() for r in c.references],
        **({"licence": c.licence} if c.licence else {}),
    }


def run(tenant: Tenant, only: set[str] | None = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    for c in REGISTRY:
        if only and c.id not in only:
            continue
        row: dict[str, Any] = {"id": c.id, "title": c.title, "category": c.category}
        try:
            tenant.require(c.licence)
            produced = c.check(tenant)
            row["status"] = "fail" if produced else "pass"
            row["findings"] = len(produced)
            findings.extend(_finding_json(c, f, i, len(produced)) for i, f in enumerate(produced))
        except NotApplicable as e:
            row.update(status="not_applicable", reason=e.reason)
        except NotEvaluated as e:
            row.update(status="not_evaluated", reason=e.reason, permissions=list(c.permissions))
        except Exception as e:  # noqa: BLE001 — one broken control must not sink the assessment
            row.update(status="error", reason=f"{type(e).__name__}: {e}")
        controls.append(row)

    rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["id"]))
    statuses = Counter(c["status"] for c in controls)
    org = _safe(lambda: tenant.organization, {})
    return {
        "schema": SCHEMA,
        "tool": {"name": "cloud-posture", "version": __version__},
        "provider": "m365",
        "tenant": {
            "id": org.get("id"),
            "displayName": org.get("displayName"),
            "defaultDomain": next((d.get("name") for d in org.get("verifiedDomains") or [] if d.get("isDefault")), None),
        },
        "generatedAt": tenant.now.isoformat(),
        "licences": _safe(lambda: tenant.licences, {}),
        "summary": {
            "controls": len(controls),
            "failed": statuses.get("fail", 0),
            "passed": statuses.get("pass", 0),
            "notApplicable": statuses.get("not_applicable", 0),
            "notEvaluated": statuses.get("not_evaluated", 0),
            "errors": statuses.get("error", 0),
            "findings": len(findings),
            "bySeverity": dict(Counter(f["severity"] for f in findings)),
            "graphCalls": tenant.graph.calls,
        },
        "controls": controls,
        "permissionGaps": tenant.permission_gaps,
        "findings": findings,
    }


def _safe(fn, default):
    try:
        return fn()
    except (NotEvaluated, NotApplicable):
        return default
