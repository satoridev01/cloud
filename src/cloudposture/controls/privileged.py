"""Privileged access: who holds the roles that control the tenant, and how exposed those accounts are."""

from __future__ import annotations

from typing import Any

from ..context import (
    GLOBAL_ADMIN,
    MICROSOFT_TENANTS,
    PRIVILEGED_ROLES,
    Tenant,
    display,
    parse_time,
    principal_kind,
    principal_url,
    role_url,
    sp_url,
    user_url,
)
from .. import cvss
from ..model import Affected, Finding, NotEvaluated, cis, cisa, control, listing, maester

# RoleManagement.Read.Directory also reads PIM eligibility; GroupMember.Read.All expands group-held roles.
PERMS = ("RoleManagement.Read.Directory", "Directory.Read.All", "GroupMember.Read.All")
STALE_DAYS = 45
WEAK_ONLY = {"mobilePhone", "alternateMobilePhone", "officePhone", "email"}


def _roles_by_principal(t: Tenant) -> dict[str, dict[str, Any]]:
    """principal id → {principal, roles: [template ids], how: {template id: [how it is held]}} over
    privileged roles, active or PIM-eligible, with group-held roles expanded to the group's members."""
    return {
        pid: {"principal": row["principal"], "roles": list(row["roles"]), "how": row["roles"]}
        for pid, row in t.privileged_holders.items()
    }


def _tier(roles: list[str]) -> int:
    return min(PRIVILEGED_ROLES[r][1] for r in roles) if roles else 9


def _tier_of(t: Tenant, uid: str) -> int:
    return _tier(_roles_by_principal(t).get(uid, {}).get("roles", []))


def _role_names(roles: list[str]) -> list[str]:
    return [PRIVILEGED_ROLES[r][0] for r in sorted(roles, key=lambda r: PRIVILEGED_ROLES[r][1])]


def _held_as(row: dict[str, Any]) -> dict[str, str]:
    """Role name → how it is held, for every role not held as a plain active assignment: an eligible
    role still has to be activated, so a reader must not take it for standing access."""
    out = {}
    for template, ways in (row.get("how") or {}).items():
        if "active" not in ways:
            out[PRIVILEGED_ROLES[template][0]] = "; ".join(ways)
    return out


def _labels(a: Affected) -> str:
    held = a.detail.get("heldAs") or {}
    return ", ".join(f"{r} ({held[r]})" if r in held else r for r in a.detail["roles"])


def _user_affected(t: Tenant, uid: str, row: dict[str, Any], **detail: Any) -> Affected:
    user = t.users.get(uid, {"id": uid})
    held = _held_as(row)
    return Affected(
        "user", uid, display(user), user_url(uid), {"roles": _role_names(row["roles"]), **({"heldAs": held} if held else {}), **detail}
    )


@control(
    "M365-PRV-01",
    "Global Administrator count outside 2–8",
    "Privileged access",
    permissions=PERMS,
    references=(cisa("MS.AAD.7.1"), cis("1.1.3"), maester("MT.1024.oneAdmin")),
)
def global_admin_count(t: Tenant) -> list[Finding]:
    # Eligible holders count, as CISA's count does: each can activate the role whenever they choose.
    rows = [r for r in _roles_by_principal(t).values() if GLOBAL_ADMIN in r["roles"] and principal_kind(r["principal"]) == "user"]
    if 2 <= len(rows) <= 8:
        return []
    affected = [_user_affected(t, r["principal"]["id"], r) for r in rows]
    indirect = [a for a in affected if a.detail.get("heldAs")]
    note = (
        f" {len(indirect)} of them hold it only as PIM-eligible or through a group: "
        + listing([f"{a.name} ({a.detail['heldAs']['Global Administrator']})" for a in indirect])
        + "."
        if indirect
        else ""
    )
    few = len(rows) < 2
    holders = [a.get("principal") or {} for a in t.role_assignments if t.role_template(a) == GLOBAL_ADMIN]
    return [
        Finding(
            title=("Only one Global Administrator" if len(rows) == 1 else "No user holds Global Administrator")
            if few
            else f"{len(rows)} users hold Global Administrator",
            severity="low" if few else "medium",
            cvss=cvss.AVAILABILITY if few else cvss.WEAKENED_DEFENCE,
            description=(
                (
                    f"{len(rows)} user account(s) hold Global Administrator, active or eligible"
                    + (f" ({listing([a.name for a in affected])})" if affected else "")
                    + ". With fewer than two, losing that one account (lockout, departure, compromise with "
                    "credential reset) leaves nobody able to administer the tenant, with no second account to "
                    "fall back on."
                )
                if few
                else (
                    f"{len(rows)} user accounts hold Global Administrator, active or eligible. Every one of them "
                    "can take over the whole tenant, so each extra holder widens the attack surface; the "
                    "recommended range is two to eight, with day-to-day work done in narrower roles."
                )
            )
            + note,
            remediation=(
                (
                    "Create a second, cloud-only emergency-access account (no mailbox, excluded from Conditional "
                    "Access, phishing-resistant credential stored offline, sign-in alert) and assign it Global "
                    "Administrator. Keep the total between two and eight."
                )
                if few
                else (
                    "Review each Global Administrator in Entra admin center > Roles and administrators > Global "
                    "Administrator. Move people to the least-privileged role that covers their work (Exchange, "
                    "SharePoint, User, Security Administrator…) and, with Entra ID P2, make the rest eligible "
                    "through PIM instead of permanently active."
                )
            ),
            affected=affected,
            evidence={
                "globalAdminUsers": [a.id for a in affected],
                "heldAs": {a.id: a.detail["heldAs"]["Global Administrator"] for a in indirect},
                "globalAdminServicePrincipals": [p.get("id") for p in holders if principal_kind(p) == "servicePrincipal"],
            },
            resource="Directory role: Global Administrator",
        )
    ]


@control(
    "M365-PRV-02",
    "Applications (service principals) hold privileged directory roles",
    "Privileged access",
    permissions=PERMS + ("Application.Read.All",),
    references=(cisa("MS.AAD.7.4"), maester("MT.1027")),
)
def sp_with_roles(t: Tenant) -> list[Finding]:
    rows = [r for r in _roles_by_principal(t).values() if principal_kind(r["principal"]) == "servicePrincipal"]
    if not rows:
        return []
    affected = []
    for r in sorted(rows, key=lambda r: _tier(r["roles"])):
        sp: dict[str, Any] = t.service_principals.get(r["principal"]["id"]) or r["principal"]
        owner = sp.get("appOwnerOrganizationId")
        origin = "Microsoft" if owner in MICROSOFT_TENANTS else ("this tenant" if owner == t.organization.get("id") else "third party")
        affected.append(
            Affected(
                "servicePrincipal",
                sp["id"],
                sp.get("displayName", sp["id"]),
                sp_url(sp["id"], sp.get("appId")),
                {
                    "roles": _role_names(r["roles"]),
                    "appId": sp.get("appId"),
                    "publisher": origin,
                    **t.credentials(sp),
                },
            )
        )
    tier0 = [a for a, r in zip(affected, sorted(rows, key=lambda r: _tier(r["roles"]))) if _tier(r["roles"]) == 0]
    third = [a for a in affected if a.detail["publisher"] == "third party"]
    return [
        Finding(
            title="Applications hold administrator roles in the directory",
            severity="critical" if tier0 else "high",
            cvss=cvss.TENANT_TAKEOVER if tier0 else cvss.PASSWORD_TO_DATA,
            description=(
                f"{len(affected)} service principal(s) hold privileged directory roles: "
                + listing([f"{a.name} ({_labels(a)})" for a in affected])
                + ". An application signs in with a client secret or certificate, not interactively, so MFA and "
                "most Conditional Access do not apply to it: whoever obtains that credential gets the role. "
                + (f"{len(tier0)} of them hold a role that reaches Global Administrator. " if tier0 else "")
                + (
                    f"{len(third)} belong to third parties (e.g. an MSP/CSP or security vendor), so the tenant's "
                    "control plane also depends on that vendor's own security."
                    if third
                    else ""
                )
            ),
            remediation=(
                "For each application: confirm it still needs the role and who owns it. Replace directory roles "
                "with the narrowest Microsoft Graph application permission that covers the integration, or scope "
                "the role to an administrative unit. Remove third-party roles that are no longer contracted, "
                "prefer certificates or managed identities over client secrets, rotate any secret that has "
                "existed for long, and alert on the service principal's sign-ins (Workload ID Premium adds "
                "Conditional Access for workload identities)."
            ),
            affected=affected,
            evidence={"assignments": [{"servicePrincipal": a.id, "roles": a.detail["roles"]} for a in affected]},
        )
    ]


@control(
    "M365-PRV-03",
    "Privileged roles held by accounts synced from on-premises",
    "Privileged access",
    permissions=PERMS + ("User.Read.All",),
    references=(cisa("MS.AAD.7.3"),),
)
def synced_admins(t: Tenant) -> list[Finding]:
    rows = [
        r
        for r in _roles_by_principal(t).values()
        if principal_kind(r["principal"]) == "user" and t.users.get(r["principal"]["id"], {}).get("onPremisesSyncEnabled")
    ]
    if not rows:
        return []
    affected = [_user_affected(t, r["principal"]["id"], r) for r in rows]
    return [
        Finding(
            title="Administrator accounts are synchronised from on-premises Active Directory",
            # Reaching these accounts needs the on-premises domain first, hence high rather than critical.
            severity="high" if any(_tier(r["roles"]) == 0 for r in rows) else "medium",
            cvss=cvss.ONPREM_TO_CLOUD if any(_tier(r["roles"]) == 0 for r in rows) else cvss.ONPREM_TO_CLOUD_LIMITED,
            description=(
                f"{len(affected)} account(s) with privileged Entra roles are synchronised from on-premises Active "
                "Directory: " + listing([f"{a.name} ({_labels(a)})" for a in affected])
                + ". Anyone who compromises the on-premises domain can reset these accounts' passwords and "
                "inherit their cloud roles, so an on-prem breach becomes a Microsoft 365 takeover."
            ),
            remediation=(
                "Create separate cloud-only administrator accounts (name@tenant.onmicrosoft.com or a cloud-only "
                "domain), move the role assignments to them, and remove the roles from the synced accounts. Keep "
                "the synced account for day-to-day work only."
            ),
            affected=affected,
            evidence={"syncedPrivilegedUsers": [a.id for a in affected]},
        )
    ]


@control(
    "M365-PRV-04",
    "Inactive accounts keep privileged roles",
    "Privileged access",
    licence="Entra ID P1",
    permissions=PERMS + ("AuditLog.Read.All",),
    references=(maester("MT.1029"),),
)
def stale_admins(t: Tenant) -> list[Finding]:
    affected = []
    worst = 9
    for r in _roles_by_principal(t).values():
        if principal_kind(r["principal"]) != "user":
            continue
        uid = r["principal"]["id"]
        activity = t.sign_in_activity(uid)
        last = max(
            filter(None, (parse_time(activity.get(k)) for k in ("lastSuccessfulSignInDateTime", "lastSignInDateTime", "lastNonInteractiveSignInDateTime"))),
            default=None,
        )
        created = parse_time(t.users.get(uid, {}).get("createdDateTime"))
        if last is None and created and (t.now - created).days < STALE_DAYS:
            continue
        idle = None if last is None else (t.now - last).days
        if idle is None or idle >= STALE_DAYS:
            affected.append(_user_affected(t, uid, r, lastSignIn=last.isoformat() if last else None, daysInactive=idle))
            worst = min(worst, _tier(r["roles"]))
    if not affected:
        return []
    return [
        Finding(
            title=f"Privileged accounts have not signed in for {STALE_DAYS}+ days",
            severity="medium",
            cvss=cvss.WEAKENED_DEFENCE,
            description=(
                f"{len(affected)} account(s) with privileged roles show no sign-in in the last {STALE_DAYS} days: "
                + listing([f"{a.name} ({_labels(a)}, " + ("never signed in" if a.detail["daysInactive"] is None else f"{a.detail['daysInactive']} days") + ")" for a in affected])
                + ". Nobody notices when a dormant admin account is taken over, and its privileges are standing "
                "access no one is using."
            ),
            remediation=(
                "Confirm with each owner whether the account is still needed. Remove the role (or disable the "
                "account) where it is not; where it is, make the role eligible through PIM (Entra ID P2) so it is "
                "only active when used. Add a recurring access review for privileged roles."
            ),
            affected=affected,
            evidence={"thresholdDays": STALE_DAYS, "accounts": [{"id": a.id, **a.detail} for a in affected]},
        )
    ]


@control(
    "M365-PRV-05",
    "Administrators without MFA registered",
    "Privileged access",
    licence="Entra ID P1",
    permissions=PERMS + ("AuditLog.Read.All",),
    references=(cisa("MS.AAD.3.6"), maester("MT.1024.mfaRegistrationV2")),
)
def admins_without_mfa(t: Tenant) -> list[Finding]:
    details = t.registration_details
    none, weak = [], []
    for r in _roles_by_principal(t).values():
        if principal_kind(r["principal"]) != "user":
            continue
        uid = r["principal"]["id"]
        reg = details.get(uid)
        if reg is None:
            continue
        methods = set(reg.get("methodsRegistered") or [])
        if not reg.get("isMfaRegistered"):
            none.append(_user_affected(t, uid, r, methodsRegistered=sorted(methods)))
        elif methods and methods <= WEAK_ONLY:
            weak.append(_user_affected(t, uid, r, methodsRegistered=sorted(methods)))
    if not none and not weak:
        return []
    parts = []
    if none:
        parts.append(f"{len(none)} have no MFA method registered at all ({listing([a.name for a in none])})")
    if weak:
        parts.append(f"{len(weak)} rely only on SMS, voice or email codes ({listing([a.name for a in weak])})")
    return [
        Finding(
            title="Administrators have no MFA, or only phishable MFA, registered",
            severity=("critical" if any(_tier_of(t, a.id) == 0 for a in none) else "high") if none else "medium",
            cvss=(
                (cvss.TENANT_TAKEOVER if any(_tier_of(t, a.id) == 0 for a in none) else cvss.PASSWORD_TO_DATA)
                if none
                else cvss.PHISHABLE_ADMIN_MFA
            ),
            description=(
                "Of the accounts holding privileged roles, " + "; ".join(parts) + ". An administrator without a "
                "registered method can be registered by whoever signs in first with the password; SMS and voice "
                "codes are open to SIM-swap and real-time phishing."
            ),
            remediation=(
                "Have each listed administrator register a phishing-resistant method (FIDO2 security key, passkey "
                "in Microsoft Authenticator, or Windows Hello for Business), then require the 'Phishing-resistant "
                "MFA' authentication strength for administrator roles in Conditional Access. Use a Temporary "
                "Access Pass for the first registration instead of a password-only sign-in."
            ),
            affected=none + weak,
            evidence={"accounts": [{"id": a.id, **a.detail} for a in none + weak]},
        )
    ]


def _permanent(t: Tenant, tier: int) -> dict[str, dict[str, Any]]:
    """user id → {roles, how} for permanent active assignments to roles of this tier. Eligible
    assignments are not read here: a role that must be activated is not standing access."""
    try:
        rows = list(
            t.graph.list("roleManagement/directory/roleAssignmentScheduleInstances?$filter=assignmentType eq 'Assigned'&$expand=principal")
        )
    except Exception as e:  # noqa: BLE001 — surfaced as not evaluated
        raise NotEvaluated(f"Could not read PIM assignment schedules ({e}).") from None
    permanent: dict[str, dict[str, Any]] = {}

    def add(uid: str, template: str, how: str) -> None:
        row = permanent.setdefault(uid, {"roles": [], "how": {}})
        if template not in row["roles"]:
            row["roles"].append(template)
        row["how"].setdefault(template, []).append(how)

    for r in rows:
        template = t.role_template(r)
        principal = r.get("principal") or {}
        if template not in PRIVILEGED_ROLES or PRIVILEGED_ROLES[template][1] != tier or r.get("endDateTime"):
            continue
        if principal_kind(principal) == "user":
            add(principal["id"], template, "active")
        elif principal_kind(principal) == "group":
            group = principal.get("displayName") or t.group_name(principal["id"])
            for uid in sorted(t.group_members(principal["id"])):
                add(uid, template, f"active through group {group}")
    return permanent


PIM_FIX = (
    "In Entra admin center > Identity governance > Privileged Identity Management > Microsoft Entra roles, "
    "convert these assignments to Eligible with a maximum activation of a few hours, and require MFA, "
    "justification and (for Global Administrator) approval on activation. A role held through a group is "
    "made eligible on the group's assignment, or by making membership of the group eligible (PIM for Groups). "
)


@control(
    "M365-PRV-06",
    "Permanent (non-PIM) assignments to highly privileged roles",
    "Privileged access",
    licence="Entra ID P2",
    permissions=("RoleAssignmentSchedule.Read.Directory", "GroupMember.Read.All"),
    references=(cisa("MS.AAD.7.4"), cisa("MS.AAD.7.5")),
)
def permanent_assignments(t: Tenant) -> list[Finding]:
    permanent = _permanent(t, 0)
    if not permanent:
        return []
    affected = [_user_affected(t, uid, row) for uid, row in permanent.items()]
    return [
        Finding(
            title="Highly privileged roles are assigned permanently instead of through PIM",
            severity="low",
            cvss=cvss.STANDING_ACCESS,
            description=(
                f"{len(affected)} user(s) hold a tenant-takeover role as a permanent active assignment although the "
                "tenant has Entra ID P2 (Privileged Identity Management): "
                + listing([f"{a.name} ({_labels(a)})" for a in affected])
                + ". Standing access means the role is usable the moment the account is compromised, with no "
                "activation, justification or approval step."
            ),
            remediation=PIM_FIX + "Keep permanent assignments only for the emergency-access accounts.",
            affected=affected,
            evidence={"permanent": {uid: [PRIVILEGED_ROLES[r][0] for r in row["roles"]] for uid, row in permanent.items()}},
        )
    ]


@control(
    "M365-PRV-07",
    "Privileged roles held through groups that ordinary accounts own",
    "Privileged access",
    licence="Entra ID P1",
    permissions=PERMS,
)
def group_owners(t: Tenant) -> list[Finding]:
    groups: dict[str, dict[str, Any]] = {}
    for a in t.privileged_assignments + [a for a in t.eligible_assignments if t.role_template(a) in PRIVILEGED_ROLES]:
        principal = a.get("principal") or {}
        if principal_kind(principal) == "group":
            row = groups.setdefault(principal["id"], {"group": principal, "roles": []})
            if t.role_template(a) not in row["roles"]:
                row["roles"].append(t.role_template(a))
    holders = _roles_by_principal(t)
    affected, worst = [], "high"
    for gid, row in groups.items():
        name = row["group"].get("displayName") or t.group_name(gid)
        for owner in {o["id"]: o for o in t.owners("groups", gid)}.values():
            if owner.get("accountEnabled") is False:
                continue  # A disabled account cannot sign in to add itself.
            if _tier(holders.get(owner["id"], {}).get("roles", [])) == 0:
                continue  # A tenant administrator can already grant any role.
            if _tier(row["roles"]) == 0:
                worst = "critical"
            affected.append(
                Affected(
                    principal_kind(owner),
                    owner["id"],
                    f"{display(owner)} — owner of group {name}",
                    principal_url(owner),
                    {"group": name, "groupId": gid, "groupGrants": _role_names(row["roles"]), "ownerRoles": _role_names(holders.get(owner["id"], {}).get("roles", []))},
                )
            )
    if not affected:
        return []
    return [
        Finding(
            title="Ordinary accounts own groups that grant administrator roles",
            severity=worst,
            cvss=cvss.OWNER_TAKEOVER if worst == "critical" else cvss.OWNER_TO_DATA,
            description=(
                "A role-assignable group passes its directory roles to every member, and the group's owners can add "
                "members — themselves included — without holding any administrator role. These owners are not tenant "
                "administrators, yet can give themselves the roles their groups hold:\n"
                + "\n".join(f"- {a.name}: the group grants {', '.join(a.detail['groupGrants'])}." for a in affected)
                + "\nCompromising one of these accounts is therefore a path to the group's roles, and the membership "
                "change that grants them is easy to miss next to ordinary group edits."
            ),
            remediation=(
                "Remove these owners (Groups > group > Owners) so only Privileged Role Administrators manage the "
                "group's membership; if delegated management is needed, use PIM for Groups so that membership is "
                "eligible, time-bound and approved. Review the members each group has today, and alert on 'Add "
                "member to group' for role-assignable groups in the audit log."
            ),
            affected=affected,
            evidence={a.id + ":" + a.detail["groupId"]: a.detail for a in affected},
        )
    ]


@control(
    "M365-PRV-08",
    "Permanent (non-PIM) assignments to administrator roles below Global Administrator",
    "Privileged access",
    licence="Entra ID P2",
    permissions=("RoleAssignmentSchedule.Read.Directory", "GroupMember.Read.All"),
    references=(cisa("MS.AAD.7.4"),),
)
def permanent_tier1(t: Tenant) -> list[Finding]:
    permanent = _permanent(t, 1)
    if not permanent:
        return []
    affected = [_user_affected(t, uid, row) for uid, row in permanent.items()]
    return [
        Finding(
            title="Administrator roles over users, apps, mail or security are assigned permanently instead of through PIM",
            severity="low",
            cvss=cvss.STANDING_ACCESS,
            description=(
                f"{len(affected)} user(s) hold an administrator role over a whole workload — users, applications, "
                "Exchange, SharePoint, Conditional Access or security settings — as a permanent active assignment "
                "although the tenant has Entra ID P2: "
                + listing([f"{a.name} ({_labels(a)})" for a in affected])
                + ". These roles stop short of Global Administrator but reach every mailbox, site or user of their "
                "workload, and standing access makes them usable the moment the account is compromised."
            ),
            remediation=PIM_FIX + "Assign the narrower role, or scope it to an administrative unit, where the full role is not needed.",
            affected=affected,
            evidence={"permanent": {uid: [PRIVILEGED_ROLES[r][0] for r in row["roles"]] for uid, row in permanent.items()}},
        )
    ]


__all__ = ["role_url"]
