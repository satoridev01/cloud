"""Conditional Access: whether the policies that are supposed to protect sign-ins actually apply."""

from __future__ import annotations

from typing import Any

from ..context import (
    AZURE_MANAGEMENT_APP_ID,
    CA_POLICIES_URL,
    PRIVILEGED_ROLES,
    SECURITY_DEFAULTS_URL,
    Tenant,
    display,
    policy_url,
    principal_kind,
    principal_url,
    role_url,
)
from ..model import Affected, Finding, cisa, control, listing, maester

PERMS = ("Policy.Read.All",)


def _cond(p: dict[str, Any], *path: str) -> Any:
    node: Any = p.get("conditions") or {}
    for key in path:
        node = (node or {}).get(key)
    return node


def _grants(p: dict[str, Any]) -> set[str]:
    return set((p.get("grantControls") or {}).get("builtInControls") or [])


def enforces_mfa(p: dict[str, Any]) -> bool:
    grant = p.get("grantControls") or {}
    return "mfa" in _grants(p) or bool(grant.get("authenticationStrength"))


def blocks(p: dict[str, Any]) -> bool:
    return "block" in _grants(p)


def enabled(p: dict[str, Any]) -> bool:
    return p.get("state") == "enabled"


def has_resources(p: dict[str, Any]) -> bool:
    apps = _cond(p, "applications") or {}
    return bool(
        [a for a in apps.get("includeApplications") or [] if a != "None"]
        or apps.get("includeUserActions")
        or apps.get("includeAuthenticationContextClassReferences")
        or apps.get("applicationFilter")
    )


def has_users(p: dict[str, Any]) -> bool:
    users = _cond(p, "users") or {}
    guests = users.get("includeGuestsOrExternalUsers")
    include = [u for u in users.get("includeUsers") or [] if u != "None"]
    return bool(include or users.get("includeGroups") or users.get("includeRoles") or guests)


def all_users(p: dict[str, Any]) -> bool:
    return "All" in (_cond(p, "users", "includeUsers") or [])


def all_apps(p: dict[str, Any]) -> bool:
    return "All" in (_cond(p, "applications", "includeApplications") or [])


def unconditional(p: dict[str, Any], allow_trusted_locations: bool = False) -> bool:
    """No condition narrows the policy: every platform, location, client app and risk level. With
    `allow_trusted_locations`, a policy that only skips trusted locations still counts."""
    c = p.get("conditions") or {}
    if c.get("signInRiskLevels") or c.get("userRiskLevels") or c.get("servicePrincipalRiskLevels"):
        return False
    platforms = c.get("platforms") or {}
    if platforms and "all" not in [x.lower() for x in platforms.get("includePlatforms") or []]:
        return False
    locations = c.get("locations") or {}
    if locations and "All" not in (locations.get("includeLocations") or []):
        return False
    if locations.get("excludeLocations") and not allow_trusted_locations:
        return False
    clients = c.get("clientAppTypes") or ["all"]
    if "all" not in clients and not {"browser", "mobileAppsAndDesktopClients"} <= set(clients):
        return False
    return True


def scope(p: dict[str, Any]) -> str:
    """How far a policy reaches, in words, for descriptions."""
    users = _cond(p, "users") or {}
    who = "all users" if all_users(p) else (
        f"{len(users.get('includeRoles') or [])} role(s)" if users.get("includeRoles") else
        f"{len(users.get('includeGroups') or [])} group(s)" if users.get("includeGroups") else
        f"{len(users.get('includeUsers') or [])} user(s)"
    )
    what = "all apps" if all_apps(p) else f"{len(_cond(p, 'applications', 'includeApplications') or [])} app(s)"
    return f"{who}, {what}"


def policy_affected(p: dict[str, Any], **detail: Any) -> Affected:
    return Affected("conditionalAccessPolicy", p["id"], p.get("displayName", p["id"]), policy_url(p["id"]), detail)


def policy_evidence(p: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": p["id"],
        "displayName": p.get("displayName"),
        "state": p.get("state"),
        "users": _cond(p, "users"),
        "applications": _cond(p, "applications"),
        "clientAppTypes": _cond(p, "clientAppTypes"),
        "grantControls": p.get("grantControls"),
    }


def baseline_mfa(t: Tenant, allow_trusted_locations: bool = False) -> list[dict[str, Any]]:
    """Enabled policies that require MFA of every user for every app, with nothing narrowing them."""
    return [
        p
        for p in t.ca_policies
        if enabled(p) and enforces_mfa(p) and all_users(p) and all_apps(p) and unconditional(p, allow_trusted_locations)
    ]


@control(
    "M365-CA-01",
    "Conditional Access policies that apply to nothing",
    "Conditional Access",
    permissions=PERMS,
    references=(maester("MT.1184"),),
)
def ca_without_effect(t: Tenant) -> list[Finding]:
    dead = [p for p in t.ca_policies if p.get("state") != "disabled" and (not has_resources(p) or not has_users(p))]
    if not dead:
        return []
    affected = [
        policy_affected(
            p,
            state=p.get("state"),
            missing="target resources" if not has_resources(p) else "users",
            grants=sorted(_grants(p)),
        )
        for p in dead
    ]
    protective = [p for p in dead if enforces_mfa(p) or blocks(p)]
    one = len(dead) == 1
    states = {"enabled" if p.get("state") == "enabled" else "in report-only" for p in dead}
    names = listing([f"'{p.get('displayName')}'" for p in dead])
    if one:
        opening = (
            f"The Conditional Access policy {names} is {next(iter(states))} but selects no "
            f"{'target resources' if not has_resources(dead[0]) else 'users'}, so Entra never applies it. "
        )
        consequence = (
            "It would require MFA or block access, so the control its name promises is not in force — "
            "sign-ins it was meant to challenge go through unchallenged. "
        )
    else:
        opening = (
            f"{len(dead)} Conditional Access policies are {' or '.join(sorted(states))} but select no target "
            f"resources or no users, so Entra never applies them: {names}. "
        )
        consequence = (
            f"{len(protective)} of them would require MFA or block access, so the controls their names "
            "promise are not in force — sign-ins they were meant to challenge go through unchallenged. "
        )
    return [
        Finding(
            title="Conditional Access policies are switched on but protect nothing",
            severity="high" if protective else "medium",
            description=(
                opening
                + (consequence if protective else "")
                + "Policies like this are usually left behind by an edit that removed the last app or group."
            ),
            remediation=(
                "For each policy listed: open it in Entra admin center > Protection > Conditional Access > "
                "Policies, and under 'Target resources' select the apps it is meant to protect (for an "
                "admin-portal or Azure policy, 'Microsoft Admin Portals' and 'Windows Azure Service Management "
                "API'), and under 'Users' the users, groups or roles. Save in report-only first, check the "
                "sign-in logs for the policy's impact, then switch it to On. Delete the policy if it is no "
                "longer needed, so the list reflects what is actually enforced."
            ),
            affected=affected,
            evidence={"policies": [policy_evidence(p) for p in dead]},
        )
    ]


@control(
    "M365-CA-02",
    "MFA is not required for all users",
    "Conditional Access",
    permissions=PERMS,
    references=(cisa("MS.AAD.3.2"),),
)
def mfa_all_users(t: Tenant) -> list[Finding]:
    if t.security_defaults or baseline_mfa(t):
        return []
    located = baseline_mfa(t, allow_trusted_locations=True)
    if located:
        return [
            Finding(
                title="MFA is skipped for sign-ins from trusted locations",
                severity="medium",
                description=(
                    "The tenant-wide MFA polic"
                    + ("y " if len(located) == 1 else "ies ")
                    + listing([f"'{p.get('displayName')}'" for p in located])
                    + (" excludes" if len(located) == 1 else " exclude")
                    + " named or trusted locations, so anyone signing in from those networks needs only a "
                    "password. An attacker who reaches the office network or VPN — or a compromised device already "
                    "on it — faces no second factor, and a trusted IP range that is broader than intended exempts "
                    "far more than the office."
                ),
                remediation=(
                    "Remove the location exclusion from the policy so MFA is required everywhere; if prompts from "
                    "the office are the concern, rely on Windows Hello for Business or passkeys (which satisfy MFA "
                    "without an extra prompt) rather than exempting the network. At minimum, review the named "
                    "locations marked as trusted (Conditional Access > Named locations) and narrow them to the "
                    "egress IPs you actually own."
                ),
                affected=[policy_affected(p, excludedLocations=_cond(p, "locations", "excludeLocations")) for p in located],
                evidence={"policies": [policy_evidence(p) | {"locations": _cond(p, "locations")} for p in located]},
            )
        ]
    partial = [p for p in t.ca_policies if enabled(p) and enforces_mfa(p)]
    detail = (
        "The enabled policies that do require MFA cover only part of the estate: "
        + listing([f"'{p.get('displayName')}' ({scope(p)})" for p in partial])
        + ". "
        if partial
        else "No enabled Conditional Access policy requires MFA at all. "
    )
    return [
        Finding(
            title="MFA is not required for every user and app",
            severity="high",
            description=(
                "Security defaults are off and no enabled Conditional Access policy requires multi-factor "
                "authentication of all users for all cloud apps without narrowing conditions. "
                + detail
                + "Any account outside that coverage can sign in with a password alone, which is what "
                "password spraying and credential-stuffing attacks rely on."
            ),
            remediation=(
                "Create a Conditional Access policy in Entra admin center > Protection > Conditional Access: "
                "Users = All users (exclude only the two emergency-access accounts); Target resources = All "
                "cloud apps; Grant = Require multifactor authentication (or an authentication strength). Run "
                "it in report-only for a few days, review who would be blocked, then turn it On. If the tenant "
                "has no Entra ID P1, enable Security defaults instead."
            ),
            affected=[policy_affected(p, scope=scope(p)) for p in partial]
            or [Affected("tenantSetting", "conditionalAccess", "Conditional Access policies", CA_POLICIES_URL)],
            evidence={"securityDefaults": False, "mfaPolicies": [policy_evidence(p) for p in partial]},
            resource="Tenant: MFA coverage (Conditional Access / security defaults)",
        )
    ]


@control(
    "M365-CA-03",
    "MFA is not required for administrator roles",
    "Conditional Access",
    permissions=PERMS + ("RoleManagement.Read.Directory",),
    references=(cisa("MS.AAD.3.6"),),
)
def mfa_admins(t: Tenant) -> list[Finding]:
    if t.security_defaults or baseline_mfa(t):
        return []
    covered: set[str] = set()
    for p in t.ca_policies:
        if enabled(p) and enforces_mfa(p) and all_apps(p) and unconditional(p):
            covered.update(_cond(p, "users", "includeRoles") or [])
    held: dict[str, int] = {}
    for a in t.privileged_assignments:
        held[t.role_template(a)] = held.get(t.role_template(a), 0) + 1
    uncovered = {role: n for role, n in held.items() if role not in covered}
    if not uncovered:
        return []
    affected = [
        Affected("directoryRole", role, PRIVILEGED_ROLES[role][0], role_url(role), {"activeAssignments": n})
        for role, n in sorted(uncovered.items(), key=lambda kv: PRIVILEGED_ROLES[kv[0]][1])
    ]
    return [
        Finding(
            title="Administrator roles can sign in without MFA",
            severity="high",
            description=(
                f"{len(uncovered)} privileged directory role(s) that have active members are not targeted by any "
                "enabled Conditional Access policy requiring MFA for all apps: "
                + listing([f"{a.name} ({a.detail['activeAssignments']} member(s))" for a in affected])
                + ". A stolen or sprayed password for one of these accounts is enough to take administrative "
                "control of the tenant."
            ),
            remediation=(
                "Create a Conditional Access policy: Users = Directory roles, and select at least Global "
                "Administrator, Privileged Role Administrator, Privileged Authentication Administrator, Security, "
                "Exchange, SharePoint, User, Application and Conditional Access Administrator; Target resources = "
                "All cloud apps; Grant = Require authentication strength 'Phishing-resistant MFA' (or at least "
                "'Require multifactor authentication'). Exclude only the emergency-access accounts."
            ),
            affected=affected,
            evidence={"rolesWithMembersWithoutMfaPolicy": uncovered, "rolesCoveredByMfaPolicies": sorted(covered)},
        )
    ]


@control(
    "M365-CA-04",
    "Legacy authentication is not blocked",
    "Conditional Access",
    permissions=PERMS,
    references=(cisa("MS.AAD.1.1"),),
)
def legacy_auth(t: Tenant) -> list[Finding]:
    if t.security_defaults:
        return []
    for p in t.ca_policies:
        clients = set(_cond(p, "clientAppTypes") or [])
        if enabled(p) and blocks(p) and all_users(p) and all_apps(p) and {"exchangeActiveSync", "other"} <= clients:
            return []
    return [
        Finding(
            title="Legacy authentication protocols are not blocked",
            severity="high",
            description=(
                "No enabled Conditional Access policy blocks legacy authentication (Exchange ActiveSync and "
                "'other clients' such as IMAP, POP, SMTP AUTH and older Office clients) for all users, and "
                "security defaults are off. Legacy protocols cannot perform MFA, so they let an attacker with "
                "a password bypass every MFA policy — most password-spray attacks against Microsoft 365 use them."
            ),
            remediation=(
                "Create a Conditional Access policy: Users = All users (exclude emergency-access accounts); "
                "Target resources = All cloud apps; Conditions > Client apps = Exchange ActiveSync clients and "
                "Other clients; Grant = Block access. Check the sign-in logs (filter Client app = legacy) first "
                "for devices or services that still depend on them, move those to modern auth, then enable."
            ),
            affected=[Affected("tenantSetting", "legacyAuthentication", "Legacy authentication (all users)", CA_POLICIES_URL)],
            evidence={"securityDefaults": False, "policiesBlockingLegacy": []},
        )
    ]


@control(
    "M365-CA-05",
    "Azure management is not protected by MFA",
    "Conditional Access",
    permissions=PERMS,
    references=(maester("MT.1184"),),
)
def azure_management(t: Tenant) -> list[Finding]:
    if t.security_defaults or baseline_mfa(t):
        return []
    partial_cover = []
    for p in t.ca_policies:
        apps = _cond(p, "applications", "includeApplications") or []
        if enabled(p) and enforces_mfa(p) and all_users(p) and ("All" in apps or AZURE_MANAGEMENT_APP_ID in apps):
            if unconditional(p):
                return []
            if unconditional(p, allow_trusted_locations=True):
                partial_cover.append(p)
    # Device-registration policies ("join to Azure") are user actions, not Azure management.
    intended = [
        p
        for p in t.ca_policies
        if "azure" in (p.get("displayName") or "").lower()
        and enforces_mfa(p)
        and not _cond(p, "applications", "includeUserActions")
        and p not in partial_cover
    ]
    note = (
        " A policy appears to have been meant for this but is not in force: "
        + listing([f"'{p.get('displayName')}' (state {p.get('state')}, {'no target resources' if not has_resources(p) else scope(p)})" for p in intended])
        + "."
        if intended
        else ""
    )
    return [
        Finding(
            title="Azure management (portal, CLI, PowerShell, ARM) can be reached without MFA",
            severity="medium" if partial_cover else "high",
            description=(
                (
                    "MFA for the 'Windows Azure Service Management API' (Azure portal, CLI, PowerShell, ARM) comes "
                    "only from " + listing([f"'{p.get('displayName')}'" for p in partial_cover])
                    + ", which skips trusted locations, so from those networks Azure can be managed with a password."
                    if partial_cover
                    else "No enabled Conditional Access policy requires MFA for the 'Windows Azure Service Management "
                    "API', which fronts the Azure portal, Azure CLI, Azure PowerShell and ARM templates."
                )
                + note
                + " Anyone holding an Azure RBAC role can therefore manage subscriptions with a password alone."
            ),
            remediation=(
                "Create (or fix) a Conditional Access policy: Users = All users (exclude emergency-access "
                "accounts); Target resources = Select apps > 'Windows Azure Service Management API' (and "
                "'Microsoft Admin Portals'); Grant = Require multifactor authentication. Enable it after a "
                "report-only check."
            ),
            affected=[policy_affected(p, state=p.get("state")) for p in intended + partial_cover]
            or [Affected("application", AZURE_MANAGEMENT_APP_ID, "Windows Azure Service Management API", CA_POLICIES_URL)],
            evidence={"intendedPolicies": [policy_evidence(p) for p in intended], "partialCover": [policy_evidence(p) for p in partial_cover]},
            resource="Windows Azure Service Management API",
        )
    ]


@control(
    "M365-CA-06",
    "Accounts and groups excluded from MFA or block policies",
    "Conditional Access",
    permissions=PERMS + ("Directory.Read.All",),
    references=(maester("MT.1005"), maester("MT.1036")),
)
def exclusions(t: Tenant) -> list[Finding]:
    guarded = [p for p in t.ca_policies if enabled(p) and (enforces_mfa(p) or blocks(p))]
    excluded: dict[str, list[str]] = {}
    for p in guarded:
        users = _cond(p, "users") or {}
        for oid in (users.get("excludeUsers") or []) + (users.get("excludeGroups") or []):
            excluded.setdefault(oid, []).append(p.get("displayName", p["id"]))
    if not excluded:
        return []
    objects = t.resolve_names(list(excluded))
    affected = []
    for oid, policies in sorted(excluded.items(), key=lambda kv: -len(kv[1])):
        obj = objects.get(oid, {"id": oid})
        affected.append(
            Affected(
                principal_kind(obj),
                oid,
                display(obj) if obj.get("displayName") else oid,
                principal_url(obj) if obj.get("@odata.type") else None,
                {"excludedFrom": policies, "excludedFromCount": len(policies), "ofProtectivePolicies": len(guarded)},
            )
        )
    groups = [a for a in affected if a.type == "group"]
    return [
        Finding(
            title="Accounts and groups are exempt from MFA or block policies",
            severity="medium",
            description=(
                f"{len(affected)} account(s) or group(s) are excluded from one or more of the {len(guarded)} enabled "
                "policies that require MFA or block access. Most excluded: "
                + listing([f"{a.name} (excluded from {a.detail['excludedFromCount']})" for a in affected[:5]])
                + ". Exclusions are expected only for two dedicated, cloud-only emergency-access accounts; any "
                "other exclusion is an account that signs in without the protection the policy provides"
                + (
                    f", and {len(groups)} of them are groups, whose membership can grow silently."
                    if groups
                    else "."
                )
            ),
            remediation=(
                "Review each excluded object in its policies (Conditional Access > policy > Users > Exclude). Keep "
                "exclusions only for the emergency-access accounts, which should be cloud-only, have no mailbox, "
                "use phishing-resistant credentials and trigger an alert on every sign-in. Remove the rest, or "
                "give them a fallback policy that still requires MFA. Replace excluded groups by the specific "
                "emergency accounts."
            ),
            affected=affected,
            evidence={"exclusions": excluded},
        )
    ]


@control(
    "M365-CA-07",
    "Protective Conditional Access policies left in report-only or disabled",
    "Conditional Access",
    permissions=PERMS,
    references=(maester("MT.1184"),),
)
def not_enforced(t: Tenant) -> list[Finding]:
    idle = [
        p
        for p in t.ca_policies
        if p.get("state") in ("disabled", "enabledForReportingButNotEnforced")
        and (enforces_mfa(p) or blocks(p))
        and has_resources(p)
        # Risk policies are reported by M365-CA-08.
        and not (_cond(p, "userRiskLevels") or _cond(p, "signInRiskLevels"))
    ]
    if not idle:
        return []
    return [
        Finding(
            title="Policies that would require MFA or block access are not enforced",
            severity="low",
            description=(
                f"{len(idle)} polic{'y' if len(idle) == 1 else 'ies'} that require MFA or block access are "
                "disabled or in report-only, so they log what they would do but enforce nothing: "
                + listing([f"'{p.get('displayName')}' ({p.get('state')})" for p in idle])
                + ". This is fine while a policy is being tested; left that way it gives a false sense of coverage."
            ),
            remediation=(
                "For each policy: check its report-only results in the sign-in logs (Conditional Access > "
                "Insights and reporting), then turn it On or delete it."
            ),
            affected=[policy_affected(p, state=p.get("state"), scope=scope(p)) for p in idle],
            evidence={"policies": [policy_evidence(p) for p in idle]},
        )
    ]



def _risk_enforced(t: Tenant, key: str, grants: set[str]) -> list[dict[str, Any]]:
    return [
        p
        for p in t.ca_policies
        if enabled(p) and all_users(p) and "high" in (_cond(p, key) or []) and ((_grants(p) & grants) or (enforces_mfa(p) and "mfa" in grants))
    ]


@control(
    "M365-CA-08",
    "Risky users and risky sign-ins are not challenged or blocked",
    "Conditional Access",
    licence="Entra ID P2",
    permissions=PERMS,
    references=(cisa("MS.AAD.2.1"), cisa("MS.AAD.2.3"), maester("MT.1012"), maester("MT.1024.userRiskPolicy")),
)
def risk_policies(t: Tenant) -> list[Finding]:
    user_risk = _risk_enforced(t, "userRiskLevels", {"block", "passwordChange"})
    signin_risk = _risk_enforced(t, "signInRiskLevels", {"block", "mfa"})
    if user_risk and signin_risk:
        return []
    drafts = [
        p for p in t.ca_policies
        if p.get("state") != "enabled" and ((_cond(p, "userRiskLevels") or []) or (_cond(p, "signInRiskLevels") or []))
    ]
    scoped = [
        p for p in t.ca_policies
        if enabled(p) and not all_users(p) and ((_cond(p, "userRiskLevels") or []) or (_cond(p, "signInRiskLevels") or []))
    ]
    gaps = []
    if not user_risk:
        gaps.append("no enabled policy blocks or forces a password change for high-risk users")
    if not signin_risk:
        gaps.append("no enabled policy requires MFA or blocks high-risk sign-ins for all users")
    return [
        Finding(
            title="Identity Protection risk signals are not acted on",
            severity="high",
            description=(
                "The tenant has Entra ID P2, so Identity Protection scores users and sign-ins for risk (leaked "
                "credentials, impossible travel, token anomalies), but " + " and ".join(gaps) + ". "
                + (
                    "Risk policies exist only in report-only or disabled state: "
                    + listing([f"'{p.get('displayName')}' ({p.get('state')})" for p in drafts])
                    + ". "
                    if drafts
                    else ""
                )
                + (
                    "Others apply to a subset of users only: " + listing([f"'{p.get('displayName')}'" for p in scoped]) + ". "
                    if scoped
                    else ""
                )
                + "A sign-in Microsoft already flags as compromised is therefore let through."
            ),
            remediation=(
                "Turn the risk policies on for all users (excluding only emergency-access accounts): user risk = "
                "High → Require password change (with MFA), or Block; sign-in risk = Medium and above → Require MFA, "
                "High → Block. Check each policy's report-only impact in the sign-in logs first, and make sure users "
                "are registered for MFA and self-service password reset so they can remediate their own risk."
            ),
            affected=[policy_affected(p, state=p.get("state"), scope=scope(p)) for p in drafts + scoped]
            or [Affected("tenantSetting", "riskPolicies", "Risk-based Conditional Access", CA_POLICIES_URL)],
            evidence={"userRiskEnforced": [p["id"] for p in user_risk], "signInRiskEnforced": [p["id"] for p in signin_risk], "draftPolicies": [policy_evidence(p) for p in drafts]},
        )
    ]


__all__ = ["baseline_mfa", "enforces_mfa", "blocks", "has_resources", "SECURITY_DEFAULTS_URL"]
