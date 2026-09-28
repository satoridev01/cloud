"""Applications: what third-party and in-house apps can do in the tenant, and who can let them in."""

from __future__ import annotations

from ..context import (
    CONSENT_URL,
    EXCHANGE_APP_ID,
    GRAPH_APP_ID,
    MICROSOFT_TENANT_ID,
    USER_SETTINGS_URL,
    Tenant,
    app_url,
    parse_time,
    sp_url,
)
from ..model import Affected, Finding, atomic_names, cisa, control, maester

# What each application permission lets an app do, in words. TAKEOVER reaches Global Administrator,
# directly or in one step; DATA reads or changes everyone's content.
TAKEOVER = {
    "RoleManagement.ReadWrite.Directory": "assign any directory role, including Global Administrator",
    "AppRoleAssignment.ReadWrite.All": "grant itself or any app any API permission",
    "Application.ReadWrite.All": "add credentials to any app and sign in as it",
    "Directory.ReadWrite.All": "create, change and delete users, groups and other directory objects",
    "Policy.ReadWrite.ConditionalAccess": "change or switch off Conditional Access policies",
    "Policy.ReadWrite.AuthenticationMethod": "change which sign-in methods the tenant allows",
    "UserAuthenticationMethod.ReadWrite.All": "add or reset any user's MFA methods",
    "Domain.ReadWrite.All": "add or federate domains",
    "Organization.ReadWrite.All": "change tenant-wide organisation settings",
}
DATA = {
    "Mail.Read": "read mail in every mailbox",
    "Mail.ReadWrite": "read and change mail in every mailbox",
    "Mail.Send": "send mail as any user",
    "full_access_as_app": "full access to every mailbox (Exchange Web Services)",
    "MailboxSettings.ReadWrite": "create inbox and forwarding rules in every mailbox",
    "Files.Read.All": "read every OneDrive and SharePoint file",
    "Files.ReadWrite.All": "read and change every OneDrive and SharePoint file",
    "Sites.Read.All": "read every SharePoint site",
    "Sites.ReadWrite.All": "read and change every SharePoint site",
    "Sites.FullControl.All": "full control of every SharePoint site, including its sharing",
    "Chat.Read.All": "read every Teams chat",
    "ChannelMessage.Read.All": "read every Teams channel message",
    "User.ReadWrite.All": "change any user's profile and account settings",
    "Group.ReadWrite.All": "create, change and delete groups and Teams",
    "GroupMember.ReadWrite.All": "change the membership of any group",
}
# A permission a broader one already includes: listing both would say the same thing twice.
SUBSUMED_BY = {
    "Mail.Read": ("Mail.ReadWrite", "full_access_as_app"),
    "Mail.ReadWrite": ("full_access_as_app",),
    "Files.Read.All": ("Files.ReadWrite.All",),
    "Sites.Read.All": ("Sites.ReadWrite.All", "Sites.FullControl.All"),
    "Sites.ReadWrite.All": ("Sites.FullControl.All",),
}
LONG_SECRET_DAYS = 730


def _grants(t: Tenant) -> dict[str, list[str]]:
    """service principal id → the risky application permissions it holds (Graph + Exchange)."""
    out: dict[str, list[str]] = {}
    for api in (GRAPH_APP_ID, EXCHANGE_APP_ID):
        resource = t.sp_by_app(api)
        if not resource:
            continue
        roles = {r.get("id"): r.get("value") for r in resource.get("appRoles") or []}
        for grant in t.app_role_grants(api):
            value = roles.get(grant.get("appRoleId"))
            pid = str(grant.get("principalId") or "")
            if pid and value and (value in TAKEOVER or value in DATA):
                held = out.setdefault(pid, [])
                if value not in held:
                    held.append(value)
    return out


def _apps(t: Tenant) -> list[tuple[dict, list[str]]]:
    """Non-Microsoft apps holding risky permissions, minus the scanner's own registration."""
    rows = []
    for sp_id, perms in _grants(t).items():
        sp = t.service_principals.get(sp_id)
        if not sp or sp.get("appOwnerOrganizationId") == MICROSOFT_TENANT_ID:
            continue
        if t.scanner_app_id and sp.get("appId") == t.scanner_app_id:
            continue
        rows.append((sp, sorted(perms)))
    return sorted(rows, key=lambda r: (r[0].get("displayName") or "").lower())


def _app_affected(t: Tenant, sp: dict, perms: list[str], meanings: dict[str, str]) -> Affected:
    owner = "this tenant" if sp.get("appOwnerOrganizationId") == t.organization.get("id") else "third party"
    return Affected(
        "servicePrincipal",
        sp["id"],
        sp.get("displayName", sp["id"]),
        sp_url(sp["id"], sp.get("appId")),
        {
            "appId": sp.get("appId"),
            "canDo": [
                meanings[p] for p in perms if p in meanings and not set(SUBSUMED_BY.get(p, ())) & set(perms)
            ],
            "permissions": [p for p in perms if p in meanings],
            "publisher": owner,
            **t.credentials(sp),
        },
    )


def _per_app(affected: list[Affected]) -> str:
    return "\n".join(f"- {name}: {'; '.join(a.detail['canDo'])}." for name, a in zip(atomic_names(affected), affected))


REVIEW = (
    "confirm the owner and the business need for each app (Enterprise applications > app > Permissions). "
    "Revoke consent for apps that are no longer used, prefer certificates over client secrets for the "
    "tenant's own apps, and review these grants every quarter."
)


@control(
    "M365-APP-01",
    "Applications that can take over the tenant",
    "Applications",
    permissions=("Application.Read.All",),
    references=(maester("MT.1186"),),
)
def takeover_apps(t: Tenant) -> list[Finding]:
    affected = [_app_affected(t, sp, perms, TAKEOVER) for sp, perms in _apps(t) if set(perms) & set(TAKEOVER)]
    if not affected:
        return []
    third = [a for a in affected if a.detail["publisher"] == "third party"]
    return [
        Finding(
            title="Applications hold permissions that can take over the tenant",
            severity="high",
            description=(
                f"{len(affected)} application(s) hold Microsoft Graph application permissions that act without a "
                "signed-in user and reach Global Administrator directly or in one step:\n"
                + _per_app(affected)
                + "\nWhoever holds the app's credential can use these at any time, outside MFA and most "
                "Conditional Access."
                + (
                    f" {len(third)} of them are published by third parties, whose credentials sit in the vendor's own "
                    "tenant, so the organisation depends on that vendor's security for its control plane."
                    if third
                    else ""
                )
            ),
            remediation=(
                "For each app, replace these permissions with the narrowest set that covers the integration — most "
                "backup, MDR and portal tools do not need Directory.ReadWrite.All, RoleManagement.ReadWrite.Directory "
                "or AppRoleAssignment.ReadWrite.All once set up. Ask the vendor for their least-privilege "
                "permission list, then " + REVIEW
            ),
            affected=affected,
            evidence={a.detail["appId"] or a.id: a.detail["permissions"] for a in affected},
        )
    ]


@control(
    "M365-APP-05",
    "Applications with access to everyone's mail, files or chats",
    "Applications",
    permissions=("Application.Read.All",),
)
def data_apps(t: Tenant) -> list[Finding]:
    # Apps already reported as able to take over the tenant can grant themselves any data access.
    affected = [
        _app_affected(t, sp, perms, DATA)
        for sp, perms in _apps(t)
        if not set(perms) & set(TAKEOVER) and set(perms) & set(DATA)
    ]
    if not affected:
        return []
    return [
        Finding(
            title="Applications can read or change content across the whole organisation",
            severity="medium",
            description=(
                f"{len(affected)} application(s) hold tenant-wide data permissions, not limited to particular "
                "mailboxes, sites or users:\n"
                + _per_app(affected)
                + "\nAny of these apps' credentials is a key to that content for every user, including executives, "
                "and a forwarding rule or a shared-link change made through it is hard to notice."
            ),
            remediation=(
                "Narrow each app to what it needs: Sites.Selected instead of Sites.* or Files.*, an Exchange "
                "application access policy (or RBAC for Applications) restricting Mail.* and MailboxSettings to "
                "specific mailboxes, and resource-specific consent for Teams. Then " + REVIEW
            ),
            affected=affected,
            evidence={a.detail["appId"] or a.id: a.detail["permissions"] for a in affected},
        )
    ]


@control(
    "M365-APP-02",
    "Users can consent to applications",
    "Applications",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.5.2"),),
)
def user_consent(t: Tenant) -> list[Finding]:
    assigned = (t.authorization_policy.get("defaultUserRolePermissions") or {}).get("permissionGrantPoliciesAssigned") or []
    legacy = [p for p in assigned if "microsoft-user-default-legacy" in p]
    low = [p for p in assigned if "microsoft-user-default-low" in p]
    if not legacy and not low:
        return []
    if legacy:
        severity, what = "high", "any application that requests permissions a user can grant (the legacy default)"
    else:
        severity, what = "low", "apps from verified publishers asking only for low-impact permissions"
    return [
        Finding(
            title="Users can grant applications access to their data",
            severity=severity,
            description=(
                f"The user consent setting lets any user consent to {what}. Illicit consent grants are a common "
                "Microsoft 365 attack: a phishing link asks the user to approve an app, which then reads their mail "
                "and files with a token that survives password resets and MFA."
                + (" The low-impact setting limits this considerably." if not legacy else "")
            ),
            remediation=(
                "In Entra admin center > Enterprise applications > Consent and permissions > User consent settings, "
                "select 'Do not allow user consent' (or at most 'verified publishers, low-impact permissions'), and "
                "enable the admin consent workflow so users can request apps for review."
            ),
            affected=[Affected("tenantSetting", "userConsent", "User consent settings", CONSENT_URL, {"permissionGrantPoliciesAssigned": assigned})],
            evidence={"permissionGrantPoliciesAssigned": assigned},
            resource="Tenant setting: user consent for applications",
        )
    ]


@control(
    "M365-APP-03",
    "Users can register applications",
    "Applications",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.5.1"),),
)
def app_registration(t: Tenant) -> list[Finding]:
    perms = t.authorization_policy.get("defaultUserRolePermissions") or {}
    if not perms.get("allowedToCreateApps"):
        return []
    return [
        Finding(
            title="Any user can register applications",
            severity="low",
            description=(
                "Every member can create app registrations. An attacker holding one user account can register an "
                "app, add credentials to it and use it as a persistent, MFA-free foothold, or dress it up for a "
                "consent-phishing campaign."
            ),
            remediation=(
                "In Entra admin center > Identity > Users > User settings, set 'Users can register applications' to "
                "No, and give the Application Developer role to the people who legitimately build integrations."
            ),
            affected=[Affected("tenantSetting", "allowedToCreateApps", "Users can register applications", USER_SETTINGS_URL, {"allowedToCreateApps": True})],
            evidence={"allowedToCreateApps": True},
            resource="Tenant setting: users can register applications",
        )
    ]


@control(
    "M365-APP-04",
    "Application secrets that are long-lived or expired",
    "Applications",
    permissions=("Application.Read.All",),
    references=(maester("MT.1024.managedIdentity"),),
)
def app_secrets(t: Tenant) -> list[Finding]:
    affected = []
    for app in t.applications:
        long_lived, expired = 0, 0
        for cred in app.get("passwordCredentials") or []:
            start, end = parse_time(cred.get("startDateTime")), parse_time(cred.get("endDateTime"))
            if end and end < t.now:
                expired += 1
            elif start and end and (end - start).days > LONG_SECRET_DAYS:
                long_lived += 1
        if long_lived or expired:
            affected.append(
                Affected("application", app.get("appId", app["id"]), app.get("displayName", app["id"]), app_url(app.get("appId", "")), {"longLivedSecrets": long_lived, "expiredSecrets": expired})
            )
    if not affected:
        return []
    return [
        Finding(
            title="App registrations use long-lived or leftover expired client secrets",
            severity="low",
            description=(
                f"{len(affected)} app registration(s) have client secrets valid for more than two years, or expired "
                "secrets still attached: " + listing([a.name for a in affected])
                + ". A secret that lives for years ends up copied into scripts, config files and tickets, and is "
                "rarely rotated after the people who made it leave."
            ),
            remediation=(
                "For each app (App registrations > app > Certificates & secrets): replace client secrets with a "
                "certificate or a managed identity where possible; otherwise create a secret valid for at most 6–12 "
                "months, update the consumer, and delete the old and expired secrets. An app management policy can "
                "enforce a maximum secret lifetime tenant-wide."
            ),
            affected=affected,
            evidence={"apps": [{"appId": a.id, **a.detail} for a in affected]},
        )
    ]
