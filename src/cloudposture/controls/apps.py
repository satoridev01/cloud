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
from ..model import Affected, Finding, cisa, control, listing, maester

# Application permissions that let an app take over the tenant, or read/write everyone's data.
TAKEOVER = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod",
    "UserAuthenticationMethod.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Organization.ReadWrite.All",
}
DATA = {
    "Mail.ReadWrite",
    "Mail.Read",
    "Mail.Send",
    "MailboxSettings.ReadWrite",
    "Files.ReadWrite.All",
    "Files.Read.All",
    "Sites.FullControl.All",
    "Sites.ReadWrite.All",
    "Sites.Read.All",
    "User.ReadWrite.All",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "Chat.Read.All",
    "ChannelMessage.Read.All",
    "full_access_as_app",
}
LONG_SECRET_DAYS = 730


def _grants(t: Tenant) -> dict[str, list[str]]:
    """service principal id → risky application permission values it holds (Graph + Exchange)."""
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


@control(
    "M365-APP-01",
    "Applications with tenant-wide write or data-access permissions",
    "Applications",
    permissions=("Application.Read.All",),
    references=(maester("MT.1186"),),
)
def risky_app_permissions(t: Tenant) -> list[Finding]:
    grants = _grants(t)
    affected = []
    for sp_id, perms in grants.items():
        sp = t.service_principals.get(sp_id)
        if not sp or sp.get("appOwnerOrganizationId") == MICROSOFT_TENANT_ID:
            continue
        owner = "this tenant" if sp.get("appOwnerOrganizationId") == t.organization.get("id") else "third party"
        affected.append(
            Affected(
                "servicePrincipal",
                sp_id,
                sp.get("displayName", sp_id),
                sp_url(sp_id, sp.get("appId")),
                {
                    "permissions": sorted(perms),
                    "takeover": sorted(set(perms) & TAKEOVER),
                    "publisher": owner,
                    "clientSecrets": len(sp.get("passwordCredentials") or []),
                    "certificates": len(sp.get("keyCredentials") or []),
                },
            )
        )
    if not affected:
        return []
    affected.sort(key=lambda a: (not a.detail["takeover"], a.name.lower()))
    takeover = [a for a in affected if a.detail["takeover"]]
    return [
        Finding(
            title="Applications can modify the directory or read everyone's data",
            severity="high" if takeover else "medium",
            description=(
                f"{len(affected)} non-Microsoft application(s) hold application permissions that act on the whole "
                "tenant without a signed-in user: "
                + listing(
                    [
                        f"{a.name} ({len(a.detail['permissions'])} permission(s)"
                        + (f", incl. {', '.join(a.detail['takeover'][:3])}" if a.detail["takeover"] else "")
                        + ")"
                        for a in affected
                    ],
                    limit=8,
                )
                + ". The full list per app is in the affected objects. "
                + (
                    f"{len(takeover)} can change roles, apps, policies or authentication methods, which is enough to "
                    "make itself or anyone Global Administrator. "
                    if takeover
                    else ""
                )
                + "The app's secret or certificate is effectively a master key to that data, and consent to it is "
                "rarely revisited."
            ),
            remediation=(
                "For each app (Enterprise applications > app > Permissions): confirm the owner and business need, "
                "and replace tenant-wide permissions with the narrowest one that works — e.g. Sites.Selected instead "
                "of Sites.ReadWrite.All, or an Exchange application access policy restricting Mail.* to specific "
                "mailboxes. Revoke consent for apps no longer used, prefer certificates over client secrets, and "
                "review these grants quarterly."
            ),
            affected=affected,
            evidence={"grants": {a.id: a.detail["permissions"] for a in affected}},
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
