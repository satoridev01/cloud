"""Applications: what third-party and in-house apps can do in the tenant, and who can let them in."""

from __future__ import annotations

from ..context import (
    CONSENT_URL,
    PRIVILEGED_ROLES,
    display,
    principal_kind,
    principal_url,
    EXCHANGE_APP_ID,
    GRAPH_APP_ID,
    MICROSOFT_TENANTS,
    USER_SETTINGS_URL,
    Tenant,
    app_url,
    parse_time,
    sp_url,
)
from .. import cvss
from ..model import Affected, Finding, atomic_names, cisa, control, listing, maester

# What each application permission lets an app do, in words. TAKEOVER reaches Global Administrator,
# directly or in one step (TIER0), or can switch off the tenant's defences; DATA reads or changes
# everyone's content.
TIER0 = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "Domain.ReadWrite.All",
}
TAKEOVER = {
    "RoleManagement.ReadWrite.Directory": "assign any directory role, including Global Administrator",
    "AppRoleAssignment.ReadWrite.All": "grant itself or any app any API permission",
    "Application.ReadWrite.All": "add credentials to any app and sign in as it",
    "Directory.ReadWrite.All": "create, change and delete users, groups and other directory objects",
    "Policy.ReadWrite.ConditionalAccess": "change or switch off Conditional Access policies",
    "Policy.ReadWrite.AuthenticationMethod": "change which sign-in methods the tenant allows",
    "UserAuthenticationMethod.ReadWrite.All": "add or reset any user's MFA methods",
    "Domain.ReadWrite.All": "add or federate a domain, and so sign in as any of its users",
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
        if not sp or sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS:
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
    "Applications that can take over the tenant or switch off its defences",
    "Applications",
    permissions=("Application.Read.All",),
    references=(maester("MT.1186"),),
)
def takeover_apps(t: Tenant) -> list[Finding]:
    affected = [_app_affected(t, sp, perms, TAKEOVER) for sp, perms in _apps(t) if set(perms) & set(TAKEOVER)]
    if not affected:
        return []
    third = [a for a in affected if a.detail["publisher"] == "third party"]
    tier0 = [a for a in affected if set(a.detail["permissions"]) & TIER0]
    return [
        Finding(
            title="Applications can take over the tenant or switch off its defences",
            severity="critical" if tier0 else "high",
            cvss=cvss.TENANT_TAKEOVER if tier0 else cvss.PASSWORD_TO_DATA,
            description=(
                f"{len(affected)} application(s) hold Microsoft Graph application permissions that act without a "
                "signed-in user and can take control of the tenant or disable its protections"
                + (
                    f" — {len(tier0)} of them ({', '.join(a.name for a in tier0)}) reach Global Administrator directly"
                    if tier0
                    else ""
                )
                + ":\n"
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
            severity="high",
            cvss=cvss.PASSWORD_TO_DATA,
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
            cvss=cvss.CONSENT_PHISHING if legacy else cvss.HARDENING_USER,
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
            cvss=cvss.HARDENING,
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
            cvss=cvss.HARDENING,
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


# Delegated scopes that act on the whole directory with the signed-in user's rights: consented for
# everyone, any administrator who uses the app hands it their administrative power.
DELEGATED_TAKEOVER = {
    "RoleManagement.ReadWrite.Directory": "manage directory roles as the signed-in user",
    "Directory.AccessAsUser.All": "do anything the signed-in user can do in the directory",
    "Directory.ReadWrite.All": "change the directory as the signed-in user",
    "AppRoleAssignment.ReadWrite.All": "grant API permissions as the signed-in user",
    "Application.ReadWrite.All": "manage apps and their credentials as the signed-in user",
}
DELEGATED_DATA = {
    "Mail.Read": "read the user's mail",
    "Mail.ReadWrite": "read and change the user's mail",
    "Mail.Send": "send mail as the user",
    "MailboxSettings.ReadWrite": "create inbox and forwarding rules for the user",
    "Files.Read.All": "read every file the user can reach",
    "Files.ReadWrite.All": "read and change every file the user can reach",
    "Sites.ReadWrite.All": "read and change every site the user can reach",
    "Sites.FullControl.All": "fully control every site the user can reach",
    "User.ReadWrite.All": "change users as the signed-in user",
    "Group.ReadWrite.All": "change groups as the signed-in user",
    "EWS.AccessAsUser.All": "full access to the user's mailbox (EWS)",
    "full_access_as_user": "full access to the user's mailbox",
}
# Community apps with a documented abuse history or retirement, named so a reader knows why.
KNOWN_RISKY_CLIENTS = {
    "31359c7f-bd7e-475c-86db-fdb8c937548e": "PnP Management Shell — a community multi-tenant app retired in September 2024",
}


@control(
    "M365-APP-06",
    "Applications consented for every user with broad delegated permissions",
    "Applications",
    permissions=("Directory.Read.All",),
)
def tenant_wide_consents(t: Tenant) -> list[Finding]:
    by_client: dict[str, set[str]] = {}
    for grant in t.delegated_grants:
        if grant.get("consentType") != "AllPrincipals":
            continue
        scopes = set((grant.get("scope") or "").split()) & (set(DELEGATED_TAKEOVER) | set(DELEGATED_DATA))
        if scopes:
            by_client.setdefault(grant.get("clientId", ""), set()).update(scopes)
    affected = []
    for sp_id, scopes in by_client.items():
        sp = t.service_principals.get(sp_id)
        if not sp or sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS:
            continue
        can = [DELEGATED_TAKEOVER[s] for s in sorted(scopes) if s in DELEGATED_TAKEOVER] + [
            DELEGATED_DATA[s] for s in sorted(scopes) if s in DELEGATED_DATA
        ]
        affected.append(
            Affected(
                "servicePrincipal",
                sp_id,
                sp.get("displayName", sp_id),
                sp_url(sp_id, sp.get("appId")),
                {
                    "appId": sp.get("appId"),
                    "scopes": sorted(scopes),
                    "canDo": can,
                    "takeover": sorted(scopes & set(DELEGATED_TAKEOVER)),
                    **({"note": KNOWN_RISKY_CLIENTS[sp.get("appId")]} if sp.get("appId") in KNOWN_RISKY_CLIENTS else {}),
                },
            )
        )
    if not affected:
        return []
    affected.sort(key=lambda a: (not a.detail["takeover"], a.name.lower()))
    takeover = [a for a in affected if a.detail["takeover"]]
    names = atomic_names(affected)
    return [
        Finding(
            title="Applications were granted access to every user's data or directory rights by one consent",
            severity="high" if takeover else "medium",
            cvss=cvss.PASSWORD_TO_DATA if takeover else cvss.DELEGATED_DATA,
            description=(
                f"{len(affected)} non-Microsoft application(s) hold delegated permissions consented on behalf of "
                "every user in the organisation, so any user who signs in to them hands over these rights without "
                "being asked:\n"
                + "\n".join(
                    f"- {n}: {'; '.join(a.detail['canDo'])}." + (f" ({a.detail['note']}.)" if a.detail.get("note") else "")
                    for n, a in zip(names, affected)
                )
                + "\n"
                + (
                    f"{len(takeover)} of them can act on the directory with the signed-in user's own rights, so the "
                    "moment an administrator uses one, it can do what that administrator can. "
                    if takeover
                    else ""
                )
                + "Each of these vendors can read or act on the data of whichever users sign in, and a compromised "
                "vendor or a stolen refresh token reaches all of it."
            ),
            remediation=(
                "For each app (Enterprise applications > app > Permissions > Admin consent): confirm it is still "
                "used and approved. Revoke the tenant-wide consent for apps no longer needed, or replace it with "
                "user-assigned access (Properties > Assignment required = Yes, then assign only the people who use "
                "it). Remove scopes the app does not need, and send new consent requests through the admin consent "
                "workflow so they are reviewed."
            ),
            affected=affected,
            evidence={a.detail["appId"] or a.id: a.detail["scopes"] for a in affected},
        )
    ]


@control(
    "M365-APP-07",
    "Ordinary users own applications that hold high privileges",
    "Applications",
    permissions=("Application.Read.All", "Directory.Read.All"),
)
def privileged_app_owners(t: Tenant) -> list[Finding]:
    grants = _grants(t)
    held_roles: dict[str, set[str]] = {}
    for a in t.role_assignments:
        pid = (a.get("principal") or {}).get("id") or a.get("principalId")
        if pid:
            held_roles.setdefault(pid, set()).add(t.role_template(a))
    apps: dict[str, dict] = {}
    for sp_id, perms in grants.items():
        apps[sp_id] = {"perms": perms, "roles": held_roles.get(sp_id, set())}
    for sp_id, roles in held_roles.items():
        if sp_id in t.service_principals and roles & set(PRIVILEGED_ROLES):
            apps.setdefault(sp_id, {"perms": [], "roles": roles})
    affected, worst = [], "high"
    for sp_id, info in apps.items():
        sp = t.service_principals.get(sp_id)
        if not sp or sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS:
            continue
        owners = list(t.owners("servicePrincipals", sp_id))
        registration = next((a for a in t.applications if a.get("appId") == sp.get("appId")), None)
        if registration:
            owners += list(t.owners("applications", registration["id"]))
        tier0 = bool(set(info["perms"]) & TIER0 or any(PRIVILEGED_ROLES.get(r, ("", 9))[1] == 0 for r in info["roles"]))
        for owner in {o["id"]: o for o in owners}.values():
            if owner.get("accountEnabled") is False:
                continue  # A disabled account cannot sign in to add a credential.
            owner_roles = held_roles.get(owner["id"], set())
            if any(PRIVILEGED_ROLES.get(r, ("", 9))[1] == 0 for r in owner_roles):
                continue  # A tenant administrator can already do what the app can.
            if tier0:
                worst = "critical"
            what = [TAKEOVER.get(p) or DATA.get(p) for p in info["perms"]] + [PRIVILEGED_ROLES[r][0] for r in info["roles"] if r in PRIVILEGED_ROLES]
            affected.append(
                Affected(
                    principal_kind(owner),
                    owner["id"],
                    f"{display(owner)} — owner of {sp.get('displayName')}",
                    principal_url(owner),
                    {"app": sp.get("displayName"), "appId": sp.get("appId"), "appCan": [w for w in what if w], "ownerRoles": sorted(PRIVILEGED_ROLES[r][0] for r in owner_roles if r in PRIVILEGED_ROLES)},
                )
            )
    if not affected:
        return []
    return [
        Finding(
            title="Ordinary accounts own applications that can act on the whole tenant",
            severity=worst,
            cvss=cvss.OWNER_TAKEOVER if worst == "critical" else cvss.OWNER_TO_DATA,
            description=(
                "An application's owner can add a new client secret to it and then sign in as the application, "
                "inheriting everything the app is allowed to do. These owners are not tenant administrators, yet "
                "own apps with far more power than they have:\n"
                + "\n".join(f"- {a.name}: the app can {'; '.join(a.detail['appCan']) or 'act with its permissions'}." for a in affected)
                + "\nCompromising one of these accounts — or the person misusing it — is therefore a path to the "
                "app's full access, outside MFA and most Conditional Access."
            ),
            remediation=(
                "Remove these owners (App registrations > app > Owners, and Enterprise applications > app > Owners) "
                "and give ownership to a small group of administrators instead. Restrict who can add credentials to "
                "apps with an app management policy, and alert on 'Add service principal credentials' and 'Update "
                "application – Certificates and secrets management' in the audit log."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]


@control(
    "M365-APP-08",
    "Credentials added to Microsoft's own applications",
    "Applications",
    permissions=("Application.Read.All",),
)
def microsoft_app_backdoors(t: Tenant) -> list[Finding]:
    affected = []
    for sp in t.service_principals.values():
        if sp.get("appOwnerOrganizationId") not in MICROSOFT_TENANTS:
            continue
        secrets = sp.get("passwordCredentials") or []
        certs = [k for k in sp.get("keyCredentials") or [] if k.get("usage") == "Verify"]
        if secrets or certs:
            affected.append(
                Affected("servicePrincipal", sp["id"], sp.get("displayName", sp["id"]), sp_url(sp["id"], sp.get("appId")), {"appId": sp.get("appId"), "clientSecrets": len(secrets), "certificates": len(certs)})
            )
    if not affected:
        return []
    return [
        Finding(
            title="Secrets or certificates were added to Microsoft first-party applications in this tenant",
            severity="high",
            cvss=cvss.PASSWORD_TO_DATA,
            description=(
                f"{len(affected)} service principal(s) of applications published by Microsoft carry credentials added "
                "in this tenant: " + "; ".join(atomic_names(affected)) + ". Microsoft's own apps do not need "
                "tenant-added secrets; adding one is a known persistence technique, because the app keeps its "
                "Microsoft-granted permissions and looks legitimate in every list."
            ),
            remediation=(
                "Treat this as a possible compromise: find who added each credential (Audit logs > 'Add service "
                "principal credentials'), remove credentials nobody can account for, and review the sign-ins of these "
                "service principals for the period since."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]


# Microsoft client apps an attacker uses for token theft and directory recon once they hold a password.
PRIVILEGED_CLIENTS = {
    "1950a258-227b-4e31-a9cf-717495945fc2": "Microsoft Azure PowerShell",
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": "Microsoft Azure CLI",
    "14d82eec-204b-4c2f-b7e8-296a70dab67e": "Microsoft Graph Command Line Tools",
    "de8bc8b5-d9f9-48b1-a8ad-b748da725064": "Graph Explorer",
    "1b730954-1685-4b74-9bfd-dac224a7b894": "Azure Active Directory PowerShell",
    "d1ddf0e4-d672-4dae-b554-9d5bdfd93547": "Microsoft Intune PowerShell",
    "fb78d390-0c51-40cd-8e17-fdbfab77341b": "Microsoft Exchange REST API Based PowerShell",
    "9bc3ab49-b65d-410a-85ad-de819febfddc": "Microsoft SharePoint Online Management Shell",
}


@control(
    "M365-APP-09",
    "Admin tools that any user can sign in to",
    "Applications",
    permissions=("Application.Read.All",),
    references=(maester("MT.1186"),),
)
def open_admin_clients(t: Tenant) -> list[Finding]:
    affected = [
        Affected("servicePrincipal", sp["id"], PRIVILEGED_CLIENTS[sp["appId"]], sp_url(sp["id"], sp["appId"]), {"appId": sp["appId"]})
        for sp in t.service_principals.values()
        if sp.get("appId") in PRIVILEGED_CLIENTS and not sp.get("appRoleAssignmentRequired")
    ]
    if not affected:
        return []
    return [
        Finding(
            title="Microsoft admin tools can be used by any user, not only administrators",
            severity="medium",
            cvss=cvss.DIRECTORY_EXPOSURE,
            description=(
                "These Microsoft command-line and admin clients do not require an assignment, so any account — "
                "including one taken over by phishing — can sign in to them and query or script against the tenant "
                "with that account's rights: " + "; ".join(a.name for a in affected) + ". Attackers use them right "
                "after a compromise to map users, groups, roles and apps and to mint long-lived tokens."
            ),
            remediation=(
                "For each app (Enterprise applications > app > Properties), set 'Assignment required' to Yes and "
                "assign the administrators and automation accounts that need it. Create the service principal first "
                "for tools that do not appear in the list yet, so the setting can be applied before anyone uses them."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]

