"""Tenant-wide settings: guests, and the licences that decide which protections exist at all."""

from __future__ import annotations

from ..context import EXTERNAL_COLLAB_URL, Tenant
from .. import cvss
from ..model import Affected, Finding, cisa, control

GUEST_ROLES = {
    "a0b1b346-4d3e-4e8b-98f8-753987be4970": "same access as members",
    "10dae51f-b6af-4016-8d66-8c2a99b929b3": "limited access (default)",
    "2af84b1e-32c8-42b7-82bc-daa82404023b": "restricted access",
}


@control(
    "M365-TEN-01",
    "Anyone, including guests, can invite external users",
    "Tenant settings",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.8.2"),),
)
def guest_invites(t: Tenant) -> list[Finding]:
    who = t.authorization_policy.get("allowInvitesFrom")
    if who not in ("everyone", "adminsGuestInvitersAndAllMembers"):
        return []
    everyone = who == "everyone"
    return [
        Finding(
            title="Guest invitations are open to " + ("everyone, including existing guests" if everyone else "every member"),
            severity="medium" if everyone else "low",
            cvss=cvss.DIRECTORY_EXPOSURE if everyone else cvss.HARDENING,
            description=(
                "Guest invite settings allow "
                + ("any user — members and guests alike — " if everyone else "every member ")
                + "to invite external accounts into the tenant. Each invitation adds an identity whose security "
                "(MFA, offboarding) the organisation does not control, with access to whatever Teams, groups and "
                "sites it is added to."
            ),
            remediation=(
                "In Entra admin center > External Identities > External collaboration settings, set 'Guest invite "
                "settings' to 'Only users assigned to specific admin roles can invite guest users', assign the Guest "
                "Inviter role to the people who need it, and restrict invitations to allowed partner domains."
            ),
            affected=[Affected("tenantSetting", "allowInvitesFrom", "Guest invite settings", EXTERNAL_COLLAB_URL, {"allowInvitesFrom": who})],
            evidence={"allowInvitesFrom": who},
            resource="Tenant setting: guest invite settings",
        )
    ]


@control(
    "M365-TEN-02",
    "Guests have the same directory access as members",
    "Tenant settings",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.8.1"),),
)
def guest_access(t: Tenant) -> list[Finding]:
    role = t.authorization_policy.get("guestUserRoleId")
    if role != "a0b1b346-4d3e-4e8b-98f8-753987be4970":
        return []
    return [
        Finding(
            title="Guests can browse the directory like members",
            severity="medium",
            cvss=cvss.DIRECTORY_EXPOSURE,
            description=(
                "Guest user access is set to 'same access as members', so any guest can enumerate every user, group "
                "and their memberships — the map an attacker needs to target privileged accounts and craft "
                "convincing internal phishing."
            ),
            remediation=(
                "In External collaboration settings, set 'Guest user access' to 'Guest user access is restricted to "
                "properties and memberships of their own directory objects'."
            ),
            affected=[Affected("tenantSetting", "guestUserRoleId", "Guest user access", EXTERNAL_COLLAB_URL, {"guestUserRoleId": role, "meaning": GUEST_ROLES[role]})],
            evidence={"guestUserRoleId": role},
            resource="Tenant setting: guest user access level",
        )
    ]


@control("M365-LIC-01", "Identity protection and PIM are not licensed", "Licensing", permissions=("Organization.Read.All",))
def p2_missing(t: Tenant) -> list[Finding]:
    if t.licences["entraIdP2"]:
        return []
    return [
        Finding(
            title="Risk-based sign-in protection and just-in-time admin access are unavailable (no Entra ID P2)",
            severity="info",
            description=(
                "The tenant has "
                + ("Entra ID P1 but not P2" if t.licences["entraIdP1"] else "neither Entra ID P1 nor P2")
                + ", so Identity Protection (blocking or challenging risky users and sign-ins), Privileged Identity "
                "Management (time-bound, approved admin activation) and access reviews cannot be configured. Checks "
                "for those features are reported as not applicable rather than as misconfigurations; closing the "
                "gap is a licensing decision."
            ),
            remediation=(
                "Consider Entra ID P2 (standalone, or via Microsoft 365 E5 / E5 Security) at least for the "
                "administrators and high-risk users, then enable user- and sign-in-risk Conditional Access policies "
                "and move privileged roles to PIM."
            ),
            affected=[Affected("tenant", t.organization.get("id", ""), t.organization.get("displayName", "Tenant"), None, {"licences": t.licences})],
            evidence={"licences": t.licences},
            resource="Tenant licences: Microsoft Entra ID",
        )
    ]
