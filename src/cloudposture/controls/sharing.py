"""Sharing: how far SharePoint and OneDrive let files travel outside the organisation."""

from __future__ import annotations

from typing import Any

from .. import cvss
from ..context import Tenant
from ..model import Affected, Finding, NotEvaluated, cisa, control

PERMS = ("SharePointTenantSettings.Read.All",)
CAPABILITIES = {
    "disabled": "only people in the organisation",
    "existingExternalUserSharingOnly": "existing guests only",
    "externalUserSharingOnly": "new and existing guests",
    "externalUserAndGuestSharing": "anyone, including 'Anyone' links that need no sign-in",
}
NEW_GUESTS = {"externalUserSharingOnly", "externalUserAndGuestSharing"}


def sharing_url(t: Tenant) -> str:
    """The SharePoint admin centre's sharing page, which lives on the tenant's own -admin host."""
    try:
        initial = next((d.get("name") for d in t.organization.get("verifiedDomains") or [] if d.get("isInitial")), None)
    except NotEvaluated:
        initial = None
    if initial and initial.endswith(".onmicrosoft.com"):
        return f"https://{initial.split('.')[0]}-admin.sharepoint.com/_layouts/15/online/AdminHome.aspx#/sharing"
    return "https://admin.microsoft.com/sharepoint"


def _setting(t: Tenant, key: str, name: str, **detail: Any) -> Affected:
    return Affected("tenantSetting", key, name, sharing_url(t), detail)


@control(
    "M365-SHR-01",
    "SharePoint and OneDrive sharing reaches beyond existing guests",
    "Sharing",
    permissions=PERMS,
    references=(cisa("MS.SHAREPOINT.1.1"),),
)
def external_sharing(t: Tenant) -> list[Finding]:
    s = t.sharepoint_settings
    capability = s.get("sharingCapability")
    if capability not in NEW_GUESTS:
        return []
    anyone = capability == "externalUserAndGuestSharing"
    return [
        Finding(
            title="Files can be shared through 'Anyone' links that need no sign-in"
            if anyone
            else "Files can be shared with any external email address",
            severity="medium" if anyone else "low",
            cvss=cvss.ANONYMOUS_LINKS if anyone else cvss.HARDENING_USER,
            description=(
                (
                    "SharePoint's organisation-level sharing is set to 'Anyone', so users can create links that open "
                    "a file or folder for whoever holds them, with no sign-in and no record of who used them. A link "
                    "forwarded, pasted into a ticket or chat, or harvested from a compromised mailbox exposes the "
                    "content to anyone, and nothing ties an access back to a person."
                    if anyone
                    else "SharePoint's organisation-level sharing is set to 'New and existing guests', so any user can "
                    "share a file with any external email address, which creates a guest account on the spot. Data "
                    "can leave the organisation through a single sharing dialog, to recipients nobody has vetted."
                )
                + " OneDrive's own setting can be no more permissive than this, but may be as permissive; reading it "
                "needs SharePoint admin PowerShell."
            ),
            remediation=(
                "In the SharePoint admin center > Policies > Sharing, lower External sharing for SharePoint to 'Existing "
                "guests' (or 'Only people in your organization'), and OneDrive's slider to the same level or below. "
                "Where a site really needs wider sharing, raise it on that site alone (Active sites > site > Sharing). "
                + (
                    "If 'Anyone' links must stay, make them expire within 30 days and allow view only."
                    if anyone
                    else ""
                )
            ).strip(),
            affected=[_setting(t, "sharingCapability", f"External sharing: {CAPABILITIES[capability]}", sharingCapability=capability)],
            evidence={"sharingCapability": capability},
            resource=f"SharePoint sharing: {CAPABILITIES[capability]}",
        )
    ]


@control(
    "M365-SHR-02",
    "External sharing is not limited to approved domains",
    "Sharing",
    permissions=PERMS,
    references=(cisa("MS.SHAREPOINT.1.3"),),
)
def sharing_domains(t: Tenant) -> list[Finding]:
    s = t.sharepoint_settings
    if s.get("sharingCapability") not in NEW_GUESTS:
        return []
    mode = s.get("sharingDomainRestrictionMode") or "none"
    allowed = s.get("sharingAllowedDomainList") or []
    if mode == "allowList" and allowed:
        return []
    blocked = s.get("sharingBlockedDomainList") or []
    return [
        Finding(
            title="Files can be shared with guests from any domain",
            severity="low",
            cvss=cvss.HARDENING_USER,
            description=(
                "SharePoint and OneDrive let users invite new guests, and no allow list limits which organisations "
                "those guests may come from"
                + (f" — only {len(blocked)} domain(s) are blocked, so every other domain is allowed" if mode == "blockList" and blocked else "")
                + ". A file can therefore be shared with a personal mailbox or a look-alike domain an attacker "
                "registered, as easily as with a partner."
            ),
            remediation=(
                "In the SharePoint admin center > Policies > Sharing > More external sharing settings, select "
                "'Limit external sharing by domain' and allow only the partner domains the organisation works with; "
                "add a domain when a new collaboration starts. Alternatively, allow external sharing only for "
                "members of a security group."
            ),
            affected=[_setting(t, "sharingDomainRestrictionMode", "External sharing: limit by domain", sharingDomainRestrictionMode=mode, blockedDomains=blocked)],
            evidence={"sharingCapability": s.get("sharingCapability"), "sharingDomainRestrictionMode": mode, "sharingAllowedDomainList": allowed, "sharingBlockedDomainList": blocked},
            resource="SharePoint sharing: guests from any domain",
        )
    ]


@control(
    "M365-SHR-03",
    "Guests can pass on access to what was shared with them",
    "Sharing",
    permissions=PERMS,
)
def guest_resharing(t: Tenant) -> list[Finding]:
    s = t.sharepoint_settings
    if s.get("sharingCapability") in (None, "disabled"):
        return []
    reshare = s.get("isResharingByExternalUsersEnabled") is True
    any_account = s.get("isRequireAcceptingUserToMatchInvitedUserEnabled") is False
    if not reshare and not any_account:
        return []
    gaps = []
    if reshare:
        gaps.append("guests can share items they do not own with further people")
    if any_account:
        gaps.append("an invitation can be accepted by an account other than the one it was sent to, so a forwarded invitation works")
    affected = []
    if reshare:
        affected.append(_setting(t, "isResharingByExternalUsersEnabled", "Guests can share items they don't own", isResharingByExternalUsersEnabled=True))
    if any_account:
        affected.append(_setting(t, "isRequireAcceptingUserToMatchInvitedUserEnabled", "Guests may accept invitations with another account", isRequireAcceptingUserToMatchInvitedUserEnabled=False))
    return [
        Finding(
            title="Guests can pass on access to the organisation's files",
            severity="low",
            cvss=cvss.HARDENING_USER,
            description=(
                "In SharePoint and OneDrive, " + "; and ".join(gaps) + ". Access granted to one vetted person can "
                "spread to people nobody in the organisation chose, and the owner of the content is not asked."
            ),
            remediation=(
                "In the SharePoint admin center > Policies > Sharing > More external sharing settings, clear 'Allow "
                "guests to share items they don't own' and select 'Guests must sign in using the same account to "
                "which sharing invitations are sent'."
            ),
            affected=affected,
            evidence={
                "isResharingByExternalUsersEnabled": s.get("isResharingByExternalUsersEnabled"),
                "isRequireAcceptingUserToMatchInvitedUserEnabled": s.get("isRequireAcceptingUserToMatchInvitedUserEnabled"),
            },
        )
    ]
