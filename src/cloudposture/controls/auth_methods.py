"""Authentication methods: which sign-in factors the tenant allows, and who has none."""

from __future__ import annotations

from ..context import AUTH_METHODS_URL, Tenant, display, user_url
from ..model import Affected, Finding, cis, cisa, control, listing, maester

WEAK = {"Sms": "SMS", "Voice": "Voice call", "Email": "Email one-time passcode"}
PHISHING_RESISTANT = {"Fido2": "FIDO2 security keys / passkeys", "X509Certificate": "Certificate-based authentication"}


def _configs(t: Tenant) -> dict[str, dict]:
    return {c.get("id"): c for c in t.auth_methods_policy.get("authenticationMethodConfigurations") or []}


def _targets(config: dict) -> str:
    targets = config.get("includeTargets") or []
    if any(x.get("id") == "all_users" for x in targets):
        return "all users"
    return f"{len(targets)} group(s)" if targets else "no one"


@control(
    "M365-AUT-01",
    "Phishable authentication methods (SMS, voice, email OTP) are enabled",
    "Authentication methods",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.3.5"), cis("5.2.3.5"), maester("EIDSCA.AV01")),
)
def weak_methods(t: Tenant) -> list[Finding]:
    configs = _configs(t)
    on = [(key, configs[key]) for key in WEAK if configs.get(key, {}).get("state") == "enabled"]
    if not on:
        return []
    affected = [
        Affected("authenticationMethod", key, WEAK[key], AUTH_METHODS_URL, {"enabledFor": _targets(cfg)}) for key, cfg in on
    ]
    return [
        Finding(
            title="SMS, voice-call or email codes are allowed as sign-in methods",
            severity="medium",
            description=(
                "The authentication methods policy enables "
                + listing([f"{a.name} (for {a.detail['enabledFor']})" for a in affected])
                + ". These codes can be intercepted by SIM-swap, call forwarding or a real-time phishing proxy, so "
                "MFA that relies on them stops little of what MFA is meant to stop. Voice calls are also a common "
                "vector for MFA-fatigue social engineering."
            ),
            remediation=(
                "Make sure every user has a stronger method first (Microsoft Authenticator with number matching, "
                "passkeys or FIDO2 keys) — check Protection > Authentication methods > User registration details. "
                "Then, in Authentication methods > Policies, disable Voice call and SMS (or restrict them to a "
                "small exception group), and disable Email OTP for members (keep it only if guests use it for "
                "one-time access)."
            ),
            affected=affected,
            evidence={key: {"state": cfg.get("state"), "includeTargets": cfg.get("includeTargets")} for key, cfg in on},
        )
    ]


@control(
    "M365-AUT-02",
    "Member accounts without any MFA method registered",
    "Authentication methods",
    licence="Entra ID P1",
    permissions=("AuditLog.Read.All", "User.Read.All"),
    references=(maester("MT.1024.mfaRegistrationV2"),),
)
def members_without_mfa(t: Tenant) -> list[Finding]:
    users = t.users
    missing = []
    for uid, reg in t.registration_details.items():
        user = users.get(uid)
        if not user or user.get("userType") != "Member" or not user.get("accountEnabled"):
            continue
        if not reg.get("isMfaRegistered"):
            missing.append(Affected("user", uid, display(user), user_url(uid), {"methodsRegistered": reg.get("methodsRegistered") or []}))
    if not missing:
        return []
    members = sum(1 for u in users.values() if u.get("userType") == "Member" and u.get("accountEnabled"))
    return [
        Finding(
            title="Enabled member accounts have no MFA method registered",
            severity="high",
            description=(
                f"{len(missing)} of {members} enabled member accounts have not registered any MFA method: "
                + listing([a.name for a in missing])
                + ". Guests are not counted — their MFA is handled by their home tenant. An account with no method "
                "can be enrolled by whoever first signs in with its password, and any policy that 'requires MFA' "
                "will prompt that person to register their own device."
            ),
            remediation=(
                "Run an MFA registration campaign (Protection > Authentication methods > Registration campaign) "
                "for these accounts, require registration from a trusted location or with a Temporary Access Pass, "
                "and disable accounts nobody uses (shared or leaver accounts are the usual culprits). Room, "
                "equipment and service accounts should not sign in interactively at all: block sign-in for them "
                "instead of registering MFA."
            ),
            affected=missing,
            evidence={"membersWithoutMfa": [a.id for a in missing], "enabledMembers": members},
        )
    ]


@control(
    "M365-AUT-03",
    "No phishing-resistant authentication method is enabled",
    "Authentication methods",
    permissions=("Policy.Read.All",),
    references=(cisa("MS.AAD.3.1"), maester("EIDSCA.AF01")),
)
def phishing_resistant(t: Tenant) -> list[Finding]:
    configs = _configs(t)
    if any(configs.get(key, {}).get("state") == "enabled" for key in PHISHING_RESISTANT):
        return []
    return [
        Finding(
            title="Phishing-resistant sign-in (passkeys, FIDO2, certificates) is not available",
            severity="low",
            description=(
                "Neither FIDO2 security keys / passkeys nor certificate-based authentication is enabled in the "
                "authentication methods policy, so users cannot register a factor that resists adversary-in-the-"
                "middle phishing, and Conditional Access cannot require the 'Phishing-resistant MFA' strength — "
                "not even for administrators."
            ),
            remediation=(
                "In Protection > Authentication methods > Policies, enable 'Passkey (FIDO2)' for at least the "
                "administrators (ideally all users), allowing device-bound passkeys in Microsoft Authenticator and "
                "FIDO2 keys. Then target administrators with the 'Phishing-resistant MFA' authentication strength."
            ),
            affected=[Affected("authenticationMethod", key, name, AUTH_METHODS_URL, {"state": configs.get(key, {}).get("state", "absent")}) for key, name in PHISHING_RESISTANT.items()],
            evidence={key: configs.get(key, {}).get("state") for key in PHISHING_RESISTANT},
        )
    ]
