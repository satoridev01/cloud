"""Identity Protection: accounts Microsoft currently believes are compromised."""

from __future__ import annotations

from .. import cvss
from ..context import PRIVILEGED_ROLES, Tenant, display, user_url
from ..model import Affected, Finding, NotEvaluated, control

RISK_URL = "https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/RiskyUsers"


@control(
    "M365-IDP-01",
    "Accounts Microsoft rates as compromised right now",
    "Identity Protection",
    licence="Entra ID P2",
    permissions=("IdentityRiskyUser.Read.All",),
)
def risky_users(t: Tenant) -> list[Finding]:
    try:
        rows = list(t.graph.list("identityProtection/riskyUsers?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"))
    except Exception as e:  # noqa: BLE001 — surfaced as not evaluated
        raise NotEvaluated(f"Could not read risky users ({e}).") from None
    rows = [r for r in rows if r.get("riskLevel") in ("high", "medium") or r.get("riskState") == "confirmedCompromised"]
    if not rows:
        return []
    admins = {(a.get("principal") or {}).get("id") for a in t.privileged_assignments}
    affected = [
        Affected(
            "user",
            r["id"],
            display({"displayName": r.get("userDisplayName"), "userPrincipalName": r.get("userPrincipalName"), "id": r["id"]}),
            user_url(r["id"]),
            {"riskLevel": r.get("riskLevel"), "riskState": r.get("riskState"), "riskDetail": r.get("riskDetail"), "lastUpdated": r.get("riskLastUpdatedDateTime"), "privileged": r["id"] in admins},
        )
        for r in sorted(rows, key=lambda r: (r.get("riskLevel") != "high", r.get("userPrincipalName") or ""))
    ]
    privileged = [a for a in affected if a.detail["privileged"]]
    return [
        Finding(
            title="Microsoft currently rates some accounts as compromised",
            severity="critical" if privileged else "high",
            cvss=cvss.TENANT_TAKEOVER if privileged else cvss.COMPROMISE_INDICATOR,
            description=(
                f"Entra ID Protection rates {len(affected)} account(s) at medium or high risk and still unremediated — "
                "typically because its password appeared in a leak or its sign-ins look like an attacker's:\n"
                + "\n".join(f"- {a.name}: {a.detail['riskLevel']} risk, {a.detail['riskState']}" + (" (holds a privileged role)" if a.detail["privileged"] else "") + "." for a in affected)
                + "\nThis is not a configuration weakness but a sign that someone may already have these credentials."
            ),
            remediation=(
                "For each account, investigate the risk detections (Protection > Identity Protection > Risky users > "
                "user > Risk history): reset the password and revoke sessions (Revoke sessions / "
                "revokeSignInSessions), check recent sign-ins, inbox rules and consented apps for signs of misuse, "
                "then confirm compromised or dismiss the risk. Make the risk policies (M365-CA-08) enforce this "
                "automatically."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]
