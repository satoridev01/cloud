"""Intune: whether device compliance, which Conditional Access relies on, means anything."""

from __future__ import annotations

from .. import cvss
from ..context import Tenant
from ..model import Affected, Finding, NotApplicable, NotEvaluated, cis, control, maester

INTUNE_URL = "https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/~/complianceSettings"


@control(
    "M365-INT-01",
    "Devices without a compliance policy count as compliant",
    "Devices",
    permissions=("DeviceManagementConfiguration.Read.All",),
    references=(maester("MT.1054"), cis("4.1")),
)
def secure_by_default(t: Tenant) -> list[Finding]:
    if not t.licences["intune"]:
        raise NotApplicable("The tenant has no Intune licence.")
    try:
        settings = t.graph.get("deviceManagement/settings")
    except Exception as e:  # noqa: BLE001 — surfaced as not evaluated
        raise NotEvaluated(f"Could not read Intune settings ({e}).") from None
    if settings.get("secureByDefault"):
        return []
    return [
        Finding(
            title="Intune treats devices that have no compliance policy as compliant",
            severity="medium",
            cvss=cvss.WEAKENED_DEFENCE,
            description=(
                "The Intune setting 'Mark devices with no compliance policy assigned as' is Compliant, so any "
                "enrolled device nobody has assigned a policy to — a personal phone, a test machine, a newly "
                "joined laptop — passes as compliant. Conditional Access policies that require a compliant device "
                "then let those devices through, which quietly undoes the control."
            ),
            remediation=(
                "In the Intune admin center > Devices > Compliance > Compliance settings, set 'Mark devices with no "
                "compliance policy assigned as' to Not compliant, after making sure every platform in use has a "
                "compliance policy assigned to its users or devices."
            ),
            affected=[Affected("tenantSetting", "secureByDefault", "Intune compliance settings: devices with no policy", INTUNE_URL, {"secureByDefault": False})],
            evidence={"secureByDefault": settings.get("secureByDefault")},
            resource="Intune compliance settings: devices with no compliance policy = Compliant",
        )
    ]
