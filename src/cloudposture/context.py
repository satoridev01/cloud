"""The tenant as the controls see it: each Graph read happens once and is shared, and a read the app
has no permission for turns every control that needs it into "not evaluated" rather than a finding."""

from __future__ import annotations

from datetime import datetime, timezone
from functools import cached_property
from typing import Any

from .graph import Graph, GraphError
from .model import NotApplicable, NotEvaluated

ENTRA = "https://entra.microsoft.com"

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
EXCHANGE_APP_ID = "00000002-0000-0ff1-ce00-000000000000"
AZURE_MANAGEMENT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"

# Directory roles that can take over the tenant or its identity plane (role template ids). The tier
# decides severity: tier 0 reaches Global Administrator directly or in one step.
PRIVILEGED_ROLES: dict[str, tuple[str, int]] = {
    GLOBAL_ADMIN: ("Global Administrator", 0),
    "e8611ab8-c189-46e8-94e1-60213ab1f814": ("Privileged Role Administrator", 0),
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": ("Privileged Authentication Administrator", 0),
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": ("Hybrid Identity Administrator", 0),
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": ("Application Administrator", 1),
    "158c047a-c907-4556-b7ef-446551a6b5f7": ("Cloud Application Administrator", 1),
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": ("Conditional Access Administrator", 1),
    "194ae4cb-b126-40b2-bd5b-6091b380977d": ("Security Administrator", 1),
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": ("Authentication Administrator", 1),
    "fe930be7-5e62-47db-91af-98c3a49a38b1": ("User Administrator", 1),
    "29232cdf-9323-42fd-ade2-1d097af3e4de": ("Exchange Administrator", 1),
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": ("SharePoint Administrator", 1),
    "3a2c62db-5318-420d-8d74-23affee5d9d5": ("Intune Administrator", 1),
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": ("Helpdesk Administrator", 1),
}


def user_url(user_id: str) -> str:
    return f"{ENTRA}/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}"


def sp_url(sp_id: str, app_id: str | None = None) -> str:
    tail = f"/appId/{app_id}" if app_id else ""
    return f"{ENTRA}/#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{sp_id}{tail}"


def app_url(app_id: str) -> str:
    return f"{ENTRA}/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/{app_id}"


def policy_url(policy_id: str) -> str:
    return f"{ENTRA}/#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/{policy_id}"


def group_url(group_id: str) -> str:
    return f"{ENTRA}/#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/{group_id}"


def role_url(template_id: str) -> str:
    return f"{ENTRA}/#view/Microsoft_AAD_IAM/RoleMenuBlade/~/RoleMembers/objectId/{template_id}/roleTemplateId/{template_id}"


AUTH_METHODS_URL = f"{ENTRA}/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods"
CA_POLICIES_URL = f"{ENTRA}/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies"
USER_SETTINGS_URL = f"{ENTRA}/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings"
CONSENT_URL = f"{ENTRA}/#view/Microsoft_AAD_IAM/ConsentPoliciesMenuBlade/~/UserSettings"
EXTERNAL_COLLAB_URL = f"{ENTRA}/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/Settings"
SECURITY_DEFAULTS_URL = f"{ENTRA}/#view/Microsoft_AAD_IAM/TenantOverview.ReactView"
DOMAINS_URL = "https://admin.microsoft.com/#/Domains"


class Tenant:
    """Cached, read-only views of one tenant, fetched on first use."""

    def __init__(self, graph: Graph, now: datetime | None = None, scanner_app_id: str | None = None):
        self.graph = graph
        self.now = now or datetime.now(timezone.utc)
        # The app registration running this assessment: it holds read permissions by design.
        self.scanner_app_id = scanner_app_id
        self.permission_gaps: dict[str, str] = {}

    def _read(self, what: str, fn):
        try:
            return fn()
        except GraphError as e:
            if e.forbidden:
                self.permission_gaps[what] = e.message
                raise NotEvaluated(f"The scanner's app registration cannot read {what} ({e.code}: {e.message}).") from None
            raise NotEvaluated(f"Reading {what} failed ({e.status} {e.code}: {e.message}).") from None

    # ---- tenant and licences ----

    @cached_property
    def organization(self) -> dict[str, Any]:
        orgs = self._read("the organization", lambda: list(self.graph.list("organization")))
        return orgs[0] if orgs else {}

    @cached_property
    def service_plans(self) -> set[str]:
        """Every service plan the tenant has an active subscription for (e.g. AAD_PREMIUM_P2)."""
        skus = self._read("subscribed SKUs", lambda: list(self.graph.list("subscribedSkus")))
        plans: set[str] = set()
        for sku in skus:
            if sku.get("capabilityStatus") not in ("Enabled", "Warning"):
                continue
            for plan in sku.get("servicePlans", []):
                if plan.get("provisioningStatus") != "Disabled":
                    plans.add(plan.get("servicePlanName", ""))
        return plans

    @cached_property
    def licences(self) -> dict[str, bool]:
        plans = self.service_plans
        return {
            "entraIdP1": bool(plans & {"AAD_PREMIUM", "AAD_PREMIUM_P2"}),
            "entraIdP2": "AAD_PREMIUM_P2" in plans,
            "intune": "INTUNE_A" in plans,
            "defenderForOffice365": bool(plans & {"ATP_ENTERPRISE", "THREAT_INTELLIGENCE"}),
        }

    def require(self, licence: str | None) -> None:
        """Raise NotApplicable when the tenant lacks the licence a control needs."""
        if licence == "Entra ID P1" and not self.licences["entraIdP1"]:
            raise NotApplicable("Needs Microsoft Entra ID P1, which the tenant does not have.")
        if licence == "Entra ID P2" and not self.licences["entraIdP2"]:
            raise NotApplicable("Needs Microsoft Entra ID P2, which the tenant does not have.")

    # ---- policies ----

    @cached_property
    def security_defaults(self) -> bool:
        policy = self._read("security defaults", lambda: self.graph.get("policies/identitySecurityDefaultsEnforcementPolicy"))
        return bool(policy.get("isEnabled"))

    @cached_property
    def ca_policies(self) -> list[dict[str, Any]]:
        return self._read("conditional access policies", lambda: list(self.graph.list("identity/conditionalAccess/policies")))

    @cached_property
    def authorization_policy(self) -> dict[str, Any]:
        return self._read("the authorization policy", lambda: self.graph.get("policies/authorizationPolicy"))

    @cached_property
    def auth_methods_policy(self) -> dict[str, Any]:
        return self._read("the authentication methods policy", lambda: self.graph.get("policies/authenticationMethodsPolicy"))

    # ---- directory ----

    @cached_property
    def users(self) -> dict[str, dict[str, Any]]:
        select = "id,displayName,userPrincipalName,userType,accountEnabled,onPremisesSyncEnabled,mail,createdDateTime"
        rows = self._read("users", lambda: list(self.graph.list(f"users?$select={select}&$top=999")))
        return {u["id"]: u for u in rows}

    @cached_property
    def role_definitions(self) -> dict[str, dict[str, Any]]:
        rows = self._read("directory role definitions", lambda: list(self.graph.list("roleManagement/directory/roleDefinitions")))
        return {r["id"]: r for r in rows}

    @cached_property
    def role_assignments(self) -> list[dict[str, Any]]:
        """Active directory role assignments at tenant scope, each with its principal expanded."""
        rows = self._read(
            "directory role assignments",
            lambda: list(self.graph.list("roleManagement/directory/roleAssignments?$expand=principal")),
        )
        return [r for r in rows if r.get("directoryScopeId", "/") == "/"]

    def role_template(self, assignment: dict[str, Any]) -> str:
        definition = self.role_definitions.get(assignment.get("roleDefinitionId", ""), {})
        return definition.get("templateId") or assignment.get("roleDefinitionId", "")

    def role_name(self, template_id: str) -> str:
        if template_id in PRIVILEGED_ROLES:
            return PRIVILEGED_ROLES[template_id][0]
        for d in self.role_definitions.values():
            if d.get("templateId") == template_id:
                return d.get("displayName", template_id)
        return template_id

    @cached_property
    def privileged_assignments(self) -> list[dict[str, Any]]:
        return [a for a in self.role_assignments if self.role_template(a) in PRIVILEGED_ROLES]

    @cached_property
    def registration_details(self) -> dict[str, dict[str, Any]]:
        """MFA registration per user (Entra ID P1 report)."""
        rows = self._read(
            "authentication method registration details",
            lambda: list(self.graph.list("reports/authenticationMethods/userRegistrationDetails")),
        )
        return {r["id"]: r for r in rows}

    def sign_in_activity(self, user_id: str) -> dict[str, Any]:
        return self._read(
            "user sign-in activity",
            lambda: self.graph.get(f"users/{user_id}?$select=id,signInActivity").get("signInActivity") or {},
        )

    @cached_property
    def service_principals(self) -> dict[str, dict[str, Any]]:
        select = "id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,accountEnabled,passwordCredentials,keyCredentials,appRoles"
        rows = self._read("service principals", lambda: list(self.graph.list(f"servicePrincipals?$select={select}&$top=999")))
        return {s["id"]: s for s in rows}

    def sp_by_app(self, app_id: str) -> dict[str, Any] | None:
        return next((s for s in self.service_principals.values() if s.get("appId") == app_id), None)

    def app_role_grants(self, resource_app_id: str) -> list[dict[str, Any]]:
        """Application permissions granted on a resource API (who holds which app role on it)."""
        resource = self.sp_by_app(resource_app_id)
        if not resource:
            return []
        return self._read(
            "application permission grants",
            lambda: list(self.graph.list(f"servicePrincipals/{resource['id']}/appRoleAssignedTo?$top=999")),
        )

    @cached_property
    def applications(self) -> list[dict[str, Any]]:
        select = "id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime"
        return self._read("app registrations", lambda: list(self.graph.list(f"applications?$select={select}&$top=999")))

    def credentials(self, sp: dict[str, Any]) -> dict[str, Any]:
        """How an application authenticates, as far as this tenant can see. A multi-tenant app's secrets
        live on its registration in the publisher's tenant, so only the tenant's own apps are counted."""
        if sp.get("appOwnerOrganizationId") not in (None, self.organization.get("id")):
            return {"credentials": "held by the publisher (not visible from this tenant)"}
        app = next((a for a in self.applications if a.get("appId") == sp.get("appId")), None)
        source = app or sp
        return {
            "clientSecrets": len(source.get("passwordCredentials") or []),
            "certificates": len(source.get("keyCredentials") or []),
        }

    @cached_property
    def domains(self) -> list[dict[str, Any]]:
        return self._read("domains", lambda: list(self.graph.list("domains")))

    def resolve_names(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        """Directory objects (users, groups, service principals) by id, in batches of 1000."""
        found: dict[str, dict[str, Any]] = {}
        wanted = [i for i in dict.fromkeys(ids) if i and i not in ("All", "GuestsOrExternalUsers", "None")]
        for start in range(0, len(wanted), 1000):
            batch = wanted[start : start + 1000]
            res = self._read(
                "directory objects",
                lambda: self.graph.post_read("directoryObjects/getByIds", {"ids": batch}),
            )
            for obj in res.get("value", []):
                found[obj["id"]] = obj
        return found


def display(obj: dict[str, Any]) -> str:
    name = obj.get("displayName") or obj.get("userPrincipalName") or obj.get("id", "")
    upn = obj.get("userPrincipalName")
    return f"{name} ({upn})" if upn and upn != name else name


def principal_kind(obj: dict[str, Any]) -> str:
    kind = obj.get("@odata.type", "").rsplit(".", 1)[-1]
    return {"user": "user", "servicePrincipal": "servicePrincipal", "group": "group"}.get(kind, kind or "principal")


def principal_url(obj: dict[str, Any]) -> str | None:
    kind = principal_kind(obj)
    if kind == "user":
        return user_url(obj["id"])
    if kind == "servicePrincipal":
        return sp_url(obj["id"], obj.get("appId"))
    if kind == "group":
        return group_url(obj["id"])
    return None


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
