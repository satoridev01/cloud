"""Controls against a fake Graph built from synthetic data (no real tenant, no network)."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cloudposture import controls  # noqa: E402,F401 — registers the controls
from cloudposture.context import GLOBAL_ADMIN, GRAPH_APP_ID, MICROSOFT_TENANT_ID, Tenant  # noqa: E402
from cloudposture.graph import GraphError  # noqa: E402
from cloudposture.report import run  # noqa: E402
from cloudposture.controls.domains import _tags  # noqa: E402

NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
TENANT_ID = "11111111-1111-1111-1111-111111111111"


def policy(pid, name, state="enabled", users=None, apps=None, grants=None, **conditions):
    return {
        "id": pid,
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {"includeUsers": ["All"], "excludeUsers": [], "includeGroups": [], "excludeGroups": [], "includeRoles": [], **(users or {})},
            "applications": {"includeApplications": ["All"], "includeUserActions": [], **(apps or {})},
            "clientAppTypes": ["all"],
            **conditions,
        },
        "grantControls": {"operator": "OR", "builtInControls": grants if grants is not None else ["mfa"]},
    }


PR_STRENGTH = {"id": "00000000-0000-0000-0000-000000000004", "displayName": "Phishing-resistant MFA", "allowedCombinations": ["windowsHelloForBusiness", "fido2", "x509CertificateMultiFactor"]}
MFA_STRENGTH = {"id": "00000000-0000-0000-0000-000000000002", "displayName": "Multifactor authentication", "allowedCombinations": ["fido2", "password,microsoftAuthenticatorPush", "password,sms"]}


def admin_policy(pid="p-adm", strength=PR_STRENGTH, session=True, users=None, **over):
    p = policy(pid, "Admins: phishing-resistant MFA", users=users or {"includeUsers": [], "includeRoles": [GLOBAL_ADMIN]}, grants=[], **over)
    p["grantControls"]["authenticationStrength"] = strength
    p["sessionControls"] = {"signInFrequency": {"isEnabled": True, "type": "hours", "value": 4}, "persistentBrowser": {"isEnabled": True, "mode": "never"}} if session else None
    return p


def base_data(**over):
    data = {
        "organization": [{"id": TENANT_ID, "displayName": "Contoso", "verifiedDomains": [{"name": "contoso.com", "isDefault": True}, {"name": "contoso.onmicrosoft.com", "isInitial": True}]}],
        "subscribedSkus": [{"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"}, {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"}]}],
        "policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
        "identity/conditionalAccess/policies": [
            policy("p-mfa", "MFA all"),
            policy("p-legacy", "Block legacy", grants=["block"], clientAppTypes=["exchangeActiveSync", "other"]),
            policy("p-ur", "User risk", grants=["block"], userRiskLevels=["high"]),
            policy("p-sr", "Sign-in risk", grants=["mfa"], signInRiskLevels=["high", "medium"]),
            policy("p-dc", "Block device code", grants=["block"], authenticationFlows={"transferMethods": "deviceCodeFlow"}),
            admin_policy(),
            policy("p-dev", "Managed devices", grants=["compliantDevice", "domainJoinedDevice"]),
        ],
        "identity/conditionalAccess/namedLocations": [],
        "oauth2PermissionGrants": [],
        "identityProtection/riskyUsers": [],
        "deviceManagement/settings": {"secureByDefault": True},
        "policies/authorizationPolicy": {"allowInvitesFrom": "adminsAndGuestInviters", "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3", "defaultUserRolePermissions": {"allowedToCreateApps": False, "permissionGrantPoliciesAssigned": []}},
        "policies/adminConsentRequestPolicy": {"isEnabled": True, "notifyReviewers": True, "reviewers": [{"query": "/users/u-admin1", "queryType": "MicrosoftGraph"}]},
        "admin/sharepoint/settings": {"sharingCapability": "existingExternalUserSharingOnly", "sharingDomainRestrictionMode": "none", "isResharingByExternalUsersEnabled": False, "isRequireAcceptingUserToMatchInvitedUserEnabled": True},
        "policies/authenticationMethodsPolicy": {"authenticationMethodConfigurations": [{"id": "Fido2", "state": "enabled"}, {"id": "Sms", "state": "disabled"}]},
        "users": [
            {"id": "u-admin1", "displayName": "Admin One", "userPrincipalName": "a1@contoso.com", "userType": "Member", "accountEnabled": True},
            {"id": "u-admin2", "displayName": "Admin Two", "userPrincipalName": "a2@contoso.com", "userType": "Member", "accountEnabled": True},
            {"id": "u-guest", "displayName": "Guest", "userPrincipalName": "g_x.com#EXT#@contoso.com", "userType": "Guest", "accountEnabled": True},
        ],
        "roleManagement/directory/roleDefinitions": [{"id": GLOBAL_ADMIN, "templateId": GLOBAL_ADMIN, "displayName": "Global Administrator"}],
        "roleManagement/directory/roleAssignments": [
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.user", "id": "u-admin1", "displayName": "Admin One"}},
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.user", "id": "u-admin2", "displayName": "Admin Two"}},
        ],
        "roleManagement/directory/roleAssignmentScheduleInstances": [],
        "reports/authenticationMethods/userRegistrationDetails": [
            {"id": "u-admin1", "isMfaRegistered": True, "methodsRegistered": ["microsoftAuthenticatorPush"]},
            {"id": "u-admin2", "isMfaRegistered": True, "methodsRegistered": ["fido2"]},
            {"id": "u-guest", "isMfaRegistered": False, "methodsRegistered": []},
        ],
        "signInActivity": {"lastSuccessfulSignInDateTime": "2026-09-20T00:00:00Z"},
        "servicePrincipals": [],
        "applications": [],
        "domains": [],
    }
    data.update(over)
    return data


class FakeGraph:
    def __init__(self, data, forbidden=()):
        self.data = data
        self.forbidden = set(forbidden)
        self.calls = 0

    def _key(self, path):
        return path.split("?")[0]

    def _check(self, key):
        if key in self.forbidden:
            raise GraphError(403, "Authorization_RequestDenied", "Insufficient privileges", key)

    def get(self, path, beta=False):
        self.calls += 1
        key = self._key(path)
        self._check(key)
        if key == "deviceManagement/settings":
            return self.data["deviceManagement/settings"]
        if key.startswith("users/"):
            return {"signInActivity": self.data["signInActivity"]}
        if key.startswith("groups/"):
            return {"displayName": "Excluded users"}
        return self.data[key]

    def list(self, path, beta=False):
        self.calls += 1
        key = self._key(path)
        self._check(key)
        if key.endswith("/appRoleAssignedTo"):
            return iter(self.data.get("grants", []))
        if key.endswith("/owners"):
            return iter(self.data.get("owners", {}).get(key.split("/")[1], []))
        if key.endswith("/transitiveMembers"):
            gid = key.split("/")[1]
            return iter({"@odata.type": "#microsoft.graph.user", "id": u} for u in self.data.get("members", {}).get(gid, []))
        return iter(self.data.get(key, []))

    def post_read(self, path, body):
        known = {u["id"]: {"@odata.type": "#microsoft.graph.user", **u} for u in self.data["users"]}
        known.update({g["id"]: {"@odata.type": "#microsoft.graph.group", **g} for g in self.data.get("groups", [])})
        return {"value": [known[i] for i in body["ids"] if i in known]}


def assess(data, forbidden=(), only=None):
    return run(Tenant(FakeGraph(data, forbidden), now=NOW), only)


def by_id(doc):
    return {c["id"]: c for c in doc["controls"]}


def finding(doc, control):
    return next(f for f in doc["findings"] if f["control"] == control)


class ConditionalAccessTests(unittest.TestCase):
    def test_well_configured_tenant_passes(self):
        doc = assess(base_data())
        failed = [c["id"] for c in doc["controls"] if c["status"] == "fail"]
        self.assertEqual(failed, [], doc["findings"])

    def test_policy_targeting_none_protects_nothing(self):
        data = base_data()
        data["identity/conditionalAccess/policies"].append(policy("p-az", "Azure MFA", apps={"includeApplications": ["None"]}))
        f = finding(assess(data), "M365-CA-01")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual(f["affected"][0]["id"], "p-az")
        self.assertIn("Azure MFA", f["resource"])
        self.assertTrue(f["affected"][0]["portalUrl"].endswith("/policyId/p-az"))

    def test_mfa_skipped_from_trusted_locations_is_medium(self):
        data = base_data()
        data["identity/conditionalAccess/policies"][0] = policy(
            "p-mfa", "MFA except office", locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]}
        )
        f = finding(assess(data), "M365-CA-02")
        self.assertEqual(f["severity"], "medium")
        self.assertIn("trusted", f["title"].lower())

    def test_no_mfa_policy_is_high(self):
        data = base_data()
        data["identity/conditionalAccess/policies"] = [p for p in data["identity/conditionalAccess/policies"] if p["id"] not in ("p-mfa", "p-adm")]
        doc = assess(data)
        self.assertEqual(finding(doc, "M365-CA-02")["severity"], "high")
        self.assertEqual(by_id(doc)["M365-CA-03"]["status"], "fail")

    def test_security_defaults_satisfy_mfa_and_legacy(self):
        data = base_data(**{"policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": True}, "identity/conditionalAccess/policies": []})
        controls = by_id(assess(data))
        for cid in ("M365-CA-02", "M365-CA-03", "M365-CA-04", "M365-CA-05"):
            self.assertEqual(controls[cid]["status"], "pass", cid)

    def test_risk_policies_only_in_report_only(self):
        data = base_data()
        for p in data["identity/conditionalAccess/policies"]:
            if p["id"] in ("p-ur", "p-sr"):
                p["state"] = "enabledForReportingButNotEnforced"
        doc = assess(data)
        f = finding(doc, "M365-CA-08")
        self.assertEqual(f["severity"], "medium")
        self.assertEqual({a["id"] for a in f["affected"]}, {"p-ur", "p-sr"})
        self.assertIn("report-only", f["resource"])
        self.assertIn("only logged", f["title"])
        # Report-only risk policies are CA-08's, not repeated under CA-07.
        self.assertNotEqual(by_id(doc)["M365-CA-07"]["status"], "fail")

    def test_risk_control_not_applicable_without_p2(self):
        data = base_data(subscribedSkus=[{"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"}]}])
        doc = assess(data)
        self.assertEqual(by_id(doc)["M365-CA-08"]["status"], "not_applicable")
        self.assertEqual(finding(doc, "M365-LIC-01")["severity"], "info")


def without(data, *ids):
    data["identity/conditionalAccess/policies"] = [p for p in data["identity/conditionalAccess/policies"] if p["id"] not in ids]
    return data


class SignInTests(unittest.TestCase):
    def test_phishing_resistant_mfa_for_all_users_passes(self):
        data = without(base_data(), "p-adm")
        data["identity/conditionalAccess/policies"].append(admin_policy("p-all", users={"includeUsers": ["All"], "includeRoles": []}))
        self.assertEqual(by_id(assess(data))["M365-CA-10"]["status"], "pass")

    def test_admins_with_ordinary_mfa_strength(self):
        data = without(base_data(), "p-adm")
        data["identity/conditionalAccess/policies"].append(admin_policy(strength=MFA_STRENGTH))
        f = finding(assess(data), "M365-CA-10")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("medium", 6.8))
        self.assertEqual(f["resource"], "Directory role: Global Administrator")

    def test_strength_by_id_alone_counts(self):
        data = base_data()
        data["identity/conditionalAccess/policies"][-2]["grantControls"]["authenticationStrength"] = {"id": "00000000-0000-0000-0000-000000000004"}
        self.assertEqual(by_id(assess(data))["M365-CA-10"]["status"], "pass")

    def test_strength_beside_an_alternative_grant_is_not_required(self):
        data = base_data()
        data["identity/conditionalAccess/policies"][-2]["grantControls"]["builtInControls"] = ["compliantDevice"]
        self.assertEqual(by_id(assess(data))["M365-CA-10"]["status"], "fail")

    def test_eligible_only_role_needs_phishing_resistant_mfa_too(self):
        data = base_data()
        data["roleManagement/directory/roleEligibilityScheduleInstances"] = [
            {"roleDefinitionId": "e8611ab8-c189-46e8-94e1-60213ab1f814", "directoryScopeId": "/", "principal": user_principal("u-admin1", "Admin One")}
        ]
        f = finding(assess(data), "M365-CA-10")
        self.assertIn("Privileged Role Administrator (1 eligible)", f["description"])

    def test_report_only_policy_is_named(self):
        data = base_data()
        data["identity/conditionalAccess/policies"][-2]["state"] = "enabledForReportingButNotEnforced"
        f = finding(assess(data), "M365-CA-10")
        self.assertIn("'Admins: phishing-resistant MFA' (enabledForReportingButNotEnforced", f["description"])

    def test_sign_in_controls_not_applicable_without_p1(self):
        controls = by_id(assess(base_data(subscribedSkus=NO_PREMIUM)))
        for cid in ("M365-CA-10", "M365-CA-11", "M365-CA-12"):
            self.assertEqual(controls[cid]["status"], "not_applicable", cid)

    def test_sign_in_controls_not_evaluated_without_policy_read(self):
        doc = assess(base_data(), forbidden={"identity/conditionalAccess/policies"})
        for cid in ("M365-CA-10", "M365-CA-11", "M365-CA-12"):
            self.assertEqual(by_id(doc)[cid]["status"], "not_evaluated", cid)
            self.assertIn("Policy.Read.All", by_id(doc)[cid]["permissions"])

    def test_no_device_requirement(self):
        f = finding(assess(without(base_data(), "p-dev")), "M365-CA-11")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("medium", 5.9))
        self.assertEqual(f["resource"], "Conditional Access: no policy requires a managed device")

    def test_device_policy_for_one_platform_is_partial(self):
        data = without(base_data(), "p-dev")
        data["identity/conditionalAccess/policies"].append(
            policy("p-win", "Windows compliant", grants=["compliantDevice"], platforms={"includePlatforms": ["windows"]})
        )
        f = finding(assess(data), "M365-CA-11")
        self.assertEqual(f["affected"][0]["id"], "p-win")

    def test_device_or_mfa_does_not_require_a_device(self):
        data = without(base_data(), "p-dev")
        data["identity/conditionalAccess/policies"].append(policy("p-or", "Device or MFA", grants=["compliantDevice", "mfa"]))
        self.assertEqual(by_id(assess(data))["M365-CA-11"]["status"], "fail")

    def test_device_and_mfa_requires_a_device(self):
        data = without(base_data(), "p-dev")
        p = policy("p-and", "Device and MFA", grants=["compliantDevice", "mfa"])
        p["grantControls"]["operator"] = "AND"
        data["identity/conditionalAccess/policies"].append(p)
        self.assertEqual(by_id(assess(data))["M365-CA-11"]["status"], "pass")

    def test_no_session_limit_for_admins(self):
        data = without(base_data(), "p-adm")
        data["identity/conditionalAccess/policies"].append(admin_policy(session=False))
        f = finding(assess(data), "M365-CA-12")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("low", 3.1))
        self.assertEqual([a["name"] for a in f["affected"]], ["Global Administrator"])

    def test_sign_in_frequency_on_a_risk_policy_does_not_count(self):
        data = without(base_data(), "p-adm")
        data["identity/conditionalAccess/policies"].append(admin_policy(session=False))
        risky = data["identity/conditionalAccess/policies"][2]
        risky["sessionControls"] = {"signInFrequency": {"isEnabled": True, "frequencyInterval": "everyTime"}}
        self.assertEqual(by_id(assess(data))["M365-CA-12"]["status"], "fail")

    def test_never_persistent_browser_for_all_users_passes(self):
        data = without(base_data(), "p-adm")
        data["identity/conditionalAccess/policies"][0]["sessionControls"] = {"persistentBrowser": {"isEnabled": True, "mode": "never"}}
        self.assertEqual(by_id(assess(data))["M365-CA-12"]["status"], "pass")


VENDOR = "99999999-0000-0000-0000-000000000000"


class NewControlTests(unittest.TestCase):
    def test_device_code_not_blocked(self):
        data = base_data()
        data["identity/conditionalAccess/policies"] = [p for p in data["identity/conditionalAccess/policies"] if p["id"] != "p-dc"]
        f = finding(assess(data), "M365-CA-09")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("high", 8.1))

    def test_trusted_locations_are_the_location_of_the_mfa_gap(self):
        data = base_data(**{"identity/conditionalAccess/namedLocations": [
            {"id": "n1", "displayName": "Vendor ranges", "isTrusted": True, "ipRanges": [{"cidrAddress": "10.10.0.0/16"}, {"cidrAddress": "203.0.113.0/24"}]},
            {"id": "n2", "displayName": "Office", "isTrusted": True, "ipRanges": [{"cidrAddress": "192.168.0.0/24"}]},
        ]})
        data["identity/conditionalAccess/policies"][0] = policy("p-mfa", "MFA except trusted", locations={"includeLocations": ["All"], "excludeLocations": ["AllTrusted"]})
        f = finding(assess(data), "M365-CA-02")
        lines = f["resource"].split("\n")
        self.assertEqual(len(lines), 2)
        self.assertIn("65,792 addresses", f["description"])
        office = next(a for a in f["affected"] if a["id"] == "n2")
        self.assertIn("private range", office["detail"]["note"])

    def test_tenant_wide_delegated_consent(self):
        app = {"id": "sp-pnp", "appId": "31359c7f-bd7e-475c-86db-fdb8c937548e", "displayName": "PnP Management Shell", "appOwnerOrganizationId": VENDOR}
        data = base_data(servicePrincipals=[app], oauth2PermissionGrants=[
            {"clientId": "sp-pnp", "consentType": "AllPrincipals", "scope": "Directory.ReadWrite.All Mail.ReadWrite"},
            {"clientId": "sp-pnp", "consentType": "Principal", "scope": "RoleManagement.ReadWrite.Directory"},
        ])
        f = finding(assess(data), "M365-APP-06")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["affected"][0]["detail"]["scopes"], ["Directory.ReadWrite.All", "Mail.ReadWrite"])
        self.assertIn("retired", f["description"])

    def test_ordinary_owner_of_a_privileged_app(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "rm", "value": "RoleManagement.ReadWrite.Directory"}]}
        mine = {"id": "sp-mine", "appId": "app-mine", "displayName": "Sync Tool", "appOwnerOrganizationId": TENANT_ID}
        data = base_data(servicePrincipals=[graph_sp, mine], grants=[{"principalId": "sp-mine", "appRoleId": "rm"}],
                         owners={"sp-mine": [{"@odata.type": "#microsoft.graph.user", "id": "u-guest", "displayName": "Dev", "userPrincipalName": "dev@contoso.com"}]})
        f = finding(assess(data), "M365-APP-07")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["resource"], "Account: Dev (dev@contoso.com) — owner of Sync Tool")

    def test_disabled_owner_is_not_reported(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "rm", "value": "Mail.ReadWrite"}]}
        mine = {"id": "sp-mine", "appId": "app-mine", "displayName": "Mailer", "appOwnerOrganizationId": TENANT_ID}
        data = base_data(servicePrincipals=[graph_sp, mine], grants=[{"principalId": "sp-mine", "appRoleId": "rm"}],
                         owners={"sp-mine": [{"@odata.type": "#microsoft.graph.user", "id": "u-x", "displayName": "Old", "accountEnabled": False}]})
        self.assertEqual(by_id(assess(data))["M365-APP-07"]["status"], "pass")

    def test_microsoft_corporate_tenant_apps_are_first_party(self):
        cli = {"id": "sp-cli", "appId": "14d82eec-204b-4c2f-b7e8-296a70dab67e", "displayName": "Microsoft Graph Command Line Tools", "appOwnerOrganizationId": "72f988bf-86f1-41af-91ab-2d7cd011db47"}
        data = base_data(servicePrincipals=[cli], oauth2PermissionGrants=[{"clientId": "sp-cli", "consentType": "AllPrincipals", "scope": "User.ReadWrite.All"}])
        self.assertEqual(by_id(assess(data))["M365-APP-06"]["status"], "pass")

    def test_admin_owner_is_not_reported(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "rm", "value": "RoleManagement.ReadWrite.Directory"}]}
        mine = {"id": "sp-mine", "appId": "app-mine", "displayName": "Sync Tool", "appOwnerOrganizationId": TENANT_ID}
        data = base_data(servicePrincipals=[graph_sp, mine], grants=[{"principalId": "sp-mine", "appRoleId": "rm"}],
                         owners={"sp-mine": [{"@odata.type": "#microsoft.graph.user", "id": "u-admin1", "displayName": "Admin One"}]})
        self.assertEqual(by_id(assess(data))["M365-APP-07"]["status"], "pass")

    def test_secret_on_a_microsoft_app(self):
        ms = {"id": "sp-ms", "appId": "app-ms", "displayName": "Office 365 Exchange Online", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "passwordCredentials": [{}], "keyCredentials": [{"usage": "Sign"}]}
        f = finding(assess(base_data(servicePrincipals=[ms])), "M365-APP-08")
        self.assertEqual(f["affected"][0]["detail"], {"appId": "app-ms", "clientSecrets": 1, "certificates": 0})

    def test_admin_client_without_assignment(self):
        cli = {"id": "sp-cli", "appId": "14d82eec-204b-4c2f-b7e8-296a70dab67e", "displayName": "Microsoft Graph Command Line Tools", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoleAssignmentRequired": False}
        f = finding(assess(base_data(servicePrincipals=[cli])), "M365-APP-09")
        self.assertEqual(f["resource"], "Application: Microsoft Graph Command Line Tools")

    def test_risky_admin_is_critical(self):
        data = base_data(**{"identityProtection/riskyUsers": [{"id": "u-admin1", "userDisplayName": "Admin One", "userPrincipalName": "a1@contoso.com", "riskLevel": "high", "riskState": "atRisk"}]})
        f = finding(assess(data), "M365-IDP-01")
        self.assertEqual(f["severity"], "critical")

    def test_intune_not_secure_by_default(self):
        plans = [{"servicePlanName": n, "provisioningStatus": "Success"} for n in ("AAD_PREMIUM", "AAD_PREMIUM_P2", "INTUNE_A")]
        data = base_data(subscribedSkus=[{"capabilityStatus": "Enabled", "servicePlans": plans}], **{"deviceManagement/settings": {"secureByDefault": False}})
        self.assertEqual(finding(assess(data), "M365-INT-01")["severity"], "medium")


class PasswordOnlyTests(unittest.TestCase):
    def test_account_excluded_through_a_group_signs_in_with_password_alone(self):
        data = base_data(members={"g-excl": ["u-room"]})
        data["users"].append({"id": "u-room", "displayName": "Board room", "userPrincipalName": "room@contoso.com", "userType": "Member", "accountEnabled": True})
        data["reports/authenticationMethods/userRegistrationDetails"].append({"id": "u-room", "isMfaRegistered": False, "methodsRegistered": []})
        data["identity/conditionalAccess/policies"][0]["conditions"]["users"]["excludeGroups"] = ["g-excl"]
        f = finding(assess(data), "M365-CA-06")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["resource"], "Account: Board room (room@contoso.com)")
        self.assertEqual(f["affected"][0]["detail"]["why"], ["excluded through group Excluded users"])
        self.assertFalse(f["affected"][0]["detail"]["mfaRegistered"])

    def test_admin_covered_by_a_role_policy_is_not_reported(self):
        data = base_data(members={"g-excl": ["u-admin1"]})
        data["identity/conditionalAccess/policies"][0]["conditions"]["users"]["excludeGroups"] = ["g-excl"]
        data["identity/conditionalAccess/policies"].append(
            policy("p-adm", "Admins MFA", users={"includeUsers": [], "includeRoles": [GLOBAL_ADMIN]})
        )
        self.assertEqual(by_id(assess(data))["M365-CA-06"]["status"], "pass")


class PrivilegedTests(unittest.TestCase):
    def test_single_global_admin(self):
        data = base_data()
        data["roleManagement/directory/roleAssignments"] = data["roleManagement/directory/roleAssignments"][:1]
        f = finding(assess(data), "M365-PRV-01")
        self.assertEqual([a["id"] for a in f["affected"]], ["u-admin1"])

    def test_service_principal_with_global_admin(self):
        data = base_data(
            servicePrincipals=[{"id": "sp-1", "appId": "app-1", "displayName": "Vendor Sync", "appOwnerOrganizationId": "99999999-0000-0000-0000-000000000000", "passwordCredentials": [{}], "keyCredentials": []}]
        )
        data["roleManagement/directory/roleAssignments"].append(
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-1", "appId": "app-1", "displayName": "Vendor Sync"}}
        )
        f = finding(assess(data), "M365-PRV-02")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["affected"][0]["detail"]["publisher"], "third party")
        # A multi-tenant app's secrets live in the publisher's tenant, so none are counted here.
        self.assertIn("publisher", f["affected"][0]["detail"]["credentials"])

    def test_own_app_credentials_come_from_its_registration(self):
        data = base_data(
            servicePrincipals=[{"id": "sp-2", "appId": "app-2", "displayName": "Internal Sync", "appOwnerOrganizationId": TENANT_ID}],
            applications=[{"id": "o-2", "appId": "app-2", "displayName": "Internal Sync", "passwordCredentials": [{}, {}], "keyCredentials": []}],
        )
        data["roleManagement/directory/roleAssignments"].append(
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "sp-2", "appId": "app-2", "displayName": "Internal Sync"}}
        )
        detail = finding(assess(data), "M365-PRV-02")["affected"][0]["detail"]
        self.assertEqual((detail["publisher"], detail["clientSecrets"]), ("this tenant", 2))

    def test_single_dead_policy_reads_in_the_singular(self):
        data = base_data()
        data["identity/conditionalAccess/policies"].append(policy("p-az", "Azure MFA", apps={"includeApplications": ["None"]}))
        desc = finding(assess(data), "M365-CA-01")["description"]
        self.assertIn("'Azure MFA' is enabled but selects no target resources", desc)

    def test_stale_admin(self):
        data = base_data(signInActivity={"lastSuccessfulSignInDateTime": "2026-01-01T00:00:00Z"})
        f = finding(assess(data), "M365-PRV-04")
        self.assertEqual(len(f["affected"]), 2)
        self.assertGreaterEqual(f["affected"][0]["detail"]["daysInactive"], 45)


EXCHANGE_ADMIN = "29232cdf-9323-42fd-ade2-1d097af3e4de"
P1_ONLY = [{"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"}]}]
NO_PREMIUM = [{"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "EXCHANGE_S_STANDARD", "provisioningStatus": "Success"}]}]


def group_principal(gid, name):
    return {"@odata.type": "#microsoft.graph.group", "id": gid, "displayName": name}


def user_principal(uid, name):
    return {"@odata.type": "#microsoft.graph.user", "id": uid, "displayName": name}


class PrivilegedHoldersTests(unittest.TestCase):
    def test_eligible_global_admin_counts_toward_the_minimum(self):
        data = base_data()
        data["roleManagement/directory/roleAssignments"] = data["roleManagement/directory/roleAssignments"][:1]
        data["roleManagement/directory/roleEligibilityScheduleInstances"] = [
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": user_principal("u-admin2", "Admin Two")}
        ]
        self.assertEqual(by_id(assess(data))["M365-PRV-01"]["status"], "pass")

    def test_eligible_admins_are_named_as_eligible_not_standing(self):
        data = base_data()
        data["roleManagement/directory/roleEligibilityScheduleInstances"] = [
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": user_principal(f"u-e{i}", f"Eligible {i}")} for i in range(7)
        ]
        f = finding(assess(data), "M365-PRV-01")
        self.assertEqual(f["title"], "9 users hold Global Administrator")
        self.assertIn("7 of them hold it only as PIM-eligible or through a group", f["description"])
        self.assertEqual(f["evidence"]["heldAs"]["u-e0"], "eligible")

    def test_group_held_role_is_expanded_to_its_members(self):
        data = base_data(members={"g-t0": ["u-sync"]})
        data["users"].append({"id": "u-sync", "displayName": "Synced Admin", "userPrincipalName": "sa@contoso.com", "userType": "Member", "accountEnabled": True, "onPremisesSyncEnabled": True})
        data["roleManagement/directory/roleAssignments"].append(
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": group_principal("g-t0", "Tier 0 admins")}
        )
        f = finding(assess(data), "M365-PRV-03")
        self.assertEqual(f["affected"][0]["id"], "u-sync")
        self.assertEqual(f["affected"][0]["detail"]["heldAs"], {"Global Administrator": "active through group Tier 0 admins"})
        self.assertIn("Global Administrator (active through group Tier 0 admins)", f["description"])

    def test_unreadable_eligibility_is_not_evaluated(self):
        doc = assess(base_data(), forbidden={"roleManagement/directory/roleEligibilityScheduleInstances"})
        self.assertEqual(by_id(doc)["M365-PRV-01"]["status"], "not_evaluated")
        self.assertIn("eligible directory role assignments (PIM)", doc["permissionGaps"])

    def test_eligibility_is_not_read_without_p2(self):
        data = base_data(subscribedSkus=P1_ONLY)
        doc = assess(data, forbidden={"roleManagement/directory/roleEligibilityScheduleInstances"})
        self.assertEqual(by_id(doc)["M365-PRV-01"]["status"], "pass")

    def test_permanent_assignment_through_a_group(self):
        data = base_data(members={"g-t0": ["u-admin1"]})
        data["roleManagement/directory/roleAssignmentScheduleInstances"] = [
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": group_principal("g-t0", "Tier 0 admins")}
        ]
        f = finding(assess(data), "M365-PRV-06")
        self.assertEqual(f["affected"][0]["detail"]["heldAs"], {"Global Administrator": "active through group Tier 0 admins"})


class GroupOwnerTests(unittest.TestCase):
    def data(self, owner):
        data = base_data(owners={"g-t0": [owner]}, members={"g-t0": []})
        data["roleManagement/directory/roleAssignments"].append(
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": group_principal("g-t0", "Tier 0 admins")}
        )
        return data

    def test_ordinary_owner_of_a_role_group(self):
        dev = {"@odata.type": "#microsoft.graph.user", "id": "u-dev", "displayName": "Dev", "userPrincipalName": "dev@contoso.com"}
        f = finding(assess(self.data(dev)), "M365-PRV-07")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("critical", 9.9))
        self.assertEqual(f["resource"], "Account: Dev (dev@contoso.com) — owner of group Tier 0 admins")
        self.assertEqual(f["affected"][0]["detail"]["groupGrants"], ["Global Administrator"])

    def test_tier1_group_is_high(self):
        dev = {"@odata.type": "#microsoft.graph.user", "id": "u-dev", "displayName": "Dev"}
        data = self.data(dev)
        data["roleManagement/directory/roleAssignments"][-1]["roleDefinitionId"] = EXCHANGE_ADMIN
        self.assertEqual(finding(assess(data), "M365-PRV-07")["severity"], "high")

    def test_admin_owner_is_not_reported(self):
        admin = {"@odata.type": "#microsoft.graph.user", "id": "u-admin1", "displayName": "Admin One"}
        self.assertEqual(by_id(assess(self.data(admin)))["M365-PRV-07"]["status"], "pass")

    def test_not_applicable_without_p1(self):
        dev = {"@odata.type": "#microsoft.graph.user", "id": "u-dev", "displayName": "Dev"}
        data = self.data(dev)
        data["subscribedSkus"] = NO_PREMIUM
        self.assertEqual(by_id(assess(data))["M365-PRV-07"]["status"], "not_applicable")

    def test_unreadable_owners_are_not_evaluated(self):
        dev = {"@odata.type": "#microsoft.graph.user", "id": "u-dev", "displayName": "Dev"}
        doc = assess(self.data(dev), forbidden={"groups/g-t0/owners"})
        self.assertEqual(by_id(doc)["M365-PRV-07"]["status"], "not_evaluated")
        self.assertIn("group owners", doc["permissionGaps"])


class PermanentTier1Tests(unittest.TestCase):
    def test_permanent_exchange_admin(self):
        data = base_data()
        data["roleManagement/directory/roleAssignmentScheduleInstances"] = [
            {"roleDefinitionId": EXCHANGE_ADMIN, "directoryScopeId": "/", "principal": user_principal("u-admin1", "Admin One")},
            {"roleDefinitionId": GLOBAL_ADMIN, "directoryScopeId": "/", "principal": user_principal("u-admin2", "Admin Two")},
        ]
        doc = assess(data)
        f = finding(doc, "M365-PRV-08")
        self.assertEqual([a["id"] for a in f["affected"]], ["u-admin1"])
        self.assertEqual(f["affected"][0]["detail"]["roles"], ["Exchange Administrator"])
        # The tier-0 assignment is PRV-06's, not repeated here.
        self.assertEqual([a["id"] for a in finding(doc, "M365-PRV-06")["affected"]], ["u-admin2"])

    def test_time_bound_assignment_passes(self):
        data = base_data()
        data["roleManagement/directory/roleAssignmentScheduleInstances"] = [
            {"roleDefinitionId": EXCHANGE_ADMIN, "directoryScopeId": "/", "endDateTime": "2026-10-01T00:00:00Z", "principal": user_principal("u-admin1", "Admin One")}
        ]
        self.assertEqual(by_id(assess(data))["M365-PRV-08"]["status"], "pass")

    def test_not_applicable_without_p2(self):
        self.assertEqual(by_id(assess(base_data(subscribedSkus=P1_ONLY)))["M365-PRV-08"]["status"], "not_applicable")

    def test_unreadable_schedules_are_not_evaluated(self):
        doc = assess(base_data(), forbidden={"roleManagement/directory/roleAssignmentScheduleInstances"})
        self.assertEqual(by_id(doc)["M365-PRV-08"]["status"], "not_evaluated")


class AuthAndAppsTests(unittest.TestCase):
    def test_guests_are_not_counted_for_mfa_registration(self):
        controls = by_id(assess(base_data()))
        self.assertEqual(controls["M365-AUT-02"]["status"], "pass")

    def test_weak_method_enabled(self):
        data = base_data()
        data["policies/authenticationMethodsPolicy"]["authenticationMethodConfigurations"].append(
            {"id": "Voice", "state": "enabled", "includeTargets": [{"id": "all_users"}]}
        )
        f = finding(assess(data), "M365-AUT-01")
        self.assertEqual(f["affected"][0]["detail"]["enabledFor"], "all users")

    def test_takeover_permission_on_third_party_app(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "r1", "value": "RoleManagement.ReadWrite.Directory"}, {"id": "r2", "value": "User.Read.All"}]}
        vendor = {"id": "sp-v", "appId": "app-v", "displayName": "Backup Vendor", "appOwnerOrganizationId": "99999999-0000-0000-0000-000000000000"}
        data = base_data(servicePrincipals=[graph_sp, vendor], grants=[{"principalId": "sp-v", "appRoleId": "r1"}, {"principalId": "sp-v", "appRoleId": "r2"}])
        doc = assess(data)
        f = finding(doc, "M365-APP-01")
        self.assertEqual(f["severity"], "critical")
        self.assertEqual(f["affected"][0]["detail"]["permissions"], ["RoleManagement.ReadWrite.Directory"])
        self.assertIn("assign any directory role", f["description"])
        # The same app is not repeated under the data-access control.
        self.assertEqual(by_id(doc)["M365-APP-05"]["status"], "pass")

    def test_data_apps_are_atomic_and_exclude_the_scanner(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "m", "value": "MailboxSettings.ReadWrite"}]}
        other = "99999999-0000-0000-0000-000000000000"
        sps = [graph_sp] + [{"id": f"sp-{i}", "appId": f"app-{i}", "displayName": name, "appOwnerOrganizationId": other} for i, name in enumerate(["Mail Tool", "Mail Tool", "Scanner"])]
        data = base_data(servicePrincipals=sps, grants=[{"principalId": f"sp-{i}", "appRoleId": "m"} for i in range(3)])
        doc = run(Tenant(FakeGraph(data), now=NOW, scanner_app_id="app-2"))
        f = finding(doc, "M365-APP-05")
        self.assertEqual(f["resource"].split("\n"), ["Mail Tool (appId app-0)", "Mail Tool (appId app-1)"])
        self.assertIn("forwarding rules", f["description"])

    def test_capabilities_skip_permissions_a_broader_one_includes(self):
        graph_sp = {"id": "sp-graph", "appId": GRAPH_APP_ID, "displayName": "Microsoft Graph", "appOwnerOrganizationId": MICROSOFT_TENANT_ID, "appRoles": [{"id": "r", "value": "Mail.Read"}, {"id": "rw", "value": "Mail.ReadWrite"}]}
        app = {"id": "sp-m", "appId": "app-m", "displayName": "Mailer", "appOwnerOrganizationId": "99999999-0000-0000-0000-000000000000"}
        data = base_data(servicePrincipals=[graph_sp, app], grants=[{"principalId": "sp-m", "appRoleId": "r"}, {"principalId": "sp-m", "appRoleId": "rw"}])
        detail = finding(assess(data), "M365-APP-05")["affected"][0]["detail"]
        self.assertEqual(detail["canDo"], ["read and change mail in every mailbox"])
        self.assertEqual(detail["permissions"], ["Mail.Read", "Mail.ReadWrite"])

    def test_legacy_user_consent_is_high(self):
        data = base_data()
        data["policies/authorizationPolicy"]["defaultUserRolePermissions"]["permissionGrantPoliciesAssigned"] = ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
        self.assertEqual(finding(assess(data), "M365-APP-02")["severity"], "high")


class ConsentTests(unittest.TestCase):
    def grants(self, *rows):
        app = {"id": "sp-mail", "appId": "app-mail", "displayName": "Mail Helper", "appOwnerOrganizationId": VENDOR}
        data = base_data(servicePrincipals=[app], oauth2PermissionGrants=list(rows))
        data["users"].append({"id": "u-amy", "displayName": "Amy", "userPrincipalName": "amy@contoso.com", "userType": "Member", "accountEnabled": True})
        return data

    def test_per_user_consent_to_mail(self):
        data = self.grants({"clientId": "sp-mail", "consentType": "Principal", "principalId": "u-amy", "scope": "openid offline_access Mail.ReadWrite"})
        f = finding(assess(data), "M365-APP-10")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("medium", 5.9))
        self.assertEqual(f["affected"][0]["detail"]["scopes"], ["Mail.ReadWrite"])
        self.assertIn("consented by Amy (amy@contoso.com)", f["description"])

    def test_admin_consenting_to_directory_rights_is_high(self):
        data = self.grants(
            {"clientId": "sp-mail", "consentType": "Principal", "principalId": "u-admin1", "scope": "Directory.AccessAsUser.All"},
            {"clientId": "sp-mail", "consentType": "Principal", "principalId": "u-amy", "scope": "Directory.AccessAsUser.All"},
        )
        f = finding(assess(data), "M365-APP-10")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["affected"][0]["detail"]["administrators"], ["Admin One (a1@contoso.com)"])

    def test_narrow_or_tenant_wide_scopes_pass(self):
        data = self.grants(
            {"clientId": "sp-mail", "consentType": "Principal", "principalId": "u-amy", "scope": "User.Read openid Mail.Read"},
            {"clientId": "sp-mail", "consentType": "AllPrincipals", "scope": "Mail.Read"},
        )
        self.assertEqual(by_id(assess(data))["M365-APP-10"]["status"], "pass")

    def test_microsoft_apps_are_not_reported(self):
        data = self.grants({"clientId": "sp-mail", "consentType": "Principal", "principalId": "u-amy", "scope": "Mail.ReadWrite"})
        data["servicePrincipals"][0]["appOwnerOrganizationId"] = MICROSOFT_TENANT_ID
        self.assertEqual(by_id(assess(data))["M365-APP-10"]["status"], "pass")

    def test_unreadable_grants_are_not_evaluated(self):
        doc = assess(base_data(), forbidden={"oauth2PermissionGrants"})
        self.assertEqual(by_id(doc)["M365-APP-10"]["status"], "not_evaluated")
        self.assertIn("Directory.Read.All", by_id(doc)["M365-APP-10"]["permissions"])

    def test_admin_consent_workflow_off(self):
        data = base_data(**{"policies/adminConsentRequestPolicy": {"isEnabled": False, "reviewers": []}})
        f = finding(assess(data), "M365-APP-11")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("low", 3.1))
        self.assertEqual(f["resource"], "Tenant setting: admin consent workflow")
        self.assertEqual(f["references"][0]["id"], "MS.AAD.5.3")

    def test_admin_consent_workflow_without_reviewers(self):
        data = base_data(**{"policies/adminConsentRequestPolicy": {"isEnabled": True, "reviewers": []}})
        self.assertIn("no reviewers", finding(assess(data), "M365-APP-11")["title"])

    def test_admin_consent_workflow_unreadable(self):
        doc = assess(base_data(), forbidden={"policies/adminConsentRequestPolicy"})
        self.assertEqual(by_id(doc)["M365-APP-11"]["status"], "not_evaluated")
        self.assertIn("the admin consent request policy", doc["permissionGaps"])


def sharing(**over):
    data = base_data()
    data["admin/sharepoint/settings"].update(over)
    return data


class SharingTests(unittest.TestCase):
    def test_anyone_links(self):
        f = finding(assess(sharing(sharingCapability="externalUserAndGuestSharing")), "M365-SHR-01")
        self.assertEqual((f["severity"], f["cvss"]["score"]), ("medium", 5.3))
        self.assertIn("Anyone", f["title"])
        self.assertTrue(f["affected"][0]["portalUrl"].startswith("https://contoso-admin.sharepoint.com/"))
        self.assertTrue(f["references"][0]["url"].endswith("/baselines/sharepoint.md#mssharepoint11v1"))

    def test_new_guests_is_low(self):
        f = finding(assess(sharing(sharingCapability="externalUserSharingOnly")), "M365-SHR-01")
        self.assertEqual(f["severity"], "low")

    def test_settings_wrapped_in_value_are_read(self):
        data = base_data()
        data["admin/sharepoint/settings"] = {"value": {**data["admin/sharepoint/settings"], "sharingCapability": "externalUserAndGuestSharing"}}
        self.assertEqual(by_id(assess(data))["M365-SHR-01"]["status"], "fail")

    def test_missing_permission_is_not_evaluated(self):
        doc = assess(base_data(), forbidden={"admin/sharepoint/settings"})
        for cid in ("M365-SHR-01", "M365-SHR-02", "M365-SHR-03"):
            self.assertEqual(by_id(doc)[cid]["status"], "not_evaluated", cid)
            self.assertEqual(by_id(doc)[cid]["permissions"], ["SharePointTenantSettings.Read.All"])
        self.assertIn("SharePoint tenant settings", doc["permissionGaps"])

    def test_any_domain(self):
        f = finding(assess(sharing(sharingCapability="externalUserSharingOnly")), "M365-SHR-02")
        self.assertEqual(f["resource"], "SharePoint sharing: guests from any domain")

    def test_block_list_still_allows_every_other_domain(self):
        data = sharing(sharingCapability="externalUserSharingOnly", sharingDomainRestrictionMode="blockList", sharingBlockedDomainList=["gmail.com"])
        self.assertIn("only 1 domain(s) are blocked", finding(assess(data), "M365-SHR-02")["description"])

    def test_allow_list_passes(self):
        data = sharing(sharingCapability="externalUserSharingOnly", sharingDomainRestrictionMode="allowList", sharingAllowedDomainList=["fabrikam.com"])
        self.assertEqual(by_id(assess(data))["M365-SHR-02"]["status"], "pass")

    def test_guest_resharing_and_forwarded_invitations(self):
        f = finding(assess(sharing(isResharingByExternalUsersEnabled=True, isRequireAcceptingUserToMatchInvitedUserEnabled=False)), "M365-SHR-03")
        self.assertEqual(len(f["resource"].split("\n")), 2)
        self.assertIn("forwarded invitation", f["description"])

    def test_resharing_is_moot_when_sharing_is_off(self):
        data = sharing(sharingCapability="disabled", isResharingByExternalUsersEnabled=True)
        self.assertEqual(by_id(assess(data))["M365-SHR-03"]["status"], "pass")


class ContractTests(unittest.TestCase):
    def test_missing_permission_is_not_evaluated_not_a_finding(self):
        doc = assess(base_data(), forbidden={"identity/conditionalAccess/policies"})
        self.assertEqual(by_id(doc)["M365-CA-01"]["status"], "not_evaluated")
        self.assertIn("conditional access policies", doc["permissionGaps"])
        self.assertFalse(any(f["control"].startswith("M365-CA-0") for f in doc["findings"]))

    def test_every_finding_carries_the_ingest_fields(self):
        data = base_data(**{"identity/conditionalAccess/policies": []})
        doc = assess(data)
        self.assertTrue(doc["findings"])
        for f in doc["findings"]:
            for field in ("id", "title", "severity", "resource", "description", "remediation"):
                self.assertIsInstance(f[field], str, (f["id"], field))
                self.assertTrue(f[field].strip(), (f["id"], field))
            self.assertIn(f["severity"], ("blocker", "critical", "high", "medium", "low", "info"))
            self.assertIsInstance(f["affected"], list)

    def test_findings_sorted_worst_first(self):
        doc = assess(base_data(**{"identity/conditionalAccess/policies": []}))
        order = ["blocker", "critical", "high", "medium", "low", "info"]
        ranks = [order.index(f["severity"]) for f in doc["findings"]]
        self.assertEqual(ranks, sorted(ranks))


class LocationTests(unittest.TestCase):
    def test_location_names_every_object(self):
        from cloudposture.model import Affected, resource_line

        objs = [Affected("servicePrincipal", str(i), f"App {i}") for i in range(10)]
        line = resource_line("Application", "applications", objs)
        self.assertEqual(line.split("\n"), [f"App {i}" for i in range(10)])


class GraphRetryTests(unittest.TestCase):
    def test_read_timeout_is_retried(self):
        from unittest import mock

        from cloudposture import graph

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b'{"value": []}'

        calls = []

        def urlopen(req, timeout):
            calls.append(1)
            if len(calls) == 1:
                raise TimeoutError("The read operation timed out")
            return Response()

        with mock.patch.object(graph.urllib.request, "urlopen", urlopen), mock.patch.object(graph.time, "sleep", lambda s: None):
            self.assertEqual(graph.Graph("t").get("users"), {"value": []})
        self.assertEqual(len(calls), 2)


class CvssTests(unittest.TestCase):
    def test_scores_match_published_values(self):
        from cloudposture.cvss import score

        for vector, expected in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H", 9.0),
        ]:
            self.assertEqual(score(vector), expected, vector)

    def test_every_finding_scores_in_its_severity_band(self):
        data = base_data(**{"identity/conditionalAccess/policies": []})
        data["policies/authorizationPolicy"].update(allowInvitesFrom="everyone", guestUserRoleId="a0b1b346-4d3e-4e8b-98f8-753987be4970")
        data["policies/authorizationPolicy"]["defaultUserRolePermissions"].update(
            allowedToCreateApps=True, permissionGrantPoliciesAssigned=["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]
        )
        doc = assess(data)
        band = {"blocker": "critical", "critical": "critical", "high": "high", "medium": "medium", "low": "low"}
        scored = [f for f in doc["findings"] if f["severity"] != "info"]
        self.assertGreater(len(scored), 5)
        for f in scored:
            self.assertIn("cvss", f, f["id"])
            self.assertEqual(f["cvss"]["rating"], band[f["severity"]], (f["id"], f["cvss"]))


class DnsParsingTests(unittest.TestCase):
    def test_dmarc_tags(self):
        self.assertEqual(_tags("v=DMARC1; p=Reject; pct=50; rua=mailto:x@y")["p"], "reject")
        self.assertEqual(_tags("v=DMARC1; p=none")["p"], "none")


if __name__ == "__main__":
    unittest.main()
