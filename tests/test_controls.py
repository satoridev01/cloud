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


def base_data(**over):
    data = {
        "organization": [{"id": TENANT_ID, "displayName": "Contoso", "verifiedDomains": [{"name": "contoso.com", "isDefault": True}]}],
        "subscribedSkus": [{"capabilityStatus": "Enabled", "servicePlans": [{"servicePlanName": "AAD_PREMIUM", "provisioningStatus": "Success"}, {"servicePlanName": "AAD_PREMIUM_P2", "provisioningStatus": "Success"}]}],
        "policies/identitySecurityDefaultsEnforcementPolicy": {"isEnabled": False},
        "identity/conditionalAccess/policies": [
            policy("p-mfa", "MFA all"),
            policy("p-legacy", "Block legacy", grants=["block"], clientAppTypes=["exchangeActiveSync", "other"]),
            policy("p-ur", "User risk", grants=["block"], userRiskLevels=["high"]),
            policy("p-sr", "Sign-in risk", grants=["mfa"], signInRiskLevels=["high", "medium"]),
        ],
        "policies/authorizationPolicy": {"allowInvitesFrom": "adminsAndGuestInviters", "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3", "defaultUserRolePermissions": {"allowedToCreateApps": False, "permissionGrantPoliciesAssigned": []}},
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
        data["identity/conditionalAccess/policies"] = data["identity/conditionalAccess/policies"][1:]
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
