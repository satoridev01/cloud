# cloud-posture

Read-only security posture assessment for **Microsoft 365 / Entra ID** tenants, built to produce
findings a person can act on:

- **Location** — every finding names the objects it is about (the Conditional Access policy, account,
  application, role or domain), with a direct link to it in the Entra / Microsoft 365 admin centre.
- **Description** — what is wrong in this tenant, with the concrete names and counts, and why it matters.
- **Remediation** — the steps to fix it, with the admin-centre path.
- **Evidence** — the facts the finding was decided from, as JSON.

It is licence-aware (a check that needs Entra ID P1/P2 is reported *not applicable* on a tenant without
it, not as a misconfiguration), deduplicated (one control per issue, not the same gap reported by three
frameworks), and a missing Graph permission makes a control *not evaluated* rather than a false finding.

The controls were chosen from what CISA SCuBA, CIS Microsoft 365, Maester/EIDSCA and Prowler check,
keeping the ones that describe a real, exploitable weakness and dropping hygiene noise ("setting not
configured explicitly", cosmetic branding, settings whose Microsoft-managed default is already secure).

## Usage

Standard library only (Python 3.10+), no install needed:

```sh
export AZURE_TENANT_ID=... AZURE_CLIENT_ID=... AZURE_CLIENT_SECRET=...
PYTHONPATH=src python3 -m cloudposture m365 --pretty -o assessment.json
PYTHONPATH=src python3 -m cloudposture controls        # list the controls
```

or `pip install git+https://github.com/satoridev01/cloud` and run `cloud-posture m365`.

A summary goes to stderr; the assessment JSON to stdout or `-o`. Exit code 2 (with an `error` document
and no `findings` array) means authentication failed — never read that as a clean tenant.

### App registration

Create an Entra app registration with a client secret and grant these Microsoft Graph **application**
permissions (admin consent), all read-only:

- `Application.Read.All`
- `AuditLog.Read.All`
- `Directory.Read.All`
- `Domain.Read.All`
- `Organization.Read.All`
- `Policy.Read.All`
- `RoleAssignmentSchedule.Read.Directory`
- `RoleManagement.Read.Directory`
- `User.Read.All`

A missing permission only marks the controls that need it as `not_evaluated`, listed in
`permissionGaps`.

## Controls

| ID | Category | Control | Needs | Also checked by |
|---|---|---|---|---|
| `M365-CA-01` | Conditional Access | Conditional Access policies that apply to nothing | — | Maester MT.1184 |
| `M365-CA-02` | Conditional Access | MFA is not required for all users | — | CISA SCuBA MS.AAD.3.2 |
| `M365-CA-03` | Conditional Access | MFA is not required for administrator roles | — | CISA SCuBA MS.AAD.3.6 |
| `M365-CA-04` | Conditional Access | Legacy authentication is not blocked | — | CISA SCuBA MS.AAD.1.1 |
| `M365-CA-05` | Conditional Access | Azure management is not protected by MFA | — | Maester MT.1184 |
| `M365-CA-06` | Conditional Access | Accounts and groups excluded from MFA or block policies | — | Maester MT.1005, Maester MT.1036 |
| `M365-CA-07` | Conditional Access | Protective Conditional Access policies left in report-only or disabled | — | Maester MT.1184 |
| `M365-CA-08` | Conditional Access | Risky users and risky sign-ins are not challenged or blocked | Entra ID P2 | CISA SCuBA MS.AAD.2.1, CISA SCuBA MS.AAD.2.3, Maester MT.1012, Maester MT.1024.userRiskPolicy |
| `M365-PRV-01` | Privileged access | Global Administrator count outside 2–8 | — | CISA SCuBA MS.AAD.7.1, CIS Microsoft 365 Foundations 1.1.3, Maester MT.1024.oneAdmin |
| `M365-PRV-02` | Privileged access | Applications (service principals) hold privileged directory roles | — | CISA SCuBA MS.AAD.7.4, Maester MT.1027 |
| `M365-PRV-03` | Privileged access | Privileged roles held by accounts synced from on-premises | — | CISA SCuBA MS.AAD.7.3 |
| `M365-PRV-04` | Privileged access | Inactive accounts keep privileged roles | Entra ID P1 | Maester MT.1029 |
| `M365-PRV-05` | Privileged access | Administrators without MFA registered | Entra ID P1 | CISA SCuBA MS.AAD.3.6, Maester MT.1024.mfaRegistrationV2 |
| `M365-PRV-06` | Privileged access | Permanent (non-PIM) assignments to highly privileged roles | Entra ID P2 | CISA SCuBA MS.AAD.7.4, CISA SCuBA MS.AAD.7.5 |
| `M365-AUT-01` | Authentication methods | Phishable authentication methods (SMS, voice, email OTP) are enabled | — | CISA SCuBA MS.AAD.3.5, CIS Microsoft 365 Foundations 5.2.3.5, Maester EIDSCA.AV01 |
| `M365-AUT-02` | Authentication methods | Member accounts without any MFA method registered | Entra ID P1 | Maester MT.1024.mfaRegistrationV2 |
| `M365-AUT-03` | Authentication methods | No phishing-resistant authentication method is enabled | — | CISA SCuBA MS.AAD.3.1, Maester EIDSCA.AF01 |
| `M365-APP-01` | Applications | Applications with tenant-wide write or data-access permissions | — | Maester MT.1186 |
| `M365-APP-02` | Applications | Users can consent to applications | — | CISA SCuBA MS.AAD.5.2 |
| `M365-APP-03` | Applications | Users can register applications | — | CISA SCuBA MS.AAD.5.1 |
| `M365-APP-04` | Applications | Application secrets that are long-lived or expired | — | Maester MT.1024.managedIdentity |
| `M365-TEN-01` | Tenant settings | Anyone, including guests, can invite external users | — | CISA SCuBA MS.AAD.8.2 |
| `M365-TEN-02` | Tenant settings | Guests have the same directory access as members | — | CISA SCuBA MS.AAD.8.1 |
| `M365-LIC-01` | Licensing | Identity protection and PIM are not licensed | — | — |
| `M365-DOM-01` | Mail domains | Email domains without an enforcing DMARC policy | — | Maester MT.1182 |
| `M365-DOM-02` | Mail domains | Email domains without a strict SPF record | — | — |

## Output

```jsonc
{
  "schema": "https://github.com/satoridev01/cloud#assessment-v1",
  "tool": { "name": "cloud-posture", "version": "0.1.0" },
  "tenant": { "id": "…", "displayName": "…", "defaultDomain": "…" },
  "licences": { "entraIdP1": true, "entraIdP2": false, "intune": true, "defenderForOffice365": false },
  "summary": { "controls": 26, "failed": 9, "passed": 14, "notApplicable": 2, "notEvaluated": 1, "findings": 9 },
  "controls": [ { "id": "M365-CA-01", "status": "fail|pass|not_applicable|not_evaluated|error", "reason": "…" } ],
  "permissionGaps": { "…": "…" },
  "findings": [
    {
      "id": "M365-CA-01",
      "control": "M365-CA-01",
      "category": "Conditional Access",
      "title": "Conditional Access policies are switched on but protect nothing",
      "severity": "critical|high|medium|low|info",
      "resource": "Conditional Access policy: CA04 - Azure Management: Require MFA",
      "description": "Finished prose: what is wrong here, with names and counts, and why it matters.",
      "remediation": "Finished prose: the steps and admin-centre path to fix it.",
      "affected": [ { "type": "conditionalAccessPolicy", "id": "…", "name": "…", "portalUrl": "https://entra.microsoft.com/…", "detail": {} } ],
      "evidence": { },
      "references": [ { "framework": "Maester", "id": "MT.1184", "url": "…" } ]
    }
  ]
}
```

`id`, `title`, `severity`, `resource`, `description` and `remediation` are always non-empty strings, so
the `findings` array can be ingested as-is; `affected` and `evidence` carry the structured detail.

## Satori

`satori://cloud/m365-cloud-posture.yml` in [satorici/playbooks](https://github.com/satorici/playbooks)
runs this tool and prints the assessment from its `assessment:json` step:

```sh
satori run satori://cloud/m365-cloud-posture.yml -d AZURE_TENANT_ID=... -d AZURE_CLIENT_ID=... -d AZURE_CLIENT_SECRET=... --output
```

## Development

```sh
python3 -m unittest discover -s tests -v
```

Tests run against a fake Graph with synthetic data. Never commit a real assessment: it contains the
tenant's users, policies and applications.
