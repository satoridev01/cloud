"""Mail domains: whether others can send email as the organisation's verified domains."""

from __future__ import annotations

from ..context import DOMAINS_URL, Tenant
from ..dnsq import DnsError, txt
from ..model import Affected, Finding, control, maester


def _mail_domains(t: Tenant) -> list[str]:
    return [
        d["id"]
        for d in t.domains
        if d.get("isVerified") and not d["id"].endswith(".onmicrosoft.com") and "Email" in (d.get("supportedServices") or [])
    ]


def _tags(record: str) -> dict[str, str]:
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().lower()
    return out


@control(
    "M365-DOM-01",
    "Email domains without an enforcing DMARC policy",
    "Mail domains",
    permissions=("Domain.Read.All",),
    references=(maester("MT.1182"),),
)
def dmarc(t: Tenant) -> list[Finding]:
    affected = []
    for domain in _mail_domains(t):
        try:
            records = [r for r in txt(f"_dmarc.{domain}") if r.lower().startswith("v=dmarc1")]
        except DnsError as e:
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": f"DNS lookup failed ({e})"}))
            continue
        if not records:
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": "no DMARC record", "record": None}))
            continue
        tags = _tags(records[0])
        policy, pct = tags.get("p", "none"), tags.get("pct", "100")
        if policy == "none":
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": "p=none (monitoring only)", "record": records[0]}))
        elif pct != "100":
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": f"p={policy} applied to only {pct}% of mail", "record": records[0]}))
    if not affected:
        return []
    missing = [a for a in affected if a.detail["problem"] == "no DMARC record"]
    return [
        Finding(
            title="Email domains can be spoofed: DMARC is missing or not enforced",
            severity="medium",
            description=(
                f"{len(affected)} verified email domain(s) do not publish an enforcing DMARC policy: "
                + "; ".join(f"{a.name} — {a.detail['problem']}" for a in affected)
                + ". Without p=quarantine or p=reject, receiving mail servers deliver messages that forge these "
                "domains, which is the basis of invoice-fraud and CEO-fraud phishing against clients and staff."
                + (f" {len(missing)} have no record at all." if missing else "")
            ),
            remediation=(
                "Publish SPF and DKIM for each domain first (Microsoft Defender > Email authentication settings > "
                "DKIM), then a DMARC record at _dmarc.<domain> starting at 'v=DMARC1; p=none; rua=mailto:<reports>'. "
                "Once reports show only legitimate senders, move to p=quarantine and then p=reject with pct=100. "
                "Domains that never send mail should publish 'v=DMARC1; p=reject' and 'v=spf1 -all'."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]


@control(
    "M365-DOM-02",
    "Email domains without a strict SPF record",
    "Mail domains",
    permissions=("Domain.Read.All",),
)
def spf(t: Tenant) -> list[Finding]:
    affected = []
    for domain in _mail_domains(t):
        try:
            records = [r for r in txt(domain) if r.lower().startswith("v=spf1")]
        except DnsError as e:
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": f"DNS lookup failed ({e})"}))
            continue
        if not records:
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": "no SPF record", "record": None}))
        elif len(records) > 1:
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": "more than one SPF record (invalid)", "record": records}))
        elif any(tok in ("+all", "?all", "all") for tok in records[0].lower().split()):
            affected.append(Affected("domain", domain, domain, DOMAINS_URL, {"problem": "SPF allows any sender (+all/?all)", "record": records[0]}))
    if not affected:
        return []
    return [
        Finding(
            title="Email domains have no SPF record, or one that allows anyone",
            severity="medium",
            description=(
                f"{len(affected)} verified email domain(s) have a missing, duplicated or permissive SPF record: "
                + "; ".join(f"{a.name} — {a.detail['problem']}" for a in affected)
                + ". SPF tells receivers which servers may send for the domain; without a valid one, forged mail "
                "from these domains is far more likely to be accepted."
            ),
            remediation=(
                "Publish exactly one TXT record at the domain root listing the real senders and ending in -all "
                "(or ~all while testing), e.g. 'v=spf1 include:spf.protection.outlook.com -all'. Merge duplicate "
                "records into one."
            ),
            affected=affected,
            evidence={a.id: a.detail for a in affected},
        )
    ]
