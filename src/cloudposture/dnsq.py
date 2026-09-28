"""TXT lookups over DNS-over-HTTPS (JSON API), so DMARC/SPF checks need no resolver library and give
the same answer from any container."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

RESOLVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


class DnsError(Exception):
    pass


def txt(name: str) -> list[str]:
    """The TXT records at `name` ([] when none exist). Raises DnsError when no resolver answers."""
    last = ""
    for base in RESOLVERS:
        url = f"{base}?{urllib.parse.urlencode({'name': name, 'type': 'TXT'})}"
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as res:
                data = json.load(res)
        except Exception as e:  # noqa: BLE001 — any failure means "try the next resolver"
            last = str(e)
            continue
        # Status 3 = NXDOMAIN: the name does not exist, so it has no records.
        if data.get("Status") not in (0, 3):
            last = f"DNS status {data.get('Status')}"
            continue
        records = []
        for answer in data.get("Answer", []) or []:
            if answer.get("type") == 16:
                # Long TXT values arrive as several quoted strings; join them back into one.
                value = answer.get("data", "")
                parts = [p for p in value.split('"') if p.strip()]
                records.append("".join(parts) if parts else value)
        return records
    raise DnsError(last or "no resolver answered")
