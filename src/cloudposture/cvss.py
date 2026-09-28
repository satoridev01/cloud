"""CVSS v3.1 base score, from the specification's formula (first.org/cvss/v3.1/specification-document).

A misconfiguration has no CVE, so each finding carries a vector describing its own attack scenario —
what an attacker needs and what they get — and the score is computed from it, never typed in."""

from __future__ import annotations

import math

WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
PREFIX = "CVSS:3.1/"


def _roundup(value: float) -> float:
    whole = round(value * 100000)
    if whole % 10000 == 0:
        return whole / 100000.0
    return (math.floor(whole / 10000) + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    body = vector[len(PREFIX):] if vector.startswith(PREFIX) else vector
    metrics = dict(part.split(":", 1) for part in body.split("/"))
    missing = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"} - metrics.keys()
    if missing:
        raise ValueError(f"CVSS vector {vector!r} lacks {sorted(missing)}")
    return metrics


def score(vector: str) -> float:
    m = parse(vector)
    scope = m["S"]
    iss = 1 - (1 - WEIGHTS["C"][m["C"]]) * (1 - WEIGHTS["I"][m["I"]]) * (1 - WEIGHTS["A"][m["A"]])
    impact = 6.42 * iss if scope == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * WEIGHTS["AV"][m["AV"]] * WEIGHTS["AC"][m["AC"]] * PR[scope][m["PR"]] * WEIGHTS["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    if scope == "U":
        return _roundup(min(impact + exploitability, 10))
    return _roundup(min(1.08 * (impact + exploitability), 10))


def rating(value: float) -> str:
    if value == 0:
        return "none"
    if value < 4.0:
        return "low"
    if value < 7.0:
        return "medium"
    if value < 9.0:
        return "high"
    return "critical"


def vector(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> str:
    return f"{PREFIX}AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


# The attack scenarios the controls describe, as vectors. Adjacent (AV:A) is "from a trusted network".
TENANT_TAKEOVER = vector("N", "H", "N", "N", "C", "H", "H", "H")  # a stolen credential controls the tenant
PASSWORD_TO_DATA = vector("N", "H", "N", "N", "U", "H", "H", "N")  # one password, no second factor
TRUSTED_NETWORK_GAP = vector("A", "H", "N", "N", "U", "H", "H", "N")
TRUSTED_NETWORK_ADMIN = vector("A", "H", "L", "N", "U", "H", "H", "N")
ONPREM_TO_CLOUD = vector("N", "H", "H", "N", "C", "H", "H", "H")
ONPREM_TO_CLOUD_LIMITED = vector("N", "H", "H", "N", "U", "H", "H", "N")
WEAKENED_DEFENCE = vector("N", "H", "N", "N", "U", "L", "L", "N")
PHISHABLE_MFA = vector("N", "H", "N", "R", "U", "H", "L", "N")
PHISHABLE_ADMIN_MFA = vector("N", "H", "N", "R", "U", "H", "H", "N")
CONSENT_PHISHING = vector("N", "L", "N", "R", "U", "H", "L", "N")
DIRECTORY_EXPOSURE = vector("N", "L", "L", "N", "U", "L", "N", "N")
SPOOFING = vector("N", "L", "N", "R", "U", "N", "L", "N")
OPEN_SPOOFING = vector("N", "L", "N", "R", "C", "L", "H", "N")
HARDENING = vector("N", "H", "L", "N", "U", "L", "N", "N")
HARDENING_USER = vector("N", "H", "N", "R", "U", "L", "N", "N")
STANDING_ACCESS = vector("N", "H", "H", "N", "U", "L", "L", "N")
AVAILABILITY = vector("N", "H", "H", "N", "U", "N", "N", "L")
TOKEN_PHISHING = vector("N", "L", "N", "R", "U", "H", "H", "N")  # the victim completes MFA for the attacker
DELEGATED_DATA = vector("N", "H", "N", "R", "U", "H", "L", "N")
OWNER_TAKEOVER = vector("N", "L", "L", "N", "C", "H", "H", "H")  # an ordinary user adds a secret and becomes the app
OWNER_TO_DATA = vector("N", "L", "L", "N", "U", "H", "H", "N")
COMPROMISE_INDICATOR = vector("N", "L", "N", "N", "U", "H", "L", "N")
