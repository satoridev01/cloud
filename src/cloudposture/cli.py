"""cloud-posture — read-only security posture assessment for Microsoft 365 / Entra ID tenants."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__, controls  # noqa: F401 — importing controls registers them
from .context import Tenant
from .graph import Graph, GraphError, acquire_token
from .model import REGISTRY
from .report import SCHEMA, run


def _write(doc: dict, path: str | None, pretty: bool) -> None:
    text = json.dumps(doc, indent=2 if pretty else None, ensure_ascii=False, default=str)
    if path and path != "-":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        sys.stdout.write(text + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cloud-posture", description=__doc__)
    parser.add_argument("--version", action="version", version=f"cloud-posture {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    m365 = sub.add_parser("m365", help="assess a Microsoft 365 / Entra ID tenant with an app registration")
    m365.add_argument("--tenant-id", default=os.environ.get("AZURE_TENANT_ID"))
    m365.add_argument("--client-id", default=os.environ.get("AZURE_CLIENT_ID"))
    m365.add_argument("--client-secret", default=os.environ.get("AZURE_CLIENT_SECRET"))
    m365.add_argument("-o", "--output", help="write the assessment JSON here (default: stdout)")
    m365.add_argument("--controls", help="comma-separated control ids to run (default: all)")
    m365.add_argument("--pretty", action="store_true", help="indent the JSON")

    sub.add_parser("controls", help="list the controls and exit")

    args = parser.parse_args(argv)

    if args.command == "controls":
        for c in REGISTRY:
            licence = f"  [{c.licence}]" if c.licence else ""
            print(f"{c.id:12} {c.category:24} {c.title}{licence}")
        return 0

    missing = [n for n in ("tenant_id", "client_id", "client_secret") if not getattr(args, n)]
    if missing:
        parser.error("missing " + ", ".join("--" + m.replace("_", "-") for m in missing) + " (or the AZURE_* environment variables)")

    try:
        graph = Graph(acquire_token(args.tenant_id, args.client_id, args.client_secret))
    except GraphError as e:
        # No findings array: a consumer must read this as "the scan collected nothing", never as clean.
        _write({"schema": SCHEMA, "error": f"authentication failed: {e.code}: {e.message}"}, args.output, args.pretty)
        return 2

    only = {c.strip() for c in args.controls.split(",")} if args.controls else None
    doc = run(Tenant(graph), only)
    _write(doc, args.output, args.pretty)
    s = doc["summary"]
    print(
        f"cloud-posture: {s['controls']} controls — {s['failed']} failed, {s['passed']} passed, "
        f"{s['notApplicable']} not applicable, {s['notEvaluated']} not evaluated, {s['errors']} errors; "
        f"{s['findings']} findings {s['bySeverity']}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
