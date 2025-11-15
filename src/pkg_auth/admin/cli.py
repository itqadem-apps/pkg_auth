# src/pkg_auth/keycloak_admin/__main__.py

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any, Sequence

from .env import settings_from_env
from . import provision_keycloak_client


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Provision Keycloak API client, roles and audience mappers",
    )

    parser.add_argument(
        "--client-id",
        help="Override API clientId (default: {APP_NAME|SERVICE_NAME}-api)",
    )
    parser.add_argument(
        "--permissions",
        "-P",
        nargs="*",
        help="Explicit list of permission/role names "
             "(if omitted, your caller can pass them programmatically).",
    )
    parser.add_argument(
        "--frontend-client-ids",
        "-F",
        nargs="*",
        help="Frontend clientIds to grant audience and client-roles mappers to "
             "(defaults from env KEYCLOAK_FRONTEND_CLIENT_IDS).",
    )
    parser.add_argument(
        "--remove-frontend-client-ids",
        "-R",
        nargs="*",
        help="Frontend clientIds to remove audience + roles mappers from "
             "(effective only with --strict-audience).",
    )
    parser.add_argument(
        "--strict-roles",
        action="store_true",
        help="Reconcile roles strictly: create missing and delete extra roles.",
    )
    parser.add_argument(
        "--strict-audience",
        action="store_true",
        help="Reconcile audience + roles mappers strictly and remove mappers "
             "from --remove-frontend-client-ids.",
    )

    return parser.parse_args(args=argv)


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    settings = settings_from_env()
    return await provision_keycloak_client(
        settings=settings,
        client_id=args.client_id,
        permissions=list(args.permissions or []),
        frontend_client_ids=list(args.frontend_client_ids or []),
        remove_frontend_client_ids=list(args.remove_frontend_client_ids or []),
        strict_roles=bool(args.strict_roles),
        strict_audience=bool(args.strict_audience),
    )


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)

    try:
        summary = asyncio.run(_run(args))
        json.dump({"ok": True, **summary}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    except Exception as exc:  # noqa: BLE001
        json.dump({"ok": False, "error": str(exc)}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        raise


if __name__ == "__main__":
    main()
