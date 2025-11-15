from __future__ import annotations

import asyncio
import time
import urllib.parse
from typing import Any, Optional, Dict, List

import httpx

from .settings import KCAdminSettings


class KeycloakAdminClient:
    """
    Minimal async Keycloak Admin wrapper.

    - obtains admin tokens
    - retries once on 401
    - exposes helpers for clients, roles, and protocol mappers
    """

    def __init__(self, settings: KCAdminSettings, client: Optional[httpx.AsyncClient] = None):
        self.s = settings
        self._client = client or httpx.AsyncClient(verify=self.s.verify_ssl, timeout=30.0)
        self._token: Optional[str] = None
        self._token_exp: float = 0.0
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # token management
    # ------------------------------------------------------------------ #

    async def _get_token(self) -> str:
        # reuse cached token if still valid
        if self._token and time.time() < (self._token_exp - 20):
            return self._token

        async with self._lock:
            if self._token and time.time() < (self._token_exp - 20):
                return self._token

            token_url = f"{self.s.base_url_slash}realms/master/protocol/openid-connect/token"
            data = {
                "client_id": "admin-cli",
                "username": self.s.keycloak_admin_user,
                "password": self.s.keycloak_admin_pass,
                "grant_type": "password",
            }
            resp = await self._client.post(token_url, data=data)
            try:
                resp.raise_for_status()
            except httpx.HTTPStatusError as e:
                raise RuntimeError(
                    f"Failed to obtain admin token: {e.response.status_code} {e.response.text}"
                ) from e

            payload = resp.json()
            self._token = payload["access_token"]
            self._token_exp = time.time() + float(payload.get("expires_in", 60))
            return self._token

    def _auth_headers(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        token = await self._get_token()
        resp = await self._client.request(
            method,
            url,
            headers=self._auth_headers(token),
            params=params,
            json=json,
        )
        if resp.status_code == 401:
            # refresh once
            await self._get_token()
            token = self._token or ""
            resp = await self._client.request(
                method,
                url,
                headers=self._auth_headers(token),
                params=params,
                json=json,
            )
        resp.raise_for_status()
        return resp

    # ------------------------------------------------------------------ #
    # base helpers
    # ------------------------------------------------------------------ #

    def _realm_admin(self) -> str:
        return f"{self.s.base_url_slash}admin/realms/{self.s.keycloak_realm}"

    # ------------------------------------------------------------------ #
    # client management
    # ------------------------------------------------------------------ #

    async def get_client_by_client_id(self, client_id: str) -> Optional[dict[str, Any]]:
        url = f"{self._realm_admin()}/clients"
        resp = await self._request("GET", url, params={"clientId": client_id})
        arr = resp.json() or []
        return arr[0] if arr else None

    async def create_client(self, client_repr: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._realm_admin()}/clients"
        try:
            resp = await self._request("POST", url, json=client_repr)
        except httpx.HTTPStatusError as e:
            # handle race: 409 when another process created it
            if e.response is not None and e.response.status_code == 409:
                existing = await self.get_client_by_client_id(client_repr["clientId"])
                if existing:
                    return existing
            raise

        location = resp.headers.get("Location")
        if location:
            fetch = await self._request("GET", location)
            return fetch.json()

        created = await self.get_client_by_client_id(client_repr["clientId"])
        if not created:
            raise RuntimeError("Client creation succeeded but could not read back the resource.")
        return created

    async def update_client(self, internal_id: str, client_repr: dict[str, Any]) -> dict[str, Any]:
        url = f"{self._realm_admin()}/clients/{internal_id}"
        await self._request("PUT", url, json=client_repr)
        fetch = await self._request("GET", url)
        return fetch.json()

    async def ensure_client(self, client_repr: dict[str, Any]) -> dict[str, Any]:
        """
        Idempotently create or update a client by clientId.
        Returns the trimmed server representation.
        """
        existing = await self.get_client_by_client_id(client_repr["clientId"])
        if not existing:
            created = await self.create_client(client_repr)
            return self._trim_client(created)

        internal_id = existing["id"]
        merged = {**existing, **client_repr}
        updated = await self.update_client(internal_id, merged)
        return self._trim_client(updated)

    # ------------------------------------------------------------------ #
    # roles
    # ------------------------------------------------------------------ #

    async def list_client_roles(self, internal_id: str) -> list[str]:
        url = f"{self._realm_admin()}/clients/{internal_id}/roles"
        resp = await self._request("GET", url)
        return [r.get("name") for r in (resp.json() or [])]

    async def create_client_role(
        self,
        internal_id: str,
        name: str,
        description: Optional[str] = None,
    ) -> None:
        url = f"{self._realm_admin()}/clients/{internal_id}/roles"
        payload: Dict[str, Any] = {"name": name}
        if description:
            payload["description"] = description
        await self._request("POST", url, json=payload)

    async def ensure_client_roles(self, internal_id: str, role_names: List[str]) -> dict[str, int]:
        existing = set(await self.list_client_roles(internal_id))
        created = 0
        for name in role_names:
            if name not in existing:
                await self.create_client_role(internal_id, name)
                created += 1
        return {
            "created": created,
            "existing": len(existing.intersection(set(role_names))),
        }

    async def delete_client_role(self, internal_id: str, role_name: str) -> None:
        encoded = urllib.parse.quote(role_name, safe="")
        url = f"{self._realm_admin()}/clients/{internal_id}/roles/{encoded}"
        await self._request("DELETE", url)

    async def ensure_client_roles_strict(self, internal_id: str, desired_roles: List[str]) -> dict[str, int]:
        existing = set(await self.list_client_roles(internal_id))
        desired = set(desired_roles)
        to_create = sorted(desired - existing)
        to_delete = sorted(existing - desired)
        created = 0
        deleted = 0
        for r in to_create:
            await self.create_client_role(internal_id, r)
            created += 1
        for r in to_delete:
            await self.delete_client_role(internal_id, r)
            deleted += 1
        return {
            "created": created,
            "deleted": deleted,
            "kept": len(existing & desired),
        }

    # ------------------------------------------------------------------ #
    # protocol mappers (audience + roles)
    # ------------------------------------------------------------------ #

    async def list_protocol_mappers(self, internal_id: str) -> list[dict[str, Any]]:
        url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models"
        resp = await self._request("GET", url)
        return resp.json() or []

    # ---- audience mapper ------------------------------------------------

    async def _find_audience_mapper(
        self,
        internal_id: str,
        included_client_id: str,
    ) -> Optional[dict[str, Any]]:
        for m in await self.list_protocol_mappers(internal_id):
            if (
                m.get("protocol") == "openid-connect"
                and m.get("protocolMapper") == "oidc-audience-mapper"
                and (m.get("config") or {}).get("included.client.audience") == included_client_id
            ):
                return m
        return None

    async def ensure_audience_mapper(
        self,
        internal_id: str,
        included_client_id: str,
        *,
        id_token_claim: bool = True,
        access_token_claim: bool = True,
        update_if_different: bool = False,
    ) -> dict[str, bool]:
        """
        Ensure audience mapper exists; optionally update its config if different.

        Returns {"created": bool, "updated": bool}.
        """
        desired_cfg = {
            "included.client.audience": included_client_id,
            "id.token.claim": "true" if id_token_claim else "false",
            "access.token.claim": "true" if access_token_claim else "false",
        }

        existing = await self._find_audience_mapper(internal_id, included_client_id)
        if existing:
            if update_if_different:
                current = existing.get("config") or {}
                if any(current.get(k) != v for k, v in desired_cfg.items()):
                    mapper_id = existing.get("id")
                    url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models/{mapper_id}"
                    payload = {
                        "id": mapper_id,
                        "name": existing.get("name") or f"aud-{included_client_id}",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": desired_cfg,
                    }
                    await self._request("PUT", url, json=payload)
                    return {"created": False, "updated": True}
            return {"created": False, "updated": False}

        url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models"
        payload = {
            "name": f"aud-{included_client_id}",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": desired_cfg,
        }
        await self._request("POST", url, json=payload)
        return {"created": True, "updated": False}

    async def remove_audience_mapper(
        self,
        internal_id: str,
        included_client_id: str,
    ) -> bool:
        existing = await self._find_audience_mapper(internal_id, included_client_id)
        if not existing:
            return False
        mapper_id = existing.get("id")
        url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models/{mapper_id}"
        await self._request("DELETE", url)
        return True

    # ---- client roles mapper (FE sees resource_access.<api>.roles) ------

    async def _find_client_roles_mapper(
        self,
        internal_id: str,
        source_client_id: str,
    ) -> Optional[dict[str, Any]]:
        claim = f"resource_access.{source_client_id}.roles"
        for m in await self.list_protocol_mappers(internal_id):
            if (
                m.get("protocol") == "openid-connect"
                and m.get("protocolMapper") == "oidc-usermodel-client-role-mapper"
            ):
                cfg = m.get("config") or {}
                if (
                    cfg.get("usermodel.clientRoleMapping.clientId") == source_client_id
                    and cfg.get("claim.name") == claim
                ):
                    return m
        return None

    async def ensure_client_roles_mapper(
        self,
        internal_id: str,
        source_client_id: str,
        *,
        update_if_different: bool = False,
    ) -> dict[str, bool]:
        """
        Ensure FE client has a roles mapper for roles of source_client_id under
        resource_access.{source_client_id}.roles.

        Returns {"created": bool, "updated": bool}.
        """
        desired_cfg = {
            "usermodel.clientRoleMapping.clientId": source_client_id,
            "claim.name": f"resource_access.{source_client_id}.roles",
            "jsonType.label": "String",
            "multivalued": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        }

        existing = await self._find_client_roles_mapper(internal_id, source_client_id)
        if existing:
            if update_if_different:
                current = existing.get("config") or {}
                if any(current.get(k) != v for k, v in desired_cfg.items()):
                    mapper_id = existing.get("id")
                    url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models/{mapper_id}"
                    payload = {
                        "id": mapper_id,
                        "name": existing.get("name") or f"roles-{source_client_id}",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-usermodel-client-role-mapper",
                        "config": {**current, **desired_cfg},
                    }
                    await self._request("PUT", url, json=payload)
                    return {"created": False, "updated": True}
            return {"created": False, "updated": False}

        url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models"
        payload = {
            "name": f"roles-{source_client_id}",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-usermodel-client-role-mapper",
            "config": desired_cfg,
        }
        await self._request("POST", url, json=payload)
        return {"created": True, "updated": False}

    async def remove_client_roles_mapper(
        self,
        internal_id: str,
        source_client_id: str,
    ) -> bool:
        existing = await self._find_client_roles_mapper(internal_id, source_client_id)
        if not existing:
            return False
        mapper_id = existing.get("id")
        url = f"{self._realm_admin()}/clients/{internal_id}/protocol-mappers/models/{mapper_id}"
        await self._request("DELETE", url)
        return True

    # ------------------------------------------------------------------ #
    # helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _trim_client(obj: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": obj.get("id"),
            "clientId": obj.get("clientId"),
            "publicClient": obj.get("publicClient"),
            "serviceAccountsEnabled": obj.get("serviceAccountsEnabled"),
            "standardFlowEnabled": obj.get("standardFlowEnabled"),
            "redirectUris": obj.get("redirectUris") or [],
            "webOrigins": obj.get("webOrigins") or [],
            "enabled": obj.get("enabled"),
        }
