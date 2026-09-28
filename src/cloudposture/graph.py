"""A minimal, read-only Microsoft Graph client: app-only (client credentials) auth, paging, and
retries on throttling. Standard library only, so the tool runs in any image with python3."""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

GRAPH = "https://graph.microsoft.com"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 60
RETRIES = 5


class GraphError(Exception):
    """A Graph call that failed. `status` 403 means the app lacks a permission (or licence) for it."""

    def __init__(self, status: int, code: str, message: str, path: str):
        super().__init__(f"{status} {code}: {message} ({path})")
        self.status = status
        self.code = code
        self.message = message
        self.path = path

    @property
    def forbidden(self) -> bool:
        return self.status in (401, 403)


def acquire_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """An app-only Graph token for the tenant (client credentials grant)."""
    body = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": f"{GRAPH}/.default",
        }
    ).encode()
    req = urllib.request.Request(
        f"{LOGIN}/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
            return json.load(res)["access_token"]
    except urllib.error.HTTPError as e:
        detail = _error_body(e)
        raise GraphError(e.code, detail.get("error", "auth_failed"), detail.get("error_description", str(e)), "token") from None


def _error_body(e: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        return json.loads(e.read().decode() or "{}")
    except (ValueError, UnicodeDecodeError):
        return {}


class Graph:
    """Read-only Graph access. Every call is a GET except `post_read` (for read-only POST actions such
    as directoryObjects/getByIds)."""

    def __init__(self, token: str):
        self._token = token
        self.calls = 0

    def _request(self, url: str, data: bytes | None = None) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",
        }
        if data is not None:
            headers["Content-Type"] = "application/json"
        path = url.replace(GRAPH, "")
        for attempt in range(RETRIES):
            req = urllib.request.Request(url, data=data, headers=headers)
            try:
                self.calls += 1
                with urllib.request.urlopen(req, timeout=TIMEOUT) as res:
                    raw = res.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < RETRIES - 1:
                    wait = float(e.headers.get("Retry-After") or 2 ** attempt)
                    time.sleep(min(wait, 30))
                    continue
                err = _error_body(e).get("error", {})
                raise GraphError(e.code, err.get("code", "error"), err.get("message", str(e)), path) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException) as e:
                # A slow Graph endpoint (sign-in activity) can time out mid-read; that is transient too.
                if attempt < RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                reason = getattr(e, "reason", None) or str(e) or type(e).__name__
                raise GraphError(0, "network", str(reason), path) from None
        raise GraphError(0, "retries", "retries exhausted", path)

    @staticmethod
    def _url(path: str, beta: bool) -> str:
        if path.startswith("https://"):
            return path
        # OData queries carry spaces and quotes ($filter=assignmentType eq 'Assigned'); encode them.
        safe = urllib.parse.quote(path.lstrip("/"), safe="/?&=$,:'()@!*+;")
        return f"{GRAPH}/{'beta' if beta else 'v1.0'}/{safe}"

    def get(self, path: str, beta: bool = False) -> dict[str, Any]:
        return self._request(self._url(path, beta))

    def list(self, path: str, beta: bool = False) -> Iterator[dict[str, Any]]:
        """Every item of a collection, following @odata.nextLink."""
        url: str | None = self._url(path, beta)
        while url:
            page = self._request(url)
            yield from page.get("value", [])
            url = page.get("@odata.nextLink")

    def post_read(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request(self._url(path, False), json.dumps(body).encode())
