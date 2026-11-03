# SPDX-License-Identifier: Apache-2.0
"""SearXNG engine that searches a backend as the user who asked.

mcp-searxng-relay, with ``SEARXNG_USER_TOKEN_MODE=exchange``, sends every search
to SearXNG with an ``X-Relay-User-Token`` header: an OAuth access token issued
by your identity provider *for this backend*, for the user behind the MCP call
(RFC 8693 token exchange). This engine reads that header and presents the token
to the backend as ``Authorization: Bearer <token>``. The backend verifies it and
returns only what that user may see.

See docs/user-tokens.md in mcp-searxng-relay for the whole flow.

Install
=======

Copy this file into SearXNG's engine directory (``searx/engines/``; in the
official image ``/usr/local/searxng/searx/engines/``), then add to
``settings.yml``:

.. code:: yaml

  engines:
    - name: private
      engine: relay_user_token
      shortcut: priv
      base_url: https://backend.internal/api/search
      categories: [general]
      disabled: true                      # only runs when asked for by name or !priv
      tokens: ['<SEARXNG_TOKENS value>']  # optional second gate, see the relay docs

Security notes
==============

- No token, no request. Without a usable header the engine sends nothing, so
  the backend is never asked without a user. There is deliberately no
  ``api_key`` fallback: a shared credential here would hand every caller,
  including people using the SearXNG web UI directly, the service account's
  access.
- The token is only ever sent to ``base_url``: redirects are not followed, and
  ``base_url`` must be https (plain http only to loopback, for testing).
- A 401/403 from the backend means "this user may not see this", not "the
  engine is broken". The engine therefore handles HTTP errors itself, so one
  user's expired token does not make SearXNG suspend the engine for everyone.
- The token is never logged, never put in results and never stored in module
  state: engines are shared by every concurrent search.
- Reading the header relies on SearXNG running engine requests inside a copy of
  the Flask request context (``copy_current_request_context`` in
  ``searx/search/__init__.py``, present since 2023-08). If a future SearXNG
  drops that, the engine logs an error and returns nothing; it fails closed.
"""

import ipaddress
import typing as t
from urllib.parse import urlencode, urlparse

import flask

from searx.result_types import EngineResults

if t.TYPE_CHECKING:
    from searx.extended_types import SXNG_Response
    from searx.search.processors import OnlineParams


engine_type = "online"
categories = ["general"]
paging = True
timeout = 5.0
send_accept_language_header = False

about = {
    "website": None,
    "wikidata_id": None,
    "official_api_documentation": None,
    "use_official_api": True,
    "require_api_key": True,
    "results": "JSON",
}

# Set per engine in settings.yml.
base_url = ""

USER_TOKEN_HEADER = "X-Relay-User-Token"
MAX_TOKEN_BYTES = 8 * 1024


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def init(engine_settings: dict[str, t.Any]) -> bool:
    """Refuse to start with a base_url the token must not be sent to."""
    url = urlparse(engine_settings.get("base_url") or base_url)
    if not url.hostname:
        logger.error("base_url is not set; this engine stays disabled")  # type: ignore[name-defined]  # noqa: F821
        return False
    if url.scheme != "https" and not (url.scheme == "http" and _is_loopback(url.hostname)):
        logger.error(  # type: ignore[name-defined]  # noqa: F821
            "base_url must be https (plain http only to loopback): it receives users' tokens"
        )
        return False
    return True


def _user_token() -> str:
    """The exchanged token the relay sent with this search, or ""."""
    try:
        token = flask.request.headers.get(USER_TOKEN_HEADER, "")
    except RuntimeError:
        # "Working outside of request context": SearXNG no longer runs engines
        # inside a copy of the request context. Fail closed, loudly.
        logger.error(  # type: ignore[name-defined]  # noqa: F821
            "no Flask request context in the engine thread; cannot read %s", USER_TOKEN_HEADER
        )
        return ""
    if not token or len(token) > MAX_TOKEN_BYTES:
        return ""
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in token):
        return ""
    return token


def request(query: str, params: "OnlineParams") -> None:
    token = _user_token()
    if not token:
        # No user, no request: SearXNG skips an engine whose url is empty.
        params["url"] = None  # type: ignore[typeddict-item]
        return

    params["url"] = f"{base_url}?{urlencode({'q': query, 'page': params['pageno']})}"
    params["headers"]["Authorization"] = f"Bearer {token}"
    params["headers"]["Accept"] = "application/json"
    params["allow_redirects"] = False
    # Handle 4xx ourselves (see response): a per-user 401/403 must not
    # suspend the engine for every user.
    params["raise_for_httperror"] = False


def response(resp: "SXNG_Response") -> EngineResults:
    """Parse ``{"results": [{"url", "title", "content"}, ...]}``.

    Adapt this to your backend's response format.
    """
    res = EngineResults()
    if resp.status_code in (401, 403):
        # Token expired, revoked or not allowed: this user gets nothing.
        logger.debug("backend refused the user token: HTTP %s", resp.status_code)  # type: ignore[name-defined]  # noqa: F821
        return res
    if resp.status_code != 200:
        # Anything else is a backend problem; raise so SearXNG reports it.
        resp.raise_for_status()

    for item in resp.json().get("results", []):
        url = item.get("url")
        if not url:
            continue
        res.add(
            res.types.MainResult(  # type: ignore[attr-defined]
                url=url,
                title=item.get("title", ""),
                content=item.get("content", ""),
            )
        )
    return res
