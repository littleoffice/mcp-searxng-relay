# SearXNG web UI (opt-in)

The base stack in [`deploy/podman`](../README.md) publishes only `/mcp`. SearXNG has no login of its own, so it is not reachable from outside at all. This overlay publishes its web UI for people too, behind single sign-on with [oauth2-proxy](https://oauth2-proxy.github.io/oauth2-proxy/).

It is a second front door, so turn it on deliberately:

- **Searches made here are not audited by the relay.** They go from signed-in browsers straight to SearXNG, so they are not in the relay's audit log or source ledger. oauth2-proxy logs who signed in; SearXNG does not log per-user queries.
- **It needs an identity provider.** No IdP, no web UI: use the relay through an MCP client instead.

What it adds:

| | |
|---|---|
| `oauth2-proxy` | a sixth container, on `edge`; Caddy asks it about every browser request (`forward_auth`) |
| `web` (internal network) | caddy and searxng only, so Caddy can serve the UI; still no route to the relay |
| [`webui.caddy`](./webui.caddy) | the `/oauth2/*` and web UI routes, imported into the base [`Caddyfile`](../Caddyfile) |

Agents never pass through oauth2-proxy: `/mcp` stays bearer-only at the gateway.

## 1. Register a client

At your identity provider, register a confidential OIDC client with redirect URI `https://<your-hostname>/oauth2/callback`.

## 2. Fill in the settings

Fill in the `CHANGEME` values in [`.oauth2-proxy.env`](./.oauth2-proxy.env): issuer URL, client ID and secret, and a cookie secret (`openssl rand -base64 32 | tr -- '+/' '-_'`). Replace `domain.tld` in the redirect URL. Narrow who may sign in with `OAUTH2_PROXY_EMAIL_DOMAINS` or `OAUTH2_PROXY_ALLOWED_GROUPS`; the shipped `*` admits every account your provider authenticates.

## 3. Pin the image

```bash
podman pull quay.io/oauth2-proxy/oauth2-proxy:v7
podman image inspect --format '{{index .RepoDigests 0}}' quay.io/oauth2-proxy/oauth2-proxy:v7
```

Put the digest in the `image:` line of [`docker-compose.webui.yaml`](./docker-compose.webui.yaml) in place of `sha256:CHANGEME`.

## 4. Bring it up

From `deploy/podman/`, with both files every time (a plain `podman-compose up -d` drops the overlay again):

```bash
podman-compose -f docker-compose.yaml -f webui/docker-compose.webui.yaml up -d
```

## 5. Check it

```bash
curl -sI https://<your-hostname>/ | head -1                              # 302 to /oauth2/sign_in, not SearXNG
curl -s -o /dev/null -w '%{http_code}\n' https://<your-hostname>/mcp     # still 401 without a token
podman exec caddy wget -qO- -T 5 http://mcp-searxng-relay:3000/health    # must still fail
```

To turn the web UI off again, run `podman-compose -f docker-compose.yaml up -d --remove-orphans` (or `podman rm -f oauth2-proxy` afterwards). Caddy's `import` then matches nothing, SearXNG leaves the `web` network, and `/` answers `404`.
