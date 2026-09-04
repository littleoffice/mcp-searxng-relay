# Podman deployment

This deployment is based on the official SearXNG [docker-compose.yaml](https://github.com/searxng/searxng/blob/master/container/docker-compose.yml), adapted to run on Podman for its stricter default isolation (rootless, daemonless, cgroups v2). It brings up four containers: [Caddy](https://caddyserver.com/) for TLS termination, `mcp-searxng-relay` (stateful mode by default), [SearXNG](https://github.com/searxng/searxng) as the upstream search engine, and [Valkey](https://valkey.io/) as SearXNG's result cache.

> ⚠️ **Not internet-facing without further hardening.** The shipped configuration is meant for trusted networks (lab, internal tooling, VPN-fronted). For public exposure, treat the bearer token, rate limits, and Caddy ACME source as deliberate decisions — start from the [Security notes](../../README.md#security-notes) in the main README.

Caddy, the relay, and SearXNG sit on the `edge` network; Valkey sits on a separate `backend` network declared `internal: true`, so it has no route to the host or the public internet — only SearXNG can reach it. All four services run with `cap_drop: [ALL]`, `no-new-privileges`, and read-only root filesystems.

## 1. Replace the placeholder hostname

Replace `domain.tld` with the hostname you'll serve under, in both:

- [`envs/.searxng.env`](./envs/.searxng.env) — the `SEARXNG_HOSTNAME` value
- [`Caddyfile`](./Caddyfile) — the site address on the first line and the email in `tls admin@…`

If you need SearXNG itself to do more (extra engines, branding, locales), the upstream reference is [docs.searxng.org](https://docs.searxng.org/admin/settings/settings.html) and the file to edit is [`settings.yml`](./settings.yml).

## 2. Pick a TLS certificate source

The shipped [`Caddyfile`](./Caddyfile) points at an internal ACME directory, which assumes you run something like [Smallstep `step-ca`](https://smallstep.com/docs/step-ca/) on your network. Three alternatives if you don't:

- **Let's Encrypt** — replace the inner `tls` block with `tls admin@your-email.tld`.
- **Self-signed, local-only** — replace it with `tls internal`. The client will need the Caddy root in its trust store.
- **Bring your own cert** — `tls /path/to/cert.pem /path/to/key.pem`, plus a bind-mount in [`docker-compose.yaml`](./docker-compose.yaml).

## 3. Set the relay auth token

The shipped [`envs/.mcp-searxng-relay.env`](./envs/.mcp-searxng-relay.env) is intentionally minimalistic; the relay refuses to start in HTTP mode without an `MCP_AUTH_TOKEN` of at least 32 characters. Generate one:

```bash
echo "MCP_AUTH_TOKEN=$(openssl rand -hex 32)" >> envs/.mcp-searxng-relay.env
```

For multi-tenant deployments (one token per agent / per user), see [Configuration](../../README.md#configuration) for `MCP_AUTH_TOKENS` and `MCP_AUTH_TOKEN_FILE`.

Alternatively, if you already run an identity provider, the relay can verify **OAuth 2.0 / OIDC** bearer JWTs instead of (or alongside) static tokens — set `MCP_OAUTH_ISSUER` and `MCP_OAUTH_AUDIENCE` and the HTTP-mode auth requirement is satisfied without any `MCP_AUTH_TOKEN`. See [OAuth 2.0 / OIDC](../../README.md#oauth-20--oidc).

## 4. Bring it up

```bash
podman-compose up -d        # or, for Podman 4.x+ native compose:
podman compose up -d
```

Once `mcp-searxng-relay` reports `server listening` in `podman-compose logs -f mcp-searxng-relay` and Caddy has provisioned its certificate, the MCP endpoint is reachable at `https://<your-hostname>/mcp`.
