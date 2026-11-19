# Podman deployment

This deployment is based on the official SearXNG [docker-compose.yaml](https://github.com/searxng/searxng/blob/master/container/docker-compose.yml), adapted to run on Podman for its stricter default isolation (rootless, daemonless, cgroups v2). It brings up five containers: [Caddy](https://caddyserver.com/) for TLS termination, [`fence-gateway`](https://github.com/littleoffice/fence-gateway) verifying every fence signature in transit, `mcp-searxng-relay` (stateful mode by default), [SearXNG](https://github.com/searxng/searxng) as the upstream search engine, and [Valkey](https://valkey.io/) as SearXNG's result cache.

> **Upgrading an existing deployment?** Since v2.3.0 this stack puts fence-gateway in front of `/mcp` and no longer publishes the SearXNG web UI. Your old env files will not start as they are. Read [Upgrading from the v2.2 layout](#upgrading-from-the-v22-layout) first.

The gateway is what turns the fence into an enforced control rather than forward compatibility. The relay signs every tool response; with nothing checking those signatures, the model is asked to respect a boundary it cannot verify. The gateway checks each one deterministically before the bytes leave this host, and drops the response when it fails. The wire contract it implements is [`docs/fence-verification.md`](../../docs/fence-verification.md).

> ⚠️ **Not internet-facing without further hardening.** The shipped configuration is meant for trusted networks (lab, internal tooling, VPN-fronted). For public exposure, treat the bearer tokens, rate limits, and Caddy ACME source as deliberate decisions — start from the [Security notes](../../README.md#security-notes) in the main README and the [deployment checklist](../../docs/security-model.md#deployment-checklist).

All services run with `cap_drop: [ALL]`, `no-new-privileges`, and read-only root filesystems (Valkey keeps the few capabilities it needs to drop privileges itself).

### Who can reach what

A container can only connect to containers it shares a network with, so the network layout is the access-control policy. Each service is reachable only from the one in front of it:

| Network | Members | Purpose |
|---|---|---|
| `edge` | caddy, fence-gateway | what Caddy can reach |
| `relay` (internal) | fence-gateway, mcp-searxng-relay | the only way to the relay |
| `search` (internal) | mcp-searxng-relay, searxng | the relay's line to SearXNG |
| `egress` | mcp-searxng-relay | the relay's own route out, for fetching URLs; shared with nobody |
| `searxng-egress` | searxng | SearXNG's own route out, to the search engines; shared with nobody |
| `backend` (internal) | searxng, valkey | SearXNG's cache |

There is one door in from outside:

| Path | Who | Credential | Goes to |
|---|---|---|---|
| `https://<host>/mcp` | agents | bearer token (or OAuth JWT), checked by the gateway | gateway → relay → SearXNG |

Everything else on the host answers `404`. Caddy has no network in common with the relay or with SearXNG, so no edit to the Caddyfile can route around the gateway, and SearXNG, which has no login of its own, cannot be searched from outside without going through the relay. The gateway is not on `search`, so it cannot query SearXNG directly either.

**Want the SearXNG web UI for people too?** It is a second front door, so it is opt-in and comes with single sign-on: see [`webui/`](./webui/README.md). Searches made there go straight to SearXNG and are not in the relay's audit log.

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

If you only need the MCP endpoint and would rather not run a reverse proxy, the gateway can terminate TLS itself via `MCP_TLS_CERT`/`MCP_TLS_KEY` (see [`envs/.fence-gateway.env`](./envs/.fence-gateway.env)); the relay's own TLS settings are in [TLS](../../docs/operations.md#tls).

## 3. Set the tokens

There are two hops, and each checks its own credential. `MCP_AUTH_TOKEN` means the same thing in both services — *what my callers must present to me* — and all that changes is who "me" is:

| Where | What it is |
|---|---|
| `envs/.fence-gateway.env` → `MCP_AUTH_TOKEN` | what your MCP clients present to the gateway |
| `envs/.fence-gateway.env` → `UPSTREAM_MCP_TOKEN` | the gateway's own credential, for startup and housekeeping only |
| `envs/.mcp-searxng-relay.env` → `MCP_AUTH_TOKEN(S)` | what the relay accepts: every client token, **plus** the gateway's |

The gateway forwards each client's credential to the relay unchanged (`UPSTREAM_MCP_AUTH_MODE=passthrough`), so a client's token is one value that appears in both files. That is deliberate. The relay files per-caller state — the fetch history behind `searxng_session_sources`, and the rate-limit bucket — under the identity a token resolves to. Were the gateway to substitute one credential for everybody, those callers would share a history and a bucket, and one could read the URLs another fetched. Forwarding keeps them apart with no change to the relay at all.

So N clients means N + 1 secrets, not 2N: one token each, plus one for the gateway.

```bash
gw="$(openssl rand -hex 32)"    # the gateway's own credential
tok="$(openssl rand -hex 32)"   # one client's token
sed -i -e "s|^UPSTREAM_MCP_TOKEN=CHANGEME|UPSTREAM_MCP_TOKEN=$gw|" \
       -e "s|^MCP_AUTH_TOKEN=CHANGEME|MCP_AUTH_TOKEN=$tok|" envs/.fence-gateway.env
# the relay accepts both: the client's (forwarded) and the gateway's (startup)
sed -i "s|^MCP_AUTH_TOKEN=CHANGEME|MCP_AUTH_TOKENS=fence-gateway:$gw,claude-desktop:$tok|" envs/.mcp-searxng-relay.env
```

Keep the two values different even with a single client: if they were the same, the client would also hold the gateway's credential.

Pass-through has a price: a client's token is valid at the relay too. What stops a client from using it there is the network — only the gateway shares a network with the relay (see [Who can reach what](#who-can-reach-what)). Don't publish a port for the relay, put it on `edge`, or route Caddy to it while pass-through is on.

For more than one client, use `MCP_AUTH_TOKENS` (`identity:token` pairs) in both files, with the same values and the same labels, so relay and gateway logs name the same caller the same way. See [Configuration](../../docs/configuration.md#environment-variables) for `MCP_AUTH_TOKENS` and `MCP_AUTH_TOKEN_FILE`.

Alternatively, if you already run an identity provider, both services can verify **OAuth 2.0 / OIDC** bearer JWTs. Pass-through forwards a JWT untouched, so pointing both at the same issuer carries identity end to end in the token's `sub` with no shared secrets at all — provided its `aud` satisfies both sides. See [OAuth 2.0 / OIDC](../../docs/configuration.md#oauth-20--oidc).

With OAuth there is a stricter option: `UPSTREAM_MCP_AUTH_MODE=exchange`. The gateway trades each caller's token at your identity provider for a token issued to the relay, so a caller's own token is refused at the relay even if they could reach it. The network then becomes a second layer instead of the only one. Setup: [token exchange](https://github.com/littleoffice/fence-gateway/blob/main/docs/token-exchange.md). The relay can go one step further and search private engines as each user — see [Per-user tokens for SearXNG engines](../../docs/user-tokens.md).

## 4. SearXNG secret

SearXNG needs its own secret. [`settings.yml`](./settings.yml) ships SearXNG's `ultrasecretkey` sentinel, which it refuses to start with, so this step is not optional:

```bash
echo "SEARXNG_SECRET=$(openssl rand -hex 32)" >> envs/.searxng.env
```

## 5. Pin the fence signing key

The relay refuses to start while `FENCE_SIGNING_KEY` still says `CHANGEME`. Give it a persistent key, so the fingerprint the gateway pins survives restarts:

```bash
sed -i "s|^FENCE_SIGNING_KEY=CHANGEME|FENCE_SIGNING_KEY=$(openssl rand -base64 32)|" envs/.mcp-searxng-relay.env
```

The gateway refuses to start without a pin here: it fetches the relay's key over plain HTTP from another container, and anyone on that path could serve their own key. So start the relay on its own first and read the fingerprint from its startup banner:

```bash
podman-compose up -d mcp-searxng-relay
podman-compose logs mcp-searxng-relay | grep -i "fence key"
```

Uncomment `-pin=<fingerprint>` in the `fence-gateway` service's `command:` and put the value there. With the pin, the gateway accepts only fences signed by that key. That covers hostile *fetched content*, which cannot mint signatures (the paper's §6.3.2 defence), and also a substituted relay, which would have to hold the relay's private key.

## 6. Bring it up

```bash
podman-compose up -d        # or, for Podman 4.x+ native compose:
podman compose up -d
```

`podman-compose logs -f fence-gateway` should show, in order:

```
fence.key.loaded fingerprint=… policy=reject
upstream.auth mode=passthrough bootstrap=true downstream_identities=1 stateless=false
upstream.connected endpoint="http://mcp-searxng-relay:3000/mcp"
proxy.tools.synced count=… added=… removed=0
http.plaintext port=3001 hint="serving plain HTTP; …"
http.listen addr=":3001" …
```

The `http.plaintext` line is expected here: Caddy terminates TLS, and the
gateway↔Caddy hop stays inside the `edge` network. It is telling you that the
bearer tokens on that hop depend on Caddy being in front, which in this stack
they do.

Once Caddy has provisioned its certificate, the MCP endpoint is at `https://<your-hostname>/mcp` — the gateway, with the relay behind it. Each verified tool call then logs `fence.verified …` and `fence.ok tool=… identity=… blocks=N`.

## 7. Check the isolation and the fence

**Prove nothing routes around the gateway.** Each of these must fail with a name-resolution error or a timeout, because the containers share no network:

```bash
podman exec caddy wget -qO- -T 5 http://mcp-searxng-relay:3000/health   # Caddy → relay
podman exec caddy wget -qO- -T 5 http://searxng:8080/                    # Caddy → SearXNG
podman run --rm --network container:fence-gateway docker.io/library/busybox \
  wget -qO- -T 5 http://searxng:8080/                                    # gateway → SearXNG
```

The `caddy` image includes busybox `wget`. The gateway image is `FROM scratch` with no shell, so the third check uses a throwaway container sharing the gateway's networks.

And from outside:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<your-hostname>/      # 404, not SearXNG
curl -s -o /dev/null -w '%{http_code}\n' https://<your-hostname>/mcp   # 401 without a token
```

**Prove the fence is actually enforced.** Set `-pin=` in the compose file to a fingerprint that is not the relay's, `podman-compose up -d fence-gateway`, and make any tool call. It should come back as an error carrying no content, with `fence.policy.reject` in the gateway log. Restore the real pin afterwards. A gateway that passes traffic in this state is not verifying anything.

**Compare against the unverified path** from inside the `relay` network, never by routing Caddy to the relay. A throwaway container joined to that network can query the relay directly with the gateway's own token:

```bash
podman run --rm --network podman_relay docker.io/curlimages/curl -s \
  -H "Authorization: Bearer $gw" -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}' \
  http://mcp-searxng-relay:3000/mcp
```

Compose prefixes network names with the project name (the directory name, by default), so the network is `podman_relay` when the stack runs from this directory; `podman network ls` shows the actual name.

**Roll out gradually.** `-policy=annotate` forwards a failing result with a warning and `isError` set; `-policy=audit` only logs. Both are for seeing what would be blocked. Neither stops an attack, so neither is a destination.

**Check caller separation** if you configured more than one client token: fetch something as each client, then call `searxng_session_sources` as each. Every client should see only its own fetches. Both seeing both means the credentials are not reaching the relay distinctly — re-check step 3.

## Upgrading from the v2.2 layout

Up to v2.2.0, this stack routed `/mcp` straight to the relay and published the SearXNG web UI, with no login, on every other path. Since v2.3.0, `/mcp` goes through fence-gateway and the web UI is off. To move a running deployment over:

1. **Pull the new files** but keep your edited `envs/`, `Caddyfile` hostname and `settings.yml` changes; re-apply them on top of the new versions. `envs/.fence-gateway.env` is new.
2. **Tokens** (step 3): your old `MCP_AUTH_TOKEN` can stay as the client token. Put it in `envs/.fence-gateway.env` as `MCP_AUTH_TOKEN`, generate a new `UPSTREAM_MCP_TOKEN`, and list both in the relay's `MCP_AUTH_TOKENS`. Clients keep the same URL and token.
3. **Fence key** (step 5): set `FENCE_SIGNING_KEY` if you have not, start the relay, and pin its fingerprint in the gateway's `command:`.
4. **SearXNG secret** (step 4): `settings.yml` no longer carries a committed `secret_key`; set `SEARXNG_SECRET`.
5. **Web UI**: if people used `https://<host>/`, add the [`webui/`](./webui/README.md) overlay, which puts it behind single sign-on. Without it, that path now answers `404` with a pointer here.
6. `podman-compose down && podman-compose up -d`, then run the checks in step 7.

To stay on the old layout instead, use `deploy/podman` from the [`v2.2.0` tag](https://github.com/littleoffice/mcp-searxng-relay/tree/v2.2.0/deploy/podman). It is not maintained.

## Known limits

- **Nothing rate-limits the gateway.** Pass-through keeps the relay's per-identity buckets working, but the gateway has no limiter of its own, so a caller can still spend the relay's budget as fast as the relay will serve it.
- **The gateway runs single-replica here.** It holds MCP sessions in memory. More than one instance needs `MCP_STATELESS=true` on both it and the relay — the two settings have to agree, or the relay's session state is stranded on whichever replica answered first. See [Deployment shapes](../kubernetes/README.md#deployment-shapes).
- **Metrics go through the gateway.** The relay is not reachable from a scraper, so Prometheus scrapes the gateway: `/mcp/metrics/gateway` for the gateway's own series, and `/mcp/metrics/relay` for the relay's, which the gateway fetches over the `relay` network. Both need the gateway's `MCP_METRICS_TOKEN`; set `UPSTREAM_METRICS_TOKEN` to the relay's `MCP_METRICS_TOKEN` (see [`envs/.fence-gateway.env`](./envs/.fence-gateway.env)). The gateway's `/mcp/health` answers `ok` without a credential and says nothing else.
