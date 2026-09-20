# Podman deployment

This deployment is based on the official SearXNG [docker-compose.yaml](https://github.com/searxng/searxng/blob/master/container/docker-compose.yml), adapted to run on Podman for its stricter default isolation (rootless, daemonless, cgroups v2). It brings up five containers: [Caddy](https://caddyserver.com/) for TLS termination, [`fence-gateway`](https://github.com/littleoffice/fence-gateway) verifying every fence signature in transit, `mcp-searxng-relay` (stateful mode by default), [SearXNG](https://github.com/searxng/searxng) as the upstream search engine, and [Valkey](https://valkey.io/) as SearXNG's result cache.

The gateway is what turns the fence into an enforced control rather than forward compatibility. The relay signs every tool response; with nothing checking those signatures, the model is asked to respect a boundary it cannot verify. The gateway checks each one deterministically before the bytes leave this host, and drops the response when it fails. The wire contract it implements is [`docs/fence-verification.md`](../../docs/fence-verification.md).

> ⚠️ **Not internet-facing without further hardening.** The shipped configuration is meant for trusted networks (lab, internal tooling, VPN-fronted). For public exposure, treat the bearer tokens, rate limits, and Caddy ACME source as deliberate decisions — start from the [Security notes](../../README.md#security-notes) in the main README.

Caddy, the gateway, the relay, and SearXNG sit on the `edge` network; Valkey sits on a separate `backend` network declared `internal: true`, so it has no route to the host or the public internet — only SearXNG can reach it. All five services run with `cap_drop: [ALL]`, `no-new-privileges`, and read-only root filesystems. At the edge, `/mcp` is the gateway: the relay is reachable only from inside the `edge` network, so a client cannot route around the verification.

## 1. Replace the placeholder hostname

Replace `domain.tld` with the hostname you'll serve under, in both:

- [`envs/.searxng.env`](./envs/.searxng.env) — the `SEARXNG_HOSTNAME` value
- [`Caddyfile`](./Caddyfile) — the site address on the first line and the email in `tls admin@…`

If you need SearXNG itself to do more (extra engines, branding, locales), the upstream reference is [docs.searxng.org](https://docs.searxng.org/admin/settings/settings.html) and the file to edit is [`settings.yml`](./settings.yml).

## 2. Build the gateway image

`fence-gateway` has no published release yet, so build it from source:

```bash
git clone https://github.com/littleoffice/fence-gateway
cd fence-gateway
podman build -t localhost/fence-gateway:dev .
```

That is the image [`docker-compose.yaml`](./docker-compose.yaml) refers to. `./build.sh <version>` in that repository does the reproducible build instead; once a release exists, swap the `image:` line for a `ghcr.io/littleoffice/fence-gateway@sha256:…` digest pin, like every other image in this stack.

## 3. Pick a TLS certificate source

The shipped [`Caddyfile`](./Caddyfile) points at an internal ACME directory, which assumes you run something like [Smallstep `step-ca`](https://smallstep.com/docs/step-ca/) on your network. Three alternatives if you don't:

- **Let's Encrypt** — replace the inner `tls` block with `tls admin@your-email.tld`.
- **Self-signed, local-only** — replace it with `tls internal`. The client will need the Caddy root in its trust store.
- **Bring your own cert** — `tls /path/to/cert.pem /path/to/key.pem`, plus a bind-mount in [`docker-compose.yaml`](./docker-compose.yaml).

Caddy also fronts SearXNG here, so this stack keeps it. If you only need the MCP endpoint and would rather not run a reverse proxy, the gateway can terminate TLS itself via `MCP_TLS_CERT`/`MCP_TLS_KEY` — see [Transports](https://github.com/littleoffice/fence-gateway#transports).

## 4. Set the tokens

There are now two doors, and each checks its own credential. `MCP_AUTH_TOKEN` means the same thing in both services — *what my callers must present to me* — and all that changes is who "me" is:

| Where | What it is |
|---|---|
| `envs/.fence-gateway.env` → `MCP_AUTH_TOKEN` | what your MCP clients present to the gateway |
| `envs/.fence-gateway.env` → `UPSTREAM_MCP_TOKEN` | the gateway's own credential, for startup and housekeeping only |
| `envs/.mcp-searxng-relay.env` → `MCP_AUTH_TOKEN(S)` | what the relay accepts: every client token, **plus** the gateway's |

The gateway forwards each client's credential to the relay unchanged (`UPSTREAM_MCP_AUTH_MODE=passthrough`), so a client's token is one value that appears in both files. That is deliberate. The relay files per-caller state — the fetch history behind `searxng_session_sources`, and the rate-limit bucket — under the identity a token resolves to. Were the gateway to substitute one credential for everybody, those callers would share a history and a bucket, and one could read the URLs another fetched. Forwarding keeps them apart with no change to the relay at all.

So N clients means N + 1 secrets, not 2N: one token each, plus one for the gateway.

```bash
# the gateway's own credential
echo "UPSTREAM_MCP_TOKEN=$(openssl rand -hex 32)" >> envs/.fence-gateway.env
# one client token, in both tables
tok="$(openssl rand -hex 32)"
echo "MCP_AUTH_TOKEN=$tok" >> envs/.fence-gateway.env
echo "MCP_AUTH_TOKEN=$tok" >> envs/.mcp-searxng-relay.env
```

(Each file ships with a `CHANGEME` placeholder on those lines; delete it once the real value is appended.)

For more than one client, use `MCP_AUTH_TOKENS` (`identity:token` pairs) in both files, with the same values and the same labels, so relay and gateway logs name the same caller the same way. See [Configuration](../../README.md#configuration) for `MCP_AUTH_TOKENS` and `MCP_AUTH_TOKEN_FILE`.

Alternatively, if you already run an identity provider, both services can verify **OAuth 2.0 / OIDC** bearer JWTs. Pass-through forwards a JWT untouched, so pointing both at the same issuer carries identity end to end in the token's `sub` with no shared secrets at all — provided its `aud` satisfies both sides. See [OAuth 2.0 / OIDC](../../README.md#oauth-20--oidc).

## 5. Pin the fence signing key

By default the relay generates a fresh signing key on every start, so the fingerprint a verifier pins changes at every restart. Give it a persistent one:

```bash
echo "FENCE_SIGNING_KEY=$(openssl rand -base64 32)" >> envs/.mcp-searxng-relay.env
```

Bring the stack up (step 6), then read the fingerprint from the relay's startup banner:

```bash
podman-compose logs mcp-searxng-relay | grep -i "fence key"
```

Uncomment `-pin=<fingerprint>` in the `fence-gateway` service's `command:` and restart it. Until you do, verification proves the fence was signed by whoever answered `/fence/public-key`. That is the paper's §6.3.2 defence and it does hold against hostile *fetched content* — a malicious page cannot mint signatures — but it proves nothing against a substituted relay. The pin is what closes that.

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
proxy.tools.registered count=…
http.plaintext port=3001 hint="serving plain HTTP; …"
http.listen addr=":3001" …
```

The `http.plaintext` line is expected here: Caddy terminates TLS, and the
gateway↔Caddy hop stays inside the `edge` network. It is telling you that the
bearer tokens on that hop depend on Caddy being in front, which in this stack
they do.

Once Caddy has provisioned its certificate, the MCP endpoint is at `https://<your-hostname>/mcp` — the gateway, with the relay behind it. Each verified tool call then logs `fence.verified …` and `fence.ok tool=… identity=… blocks=N`.

## 7. Testing the fence

**Prove it is actually enforcing.** Set `-pin=` in the compose file to a fingerprint that is not the relay's, `podman-compose up -d fence-gateway`, and make any tool call. It should come back as an error carrying no content, with `fence.policy.reject` in the gateway log. Restore the real pin afterwards. A gateway that passes traffic in this state is not verifying anything.

**Compare against the unverified path.** Uncomment the `/raw-mcp*` block in the [`Caddyfile`](./Caddyfile) and reload Caddy to expose the relay directly, so the same query can be run with and without the check. Comment it out again when you're done — it is a route around the control.

**Roll out gradually.** `-policy=annotate` forwards a failing result with a warning and `isError` set; `-policy=audit` only logs. Both are for seeing what would be blocked. Neither stops an attack, so neither is a destination.

**Check caller separation** if you configured more than one client token: fetch something as each client, then call `searxng_session_sources` as each. Every client should see only its own fetches. Both seeing both means the credentials are not reaching the relay distinctly — re-check step 4.

## Known limits

- **Nothing rate-limits the gateway.** Pass-through keeps the relay's per-identity buckets working, but the gateway has no limiter of its own, so a caller can still spend the relay's budget as fast as the relay will serve it.
- **The gateway runs single-replica here.** It holds MCP sessions in memory. More than one instance needs `MCP_STATELESS=true` on both it and the relay — the two settings have to agree, or the relay's session state is stranded on whichever replica answered first. See [Deployment shapes](../kubernetes/README.md#deployment-shapes).
- **`/metrics` and `/health` are unchanged**, still served by the relay and scraped from it directly; the gateway exposes neither.
