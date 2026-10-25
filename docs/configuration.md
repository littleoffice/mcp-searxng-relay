# Configuration

Every environment variable the relay reads, and the settings that need more than a table row: tokens, OAuth, session modes, rate limiting and engines.

## Contents

- [Environment variables](#environment-variables)
- [Token file format](#token-file-format)
- [OAuth 2.0 / OIDC](#oauth-20--oidc)
- [Session modes](#session-modes)
  - [Tuning the session janitor](#tuning-the-session-janitor)
- [Rate limiting](#rate-limiting)
- [Session limits](#session-limits)
- [Scoping a relay to specific engines](#scoping-a-relay-to-specific-engines)
- [Advertising engines to the model](#advertising-engines-to-the-model)

## Environment variables

All configuration is via environment variables. The server will refuse to start if `SEARXNG_URL` is not set. When `MCP_PORT` is set, some authentication layer is required — either at least one of `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKEN_FILE` (static bearer tokens) or OAuth verification via `MCP_OAUTH_ISSUER` (see [OAuth 2.0 / OIDC](#oauth-20--oidc)). The two can run side by side.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SEARXNG_URL` | **yes** | — | Base URL of your SearXNG instance (trailing slash stripped automatically) |
| `MCP_PORT` | no | — | Port to listen on in HTTP mode. If unset, the server uses stdio |
| `MCP_AUTH_TOKEN` | HTTP mode¹ | — | Single bearer token; identity is logged as `"default"`. Backwards-compatible with single-tenant deployments |
| `MCP_AUTH_TOKENS` | HTTP mode¹ | — | Comma-separated `identity:token` pairs for small static fleets, e.g. `alice:abc...,bob:def...` |
| `MCP_AUTH_TOKEN_FILE` | HTTP mode¹ | — | Path to a file with one `identity:token` per line; `#` comments and blank lines ignored |
| `MCP_OAUTH_ISSUER` | HTTP mode¹ | — | OIDC issuer URL. Setting it turns on OAuth 2.0 bearer-JWT verification alongside the static token table. By default the issuer's `/.well-known/openid-configuration` and JWKS are discovered at startup and rotated automatically. See [OAuth 2.0 / OIDC](#oauth-20--oidc) |
| `MCP_OAUTH_AUDIENCE` | with issuer | — | Required when `MCP_OAUTH_ISSUER` is set. The resource identifier every token must carry in its `aud` claim (this relay), e.g. `https://relay.example.com`. Tokens minted for another service are rejected |
| `MCP_OAUTH_JWKS_FILE` | no | — | Path to a static JWKS document, used instead of network discovery (air-gapped or key-synced deployments). Hot-reloaded on mtime change, like a rotated cert-manager Secret. `MCP_OAUTH_ISSUER` is still required (for `iss` validation) |
| `MCP_OAUTH_IDENTITY_CLAIM` | no | `sub` | Token claim used as the audit identity in logs (`identity=<value>`). Common alternatives: `email`, `client_id`, `azp` |
| `MCP_OAUTH_REQUIRED_SCOPE` | no | — | If set, every token must grant this scope (checked against the space-delimited `scope` string and the `scp` array). Tokens without it are rejected |
| `MCP_OAUTH_CA_ROOTS` | no | — | PEM CA roots for reaching a private issuer whose own TLS certificate is not in the system trust store (e.g. an internal Keycloak). Scoped to OAuth discovery/JWKS fetching only — does not affect the fetch tool or the SearXNG client |
| `MCP_TRUST_FORWARDED_HEADERS` | no | `false` | Believe `X-Forwarded-Proto` / `X-Forwarded-Host` when building the RFC 9728 `resource_metadata` URL advertised in a `401` challenge. Off by default: nothing about an inbound request distinguishes a header a reverse proxy set from one the caller typed, and that value names where an OAuth client goes to discover which authorization server to trust. Turn it on only when a proxy you control terminates every request; without it the URL is derived from the connection the client actually made |
| `MCP_HEALTH_TOKEN` | no | — | Optional bearer token that gates `GET /health`. A **separate** secret from the MCP tokens above — do not reuse a value. Unset (the default) leaves `/health` open. Same 32-character minimum. If you set it, **every** prober must send it (see [Health endpoint](operations.md#health-endpoint)) |
| `MCP_METRICS_TOKEN` | to scrape | — | Bearer token that gates `GET /metrics`. A **separate** secret from the MCP tokens above — do not reuse a value. Unset, `/metrics` returns `401` to everyone, including callers holding a valid MCP token. Same 32-character minimum. Required if you scrape metrics (see [Metrics](observability.md#metrics)) |
| `MCP_TLS_CERT` | no | — | Path to a PEM certificate. With `MCP_TLS_KEY`, the relay serves HTTPS directly instead of plain HTTP. The pair is hot-reloaded on file change, so a renewal is picked up without a restart. Mutually exclusive with the `MCP_TLS_ACME_*` variables. See [TLS](operations.md#tls) |
| `MCP_TLS_KEY` | no | — | Path to the PEM private key for `MCP_TLS_CERT`. Both are required together; one alone fails startup. This listener negotiates **TLS 1.3 or better**; the ACME listener below keeps a 1.2 floor because it also answers the CA's challenge handshakes |
| `MCP_TLS_ACME_DOMAINS` | for ACME | — | Comma-separated hostnames the certificate may cover (the ACME host allow-list). **Setting this (or any `MCP_TLS_ACME_*` variable) turns ACME on** — there is no separate on/off flag — and this one is then required. Certificates are obtained automatically, with challenges served over TLS-ALPN-01 on the same port (no second port needed). Mutually exclusive with `MCP_TLS_CERT`. See [TLS](operations.md#tls) |
| `MCP_TLS_ACME_EMAIL` | no | — | ACME account contact address. Optional; if set it must be a valid bare address (e.g. `admin@example.com`), or startup fails — a public CA rejects a malformed contact at registration. Leave unset to register without a contact |
| `MCP_TLS_ACME_DIRECTORY` | no | Let's Encrypt | ACME directory URL. Point it at a private CA (e.g. step-ca) to use one instead of Let's Encrypt |
| `MCP_TLS_ACME_CACHE_DIR` | no | `/var/cache/mcp-acme` | Directory where issued certificates are cached so they survive restarts. Defaults to the path shown; **mount a volume, bind mount or PVC there** to make it persistent (without persistence, restarts re-request and can hit CA rate limits). Startup fails if the path is not writable |
| `MCP_TLS_ACME_CA_ROOTS` | no | — | Optional PEM bundle the ACME client should trust for a private ACME directory. By default the private CA is trusted through the **process trust store** (mount its root there, or set `SSL_CERT_FILE`); this override instead **confines** that trust to the ACME client, keeping it out of the fetch tool and SearXNG paths |
| `MCP_TLS_HEALTHCHECK_INSECURE` | no | `false` | When the `--healthcheck` probe speaks HTTPS, skip certificate verification. Defaults to `false` (verify). Mainly for **manual**-cert TLS whose certificate is not valid for the loopback probe address; in ACME mode the probe presents the first domain as SNI and verifies normally, so this is not needed. Affects the self-probe only, not the served endpoint. See [TLS](operations.md#tls) |
| `MCP_STATELESS` | no | `false` | If `true`, the SDK issues no session IDs and treats each request as a fresh temporary session; the relay reads `Mcp-Session-Id` itself for correlation. See "Session modes" below |
| `MCP_SESSION_MAX_AGE` | no | `168h` | Stateful mode only. How long a session may live before the janitor closes it. Go duration syntax (`30m`, `12h`, `168h` — no `d` or `w`) |
| `MCP_SESSION_JANITOR_INTERVAL` | no | `15m` | Stateful mode only. How often the janitor sweeps for expired sessions. Same duration syntax |
| `MCP_RATE_LIMIT_RPS` | no | `5` | Per-caller sustained request rate (requests/second). Set to `0` to disable. Fractional values supported (e.g. `0.5` = one request every two seconds) |
| `MCP_RATE_LIMIT_BURST` | no | `2 × RPS, min 1` | Token-bucket burst capacity — the number of requests a caller can fire back-to-back before the sustained rate kicks in |
| `MCP_RATE_LIMIT_EXEMPT` | no | — | Comma-separated identity names that bypass the rate limiter entirely (e.g. `ci,uptime-monitor`). Useful for trusted internal callers and monitoring identities |
| `AUTH_USERNAME` | no | — | HTTP Basic Auth username for SearXNG (if your instance requires it) |
| `AUTH_PASSWORD` | no | — | HTTP Basic Auth password for SearXNG |
| `SEARXNG_TOKENS` | no | — | Comma-separated [private-engine tokens](https://docs.searxng.org/admin/settings/settings_engines.html#private-engines-tokens) sent as the `tokens` search parameter on every query. Engines carrying a `tokens:` list in SearXNG's `settings.yml` are invisible and unusable without one. Scopes this relay to a subset of the engines on a shared SearXNG instance. See [Scoping a relay to specific engines](#scoping-a-relay-to-specific-engines) |
| `SEARXNG_ENGINES` | no | — | Semicolon-separated `name: purpose` entries describing the engines this relay should advertise to the model in the `searxng_web_search` tool description, e.g. `gitea: our self-hosted forge (repos, issues, code); wikipedia: encyclopedia`. The name is a SearXNG engine identifier (lowercased); the purpose is free text (the first `:` separates them, so a purpose may contain colons). A name-only entry is allowed. See [Advertising engines to the model](#advertising-engines-to-the-model) |
| `SEARXNG_ENGINES_FILE` | no | — | Path to a file with one `name: purpose` entry per line; `#` comments and blank lines ignored. Merges with `SEARXNG_ENGINES` (file entries override inline ones by name, in place). A named-but-unreadable path fails startup, matching `MCP_AUTH_TOKEN_FILE` |
| `SEARXNG_ENGINES_DISCOVER` | no | `false` | Opt in to auto-discovering the instance's enabled engines from SearXNG's `/config` at startup, instead of (or alongside) listing them by hand. Discovered engines are the *lowest*-priority layer — `SEARXNG_ENGINES` / `SEARXNG_ENGINES_FILE` still add engines and override a discovered engine's purpose. **Soft-fail:** a blocked or unreachable `/config` (common on hardened instances) logs a warning and leaves the manual roster intact rather than failing startup. Read the privacy note under [Advertising engines to the model](#advertising-engines-to-the-model) before enabling. See also `SEARXNG_ENGINES_DISCOVER_CATEGORIES` and `SEARXNG_ENGINES_EXCLUDE` |
| `SEARXNG_ENGINES_DISCOVER_CATEGORIES` | no | — | Comma-separated SearXNG category allowlist for discovery (e.g. `general,it,science`). When set, only engines in at least one of these categories are advertised — the recommended way to keep the always-on tool description small, since a stock SearXNG enables 100+ engines. Unset advertises all enabled engines, capped at 40 (a warning is logged if the cap truncates). No effect unless `SEARXNG_ENGINES_DISCOVER=true` |
| `SEARXNG_ENGINES_EXCLUDE` | no | — | Comma-separated engine names that discovery must **never** advertise, e.g. a private/token-gated backend you do not want named in the tool description. `/config` lists engines regardless of tokens, so this — not the token set — is what keeps a private engine's existence out of the roster. Applies to discovered engines only; an engine you list manually in `SEARXNG_ENGINES` is treated as intentional. No effect unless `SEARXNG_ENGINES_DISCOVER=true` |
| `USER_AGENT` | no | `mcp-searxng-relay/<version>` | User-Agent header sent with all outbound requests |
| `CACHE_TTL_SECONDS` | no | `300` | How long fetched URL content is cached (seconds) |
| `CACHE_MAX_ENTRIES` | no | `1000` | Maximum number of URLs held in the in-memory cache. Oldest entries are evicted automatically when the cap is reached |
| `MAX_BODY_BYTES` | no | `500000` | Maximum response body size read from fetched URLs (bytes) |
| `MAX_PDF_BYTES` | no | `50000000` | Maximum response body size for PDF URLs (bytes). PDFs get a separate, larger limit since a multi-hundred-page document can easily be 50 MB |
| `MAX_OFFICE_BYTES` | no | `50000000` | Maximum response body size for Office document URLs (DOCX, XLSX, PPTX + legacy DOC, XLS, PPT) (bytes). Modern OOXML files are ZIP archives that routinely embed images, fonts, and chart data, so they get their own cap separate from `MAX_BODY_BYTES` |
| `MAX_IMAGE_BYTES` | no | `7500000` | Maximum raw size for image responses (bytes). The wire form is ~33% larger after base64 encoding |
| `MCP_HISTORY_ENTRIES` | no | `50` | How many distinct sources `searxng_session_sources` retains per caller. Slots hold sources, not fetches, so this counts things an agent might cite. The constraint on raising it is context, not memory — the list is read into the model's context on every call, at roughly 40–80 tokens per entry. Watch `mcp_session_sources_elided_total` to find out whether your agents need more |
| `MAX_EXTRACTED_CHARS` | no | `1000000` | Cap on *extracted text* kept (and cached) per URL, as distinct from the `MAX_*_BYTES` caps on the raw response body. This is what `searxng_read_url` pagination pages through; each response returns at most 100k characters of it. Memory note: worst case the cache holds `CACHE_MAX_ENTRIES × MAX_EXTRACTED_CHARS` bytes of content (~1 GB at defaults, though real pages rarely approach the cap) — lower either value on tight memory budgets, raise this one to page deeper into very large documents |
| `EXTRACT_LINKS` | no | `true` | Whether hyperlink targets from fetched **HTML** are surfaced to the model. When enabled, anchors render as Markdown links (`[label](https://resolved-target)`) in both prose and table cells, matching what Office documents already produce. Relative hrefs are resolved against the page URL; only `http`/`https` targets are emitted (`javascript:`, `data:` and friends are dropped). Set to `false` to restore the previous behaviour of emitting anchor text only. Does not affect Office documents, whose links come through the `office_oxide` converter either way |
| `FETCH_KEEP_INVISIBLE_CHARS` | no | `false` | Set to `true` to stop the relay removing invisible characters (Unicode tag characters, zero-width characters, bidi controls) from fetched text. On by default, because those characters are how a page hides instructions a reader never sees. See [Hidden-text removal](security-model.md#hidden-text-removal) |
| `FETCH_KEEP_HIDDEN_TEXT` | no | `false` | Set to `true` to stop the relay removing HTML elements a browser would not render (`hidden`, `aria-hidden="true"`, `<template>`, `<input type="hidden">`, inline `display:none` / `visibility:hidden` / `opacity:0` / `font-size:0`) before extraction. On by default. See [Hidden-text removal](security-model.md#hidden-text-removal) |
| `PRUNE_SELECTOR` | no | `[class*="related"], [id*="related"]` | CSS selector whose matches are removed **before** trafilatura decides which subtree is the article. Without it, sites that wrap boilerplate in an attractive-looking container can have that container selected instead of the story — silently, with plausible text and no error. The default is the narrowest selector measured to fix a real case (a Register article where the most-popular sidebar was extracted in place of the body) with no change to a heise article. Set to an empty string to disable pruning. A malformed selector fails startup rather than being silently ignored. Note that `header` and `footer` are deliberately **not** included: `<article><header><h1>` is ordinary HTML5 and pruning it decapitates articles |
| `FETCH_ALLOWED_HOSTS` | no | — | Comma-separated `host:port` entries whose fetches bypass the public-IP SSRF check, so the fetch tool can reach named internal resources (e.g. `confluence.corp:443,wiki.internal:8443`). **The port is mandatory** — a bare hostname fails startup. Matched exactly on the request hostname (case- and trailing-dot-insensitive; no subdomain wildcards) and re-checked on every redirect hop. See [SSRF protection](security-model.md#ssrf-protection) |
| `FETCH_ALLOWED_CIDRS` | no | — | Comma-separated `range/prefix:port` entries treated as reachable even though the default policy would block them (e.g. `10.1.2.0/24:443,192.168.5.0/24:8443`). **The port is mandatory**; a default route (`0.0.0.0/0`, `::/0`) is refused. Checked against the *resolved* IP at dial time and on each redirect, so it stays robust against DNS rebinding. Each range's size is logged at startup. See [SSRF protection](security-model.md#ssrf-protection) |
| `FETCH_PROXY` | no | — | Egress proxy for the fetch tool (`http`, `https`, `socks5`, `socks5h`), e.g. `http://proxy.corp:3128`. On its own it applies **only** to hosts on `FETCH_ALLOWED_HOSTS`. Deliberately *not* read from `HTTP_PROXY`/`HTTPS_PROXY`. A malformed URL or unsupported scheme fails startup. See [SSRF protection](security-model.md#ssrf-protection) |
| `FETCH_PROXY_ALL` | no | `false` | Route **every** fetch through `FETCH_PROXY`, not just allow-listed hosts. For networks with no direct egress. Delegates the per-IP SSRF policy to the proxy: `FETCH_ALLOWED_CIDRS` and the public-IP check stop applying. Setting it without `FETCH_PROXY` fails startup. See [SSRF protection](security-model.md#ssrf-protection) |
| `FENCE_SIGNING_KEY` | no | — | Ed25519 private key used to sign `<sec:fence>` elements, supplied inline. Accepts PKCS#8 PEM, base64 PKCS#8 DER, a base64 32-byte seed, or a base64 64-byte private key — the encoding is auto-detected, and line-wrapped base64 is fine. When unset a fresh key is generated at every process start, which a verifying gateway cannot pin; startup logs a `warn` saying so. Set this (or the `_FILE` form) in every deployment. Mutually exclusive with `FENCE_SIGNING_KEY_FILE`: setting both fails startup, as does a malformed key. See [Fence signing key](prompt-fencing.md#fence-signing-key) |
| `FENCE_SIGNING_KEY_FILE` | no | — | Path to a file holding the same key material, for Secret mounts and `podman secret`. Same encodings and same validation as `FENCE_SIGNING_KEY`. A file readable beyond its owner logs a warning but does not fail startup, since read-only mounts routinely land at `0444`. See [Fence signing key](prompt-fencing.md#fence-signing-key) |
| `FENCE_PREAMBLE` | no | `fenced` | Where the awareness preamble travels. `fenced` emits format 1.1: the preamble is the body of its own signed `rating="trusted" type="instructions"` fence, so a response has two fences and no non-whitespace bytes outside them. `prose` emits format 1.0: unsigned preamble text, then one content fence — keep it only for gateways that predate 1.1; startup logs a `warn` while it is set. The value is also what `version` reports, on every fence and at `/fence/public-key`. Any other value fails startup. Pair it with a persistent signing key the gateway pins. See [Fenced awareness preamble](prompt-fencing.md#fenced-awareness-preamble) |
| `LOG_LEVEL` | no | `info` | Log verbosity: `debug`, `info`, `warn`, `error`, `off` |
| `LOG_FORMAT` | no | `text` | Log format: `text` or `json` |

¹ HTTP mode requires an authentication layer: *at least one* of the three static auth-token variables **or** OAuth (`MCP_OAUTH_ISSUER` + `MCP_OAUTH_AUDIENCE`). The static variables can also be combined: later sources override earlier ones if the same digest appears in more than one. All static tokens are independently validated against a 32-character minimum. When both static tokens and OAuth are configured, a request is accepted if *either* validates.

Generate a strong token:

```bash
openssl rand -hex 32
```

## Token file format

When using `MCP_AUTH_TOKEN_FILE`, each non-comment line is `identity:token`. The split is on the first `:`, so tokens may contain colons; identities may not. Identities are arbitrary strings used only for log correlation — typically a username, agent name, or service account label.

```
# This is a comment.

alice:7f3a8c2e9b1d4f6a0c8e2b9d4f6a0c8e2b9d4f6a0c8e2b9d4f6a0c8e2b9d4f6a
bob:0e1d2c3b4a596877665544332211ffeedccbbaa998877665544332211ffeedc
service-ci:9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba

# Identity rotation: both lines below are accepted for "alice" until
# the old one is removed.  Useful for zero-downtime token rotation.
alice:newtokenvaluefor32charsminimum0123456789abcdef0123456789abcdef
```

Set the file mode to `0600` and place it on `tmpfs` (or a Docker secret / Kubernetes projected volume) if your threat model includes other users on the host.

## OAuth 2.0 / OIDC

The static token table above is a shared secret you mint and distribute yourself. For fleets that already run an identity provider — Keycloak, Auth0, Microsoft Entra, Okta, Dex, Ory Hydra — the relay can instead **verify OAuth 2.0 bearer JWTs** the provider issues, and derive the audit identity from a token claim rather than a lookup table.

The relay is only a **Resource Server**: it verifies presented tokens. It is **not** an Authorization Server — it runs no `/authorize` or `/token` endpoint, shows no consent screen, and stores no refresh tokens. The provider owns the whole token lifecycle; a client obtains a token from the provider (the OAuth flow, PKCE, refresh — all on the provider's side) and sends it as `Authorization: Bearer <jwt>`. The relay checks the signature and the `iss` / `aud` / `exp` / `nbf` claims, optionally a required scope, then attaches the identity claim to the request context exactly as a static token's identity would be — so per-identity audit logging, history, and the rate-limit exempt list all work unchanged.

**Enable it** by pointing the relay at your issuer and naming the audience it should accept:

```bash
-e MCP_OAUTH_ISSUER=https://idp.example.com/realms/main \
-e MCP_OAUTH_AUDIENCE=https://relay.example.com
```

At startup the relay fetches `https://idp.example.com/realms/main/.well-known/openid-configuration` and the JWKS it names; the key set is then cached and rotated automatically as the provider publishes new keys, so a signing-key roll needs no relay restart. A discovery endpoint that is unreachable or misconfigured **fails startup** rather than silently accepting nothing.

**Two key sources**, mutually exclusive:

- **Issuer discovery** (default) — keys fetched from the issuer over the network, as above. For a private issuer whose own TLS certificate is not publicly trusted, add `MCP_OAUTH_CA_ROOTS=/etc/mcp/idp-ca.pem`; that trust is scoped to OAuth traffic only and never widens the fetch tool or the SearXNG client.
- **Static JWKS file** — `MCP_OAUTH_JWKS_FILE=/etc/mcp/jwks.json` supplies the verification keys from disk, for air-gapped deployments or ones that sync keys by other means. `MCP_OAUTH_ISSUER` is still required (its value is checked against each token's `iss`). The file is hot-reloaded on mtime change, so a key rotation is picked up without a restart.

**Identity and scope.** By default the `sub` claim becomes the audit identity; set `MCP_OAUTH_IDENTITY_CLAIM=email` (or `client_id`, `azp`, …) to use another. Set `MCP_OAUTH_REQUIRED_SCOPE=search` to reject any token that does not grant that scope.

**Static tokens and OAuth coexist.** When both are configured, each request is tried against the static digest table first (a cheap fixed-length lookup) and then OAuth verification; either one validating admits the request. This lets you keep a static token for CI or a monitoring probe while human or agent callers authenticate through the IdP. You can also run OAuth *only* — with no `MCP_AUTH_TOKEN*` set at all — and the HTTP-mode "authentication is required" check is satisfied by the issuer alone.

**Client discovery.** When OAuth is enabled the relay serves [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected-resource metadata at `GET /.well-known/oauth-protected-resource` (unauthenticated — it only names the issuer and audience), and every `401` carries a `WWW-Authenticate: Bearer … resource_metadata="…"` challenge pointing at it. A spec-compliant MCP client can follow that to discover which issuer to authenticate against with no out-of-band configuration.

> **Rate limiting note.** OAuth-authenticated callers are currently bucketed **per source IP**, not per identity, because token verification happens inside the auth middleware which runs *after* the rate limiter (the limiter cheaply re-hashes static tokens, but a full JWT verification on the limiter path would be wasteful). Static-token callers are still bucketed per identity. If you need per-identity limits for OAuth callers, put them behind distinct source addresses or a proxy that sets a stable client key.

## Session modes

The MCP Streamable HTTP transport is stateful by default: the SDK assigns a session ID on `initialize`, the client echoes it on every subsequent request, and the SDK looks it up in an in-memory map. When the server restarts, that map is rebuilt empty — the client's old session ID returns 404, and many MCP clients fail to re-initialize automatically despite the spec requiring it. The result is "I redeployed and my agent is stuck until I restart it."

| Mode | `MCP_STATELESS` | When to use | Trade-off |
|---|---|---|---|
| **Stateful** *(default)* | `false` | Multi-tenant deployment where `session_id` must be server-issued and forgery-proof | Agent must re-handshake after every server restart |
| **Stateless** | `true` | Deployment that must survive server restarts without client reconnect | `session_id` becomes client-asserted (not server-validated); `GET`/`DELETE` return 405; server-initiated notifications cannot reach the client |

For audit correlation in stateful mode, every tool-call log line carries both `identity` (which token authenticated the request) and `session_id` (which initialize handshake the request belongs to). The `session_id` connects tool calls back to the `"session initialized"` log line for the same session — that's where the client's identity is recorded at handshake time. Idle sessions are reaped after `MCP_SESSION_MAX_AGE` by a background janitor (defaults to 7 days); sessions cleanly closed by the client (DELETE) are tracked too and freed immediately.

In stateless mode the `session_id` field is still present and stable across requests from one client, but it comes from somewhere else and means something weaker. As of go-sdk **v1.7.0** a stateless server does not read or set `Mcp-Session-Id` at all — the SDK's own `req.Session.ID()` is empty for every request, and `ServerOptions.GetSessionID` is not consulted. (Before v1.7.0 the SDK echoed the client's value back; the change follows the sessionless direction of the MCP spec, [SEP-2567](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2567).)

So in stateless mode **this relay reads the header itself**, in one middleware, and only in that mode. The value is validated for shape — at most 128 bytes of printable, space-free ASCII, rejected outright rather than truncated — and then used for exactly two things: the `session_id` field in audit logs, and the conversation half of the per-caller key behind [`searxng_session_sources`](tools.md#searxng_session_sources). Without it, two agents sharing one token would share one source ledger and evict each other's entries.

What that value is has not changed: an authenticated client can assert any `session_id` it likes, so it is a correlation handle and never a claim about who the caller is. What changed is who reads it — this is now the relay's deliberate choice rather than SDK behaviour inherited by accident. A client that sends no header simply gets an empty `session_id`, which is a clean degradation rather than a failure. `identity` remains server-validated in both modes, and is the canonical join key when forgery-resistance matters — in stateless mode it is the *only* thing keeping tenants apart, since the conversation half is entirely client-supplied.

If you don't want session IDs in your logs at all, there are two cases. In **stateful** mode, set `mcp.ServerOptions.GetSessionID` to `func() string { return "" }` in `server.go:buildMCPServer`: the SDK then omits the `Mcp-Session-Id` response header and `req.Session.ID()` returns empty for every request — true "sessionless" mode. The relay's own header read is deliberately *not* wired into this path, so it cannot hand back the client-supplied IDs you just asked it to stop recording. In **stateless** mode, drop the `trackClientSession` middleware from the chain in `main.go` instead; `GetSessionID` is not consulted there and would have no effect. Neither is exposed as an env var because the use case is narrow.

### Tuning the session janitor

The two janitor knobs serve different purposes and are worth understanding before changing the defaults:

- **`MCP_SESSION_MAX_AGE`** is a *policy* setting. It caps how long any one session is allowed to live. Lower it (e.g. `24h`) when your environment rotates auth tokens daily — sessions older than the rotation period are using a token that no longer exists in the table, so reaping them forces a clean re-handshake with the current one. Lower it further for compliance frameworks that require periodic re-authentication. Raise it (e.g. `720h` / 30d) for batch or scheduled agents that legitimately go idle for long stretches.

- **`MCP_SESSION_JANITOR_INTERVAL`** is a *mechanism* setting. It controls how often the cleanup pass runs. Shorter intervals catch expired sessions sooner at the cost of a small amount of mutex contention; longer intervals are cheaper but allow more overshoot past `MCP_SESSION_MAX_AGE`. The default of `15m` means a session might live up to 15 minutes past its max age before being closed — fine for the policy "approximately a week" but worth lowering if your max age is itself short.

If you don't see the session cap (`mcp_active_sessions` in `/metrics`) climbing under load, the defaults are working and there's nothing to tune.

## Rate limiting

In HTTP mode the server applies a per-caller token-bucket rate limit to requests under `/`. Defaults are `5` requests per second sustained with a burst of `10` — comfortable for a single agent reasoning with the tools (typical pattern is 1–3 tool calls per agent turn with seconds of model think-time between) while still bounding the damage a runaway agent or leaked token can do. Set `MCP_RATE_LIMIT_RPS=0` to disable.

Buckets are keyed by **identity** when the request carries a recognised bearer token, and by **remote IP** otherwise. The fallback is intentional: an unauthenticated attacker brute-forcing tokens from a single host shares one IP-keyed bucket regardless of which token guess they present, so the limiter throttles the attack at the network edge rather than at the auth check. Authenticated callers are billed against their identity — multiple agents using the same token share one bucket, which is the right semantic for "this credential's usage budget."

Rejections return HTTP `429 Too Many Requests` with a `Retry-After` header containing an integer second count. Every rejection emits a structured WARN log line with `identity` (when known), `remote`, `method`, `path`, and `retry_after` so the audit trail records denied traffic the same way it records unauthorised traffic. The Prometheus counter `mcp_rate_limit_rejections_total` aggregates rejections for dashboards and alerting (no per-identity label by design — rejection events are already in the structured log when forensics needs them).

The bucket store is an LRU capped at 10,000 entries. Identities are bounded by the configured auth-token table so they all fit comfortably; the cap bounds memory under an IP-rotation attack, at the cost that evicted buckets reset to full on next contact (which doesn't materially affect throttling for distinct attackers).

**What this doesn't cover.** `/health` is never rate-limited so a polling load balancer can't be flagged as abusive. `/metrics` is also exempt — a scraper that's polling on a fixed interval shouldn't produce gaps in Prometheus that look like outages, and an abusive scraper is better contained by rotating `MCP_METRICS_TOKEN` than by 429-ing the metrics endpoint. Because that token is separate from the MCP tokens, revoking it costs the scraper nothing but its own access. `/fence/public-key` is unauthenticated and unthrottled (it's a public key, public). Stdio mode has no HTTP middleware and therefore no rate limit, but it's also a single trusted process with no remote attack surface.

**Exempt list.** `MCP_RATE_LIMIT_EXEMPT=ci,uptime-monitor` skips the limiter entirely for those identities. Use it for internal monitoring agents that hit the MCP root endpoint (rather than `/metrics`), and for CI pipelines that run high-rate functional tests against the live service. Tokens for exempt identities should still come from a strong source — exemption is about volume, not trust.

**Tuning notes.**

- *Single agent.* Defaults are fine. A reasoning agent makes single-digit tool calls per turn, well below 5 rps.
- *Many concurrent agents under one identity.* If you front several agents with one token, calculate `(agents × peak-burst-per-agent)` and set `MCP_RATE_LIMIT_BURST` to cover it, leaving `MCP_RATE_LIMIT_RPS` at the per-identity sustained budget you actually want. Or split into one identity per agent and let the limits stack naturally.
- *Multi-replica deployments.* Buckets are per-process. Under round-robin routing the effective per-caller rate is `(replicas × RPS)`; under sticky-session routing it's `RPS`. If you need a globally-enforced budget, terminate at the Ingress and set `MCP_RATE_LIMIT_RPS=0` on the pods.
- *Public/internet-facing.* Tighten RPS to whatever an upstream-friendly rate is for SearXNG and keep `MCP_RATE_LIMIT_BURST` close to that — the burst is what an attacker would exploit first.

## Session limits

In HTTP mode the server caps concurrent sessions at 1,000. Requests to initialise beyond this limit receive a `503 Service Unavailable` response. Sessions are removed when the client sends a `DELETE` request.

## Scoping a relay to specific engines

`SEARXNG_TOKENS` lets several relays share one SearXNG instance while each reaches only its own engines — useful when separate teams have separate internal search backends and must not read each other's.

Mark the engine private in SearXNG's `settings.yml`. `tokens:` gates who may select the engine; the engine's own credential (`api_key` or equivalent) is what limits what it can see:

```yaml
engines:
  - name: teama-confluence
    engine: json_engine
    base_url: https://confluence-a.corp/rest/api/search
    api_key: "<team A service account token>"
    shortcut: cfa
    categories: [general]
    disabled: true
    tokens: ['ENGINE-TOKEN-A']
```

Then give each relay only its own token:

```bash
docker run -d \
  -e SEARXNG_URL=https://searxng.corp \
  -e SEARXNG_TOKENS=ENGINE-TOKEN-A \
  -e MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  -e MCP_PORT=8080 -p 8080:8080 \
  ghcr.io/littleoffice/mcp-searxng-relay:latest
```

Notes:

- **`disabled: true` is not redundant.** Without it the engine sits in its category and fires on every ordinary web search, adding latency and putting internal results in front of unrelated queries. Naming an engine explicitly through the `engines` search parameter builds the engine reference directly and is unaffected by the disabled-by-default state, so the engine still runs when actually asked for.
- **The boundary is enforced by SearXNG, not by this relay.** SearXNG resolves the full engine reference list — categories, the `engines` parameter, and `!bang` syntax inside the query string alike — and only then drops engines whose `tokens:` are unsatisfied. A filter in this process on the `engines` parameter would miss the bang path; presenting the wrong token cannot be worked around from the agent side.
- **Tokens are per-process, not per-caller.** Every identity in the token table shares them. Where two groups of callers must be separated, run one relay per group. The identities in `MCP_AUTH_TOKEN_FILE` are audit labels, not an authorization boundary.
- **`tokens` as a query parameter is undocumented upstream.** SearXNG's Search API docs describe engine tokens only as a Preferences-page setting. That they are also accepted as a request parameter follows from `webapp.pre_request` merging `request.args` into the preferences it parses. It is long-standing behaviour, but pin your SearXNG image by digest and keep a test asserting the negative case — a search naming another team's engine without its token returns no results.
- **Search only.** `searxng_read_url` does not use these tokens. If the relay must be kept away from another team's internal hosts, that is `FETCH_ALLOWED_HOSTS` / `FETCH_ALLOWED_CIDRS`, set per relay.

## Advertising engines to the model

Models trained on public search habits reach for Google/Bing dialect — most visibly a `site:` filter — because nothing in a bare search tool tells them the backend is different. Against SearXNG that misfires in a way that is easy to miss: `site:` is forwarded to general-web engines (so it *appears* to work), but a specialized backend like a self-hosted forge has no such operator, so `site:code.corp` becomes a literal search term and matches nothing. The correct move is to select the backend **by engine** — the `engines` parameter (`engines=gitea`) or a `!bang` in the query (`!gitea …`), both of which this relay already supports — not to scope by domain.

The fix lives at the tool boundary, not in the model. `SEARXNG_ENGINES` / `SEARXNG_ENGINES_FILE` let you advertise a curated roster in the `searxng_web_search` description, so the model both learns the dialect and knows which engines exist and what each is for:

```bash
docker run -d \
  -e SEARXNG_URL=https://searxng.corp \
  -e SEARXNG_ENGINES='gitea: our self-hosted forge — repositories, issues, code; wikipedia: encyclopedia articles; arxiv: preprints, papers' \
  -e MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  -e MCP_PORT=8080 -p 8080:8080 \
  ghcr.io/littleoffice/mcp-searxng-relay:latest
```

The purpose text is what turns "this is code-related" into "use the `gitea` engine" — write it for the model, describing what each engine is good for.

Notes:

- **Curated by default; discovery is opt-in.** By default the roster is exactly what you list — nothing is pulled from SearXNG. Set `SEARXNG_ENGINES_DISCOVER=true` to auto-populate it from SearXNG's `/config` endpoint, with the manual roster layered on top (it adds engines and overrides purposes). Two things to know before you enable it. First, **it can leak private engines:** `/config` enumerates *every* enabled engine unconditionally — SearXNG's `tokens:` gates whether an engine answers a query, not whether it is listed — so discovery will advertise the existence of token-gated backends unless you name them in `SEARXNG_ENGINES_EXCLUDE`. That is the boundary [engine scoping](#scoping-a-relay-to-specific-engines) exists to draw, so discovery is off by default and, when on, the operator stays in control of what is advertised. Second, discovery only supplies engine *names* (and a category-derived hint) — the human "purpose" text that turns "this is code-related" into "use `gitea`" still comes from `SEARXNG_ENGINES` / `SEARXNG_ENGINES_FILE`, so curation remains worthwhile even with discovery on. On a hardened instance that blocks `/config`, discovery fails soft (a warning, then your manual roster) — so leaving it on is safe there, it just does nothing.
- **The roster is advisory.** It only changes the tool *description*; it does not restrict which engines can be queried (that is `SEARXNG_TOKENS` upstream) and the query is never rewritten. A model can still name an engine you did not list, and a `site:` filter is still forwarded verbatim — the roster steers, it does not enforce.
- **Cheap and stable.** The description is built once at startup and stays constant for the process, so it sits in the tool-definitions prefix that clients and inference caches reuse across turns — a handful of engines costs a few hundred input tokens once, not per call.
- **Leave it unset** to ship only the generic dialect guidance (select by engine/`!bang`, not `site:`) with no engine names — still useful, but the model then has to discover engine names from result `engine` fields.
