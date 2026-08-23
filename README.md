# mcp-searxng-relay

A Model Context Protocol (MCP) server giving AI agents web search and URL fetching through your own self-hosted [SearXNG](https://github.com/searxng/searxng) instance — built for environments where search must stay on approved infrastructure and every query must be auditable. No third-party search APIs, no external data brokers; queries never leave infrastructure you control.

**Who this is for.** Teams running AI agents in corporate or government environments where outbound search is restricted, monitored, or both — and where "we use a hosted search API" is not an acceptable answer. The project prioritizes a defensible security posture and a clean audit trail over breadth of features.

**What's distinctive.** Most search tooling for agents stops at "here are some results." This relay also tells you what the agent *actually did with them*.

`searxng_session_sources` returns the URLs this relay genuinely fetched for a given caller — byte-exact, newest first, each marked with how much was really read: the full text, one window of a longer document, metadata only, or a fetch that failed. Agents transcribe URLs badly when they compose a final answer thousands of tokens after the tool call that produced it, and fabricate them outright when they never fetched one at all. An instruction like "don't cite sources you haven't read" is unenforceable against a model's recall; against this list it is a lookup. The read-depth distinction is the part that matters — "fetched" and "read in full" are not the same claim, and it is precisely the one models lose.

A hosted search API structurally cannot offer this: it sees one query at a time and keeps no per-caller ledger. The same reasoning runs through the rest of the project — every search and fetch is [attributed to an identity and a session](#logging), the [SSRF policy](#security-notes) is documented and its reach is stated in config rather than inferred, and nothing that would widen a security boundary is allowed to happen silently. If you need to be able to say what your agents searched, what they read, and how much of it, that is what this is for.

**Companion project.** This relay is designed to be deployed alongside [searxng-helm](https://github.com/littleoffice/searxng-helm), a hardened Helm chart for SearXNG on Kubernetes (rootless, read-only rootfs, deny-by-default NetworkPolicies, cosign-signed). The chart deploys both SearXNG and this relay as a pair; see its README for the full infrastructure security story. The relay also ships minimal standalone K8s manifests for quick testing — see [Kubernetes](#kubernetes) below.

This MCP server supports both the **stdio** transport (for local use with Claude Desktop and similar clients) and the **Streamable HTTP** transport (for networked or containerised deployments).

---

## Contents

- [Features](#features)
- [Requirements](#requirements)
  - [Enabling JSON format in SearXNG](#enabling-json-format-in-searxng)
- [Quick start](#quick-start)
  - [Docker (recommended)](#docker-recommended)
  - [Docker Compose](#docker-compose)
  - [Building the container image](#building-the-container-image)
  - [Kubernetes](#kubernetes)
- [Configuration](#configuration)
  - [Token file format](#token-file-format)
  - [Session modes](#session-modes)
    - [Tuning the session janitor](#tuning-the-session-janitor)
- [MCP tools](#mcp-tools)
  - [`searxng_web_search`](#searxng_web_search)
  - [`searxng_read_url`](#searxng_read_url)
  - [`searxng_url_metadata`](#searxng_url_metadata)
  - [`searxng_session_sources`](#searxng_session_sources)
- [Using with Claude Desktop (stdio mode)](#using-with-claude-desktop-stdio-mode)
- [Using with Claude Desktop (HTTP mode)](#using-with-claude-desktop-http-mode)
- [Scoping a relay to specific engines](#scoping-a-relay-to-specific-engines)
- [Security notes](#security-notes)
- [Rate limiting](#rate-limiting)
- [Session limits](#session-limits)
- [Operations](#operations)
  - [Health endpoint](#health-endpoint)
  - [`--healthcheck` CLI flag](#--healthcheck-cli-flag)
  - [Graceful shutdown](#graceful-shutdown)
  - [HTTP server timeouts](#http-server-timeouts)
- [Building the Docker image](#building-the-docker-image)
- [Logging](#logging)
- [Metrics](#metrics)

---

## Features

- **Verifiable source list** — `searxng_session_sources` returns the URLs the relay actually fetched for a caller, byte-exact and newest-first, each marked with how much of it was read: full text, one window of a longer document, metadata only, or a failed fetch. Agents transcribe URLs badly when composing a final answer far from the tool call that produced them, and fabricate them outright when they never fetched one; this gives the model ground truth to copy from instead of recall, and gives you a record of what it actually read. Delivered in a CDATA-encoded fence so URLs survive the round trip unescaped.
- **Web search** via SearXNG with full control over language, category, time range, safe-search level, and result count
- **URL fetching** with structured Markdown output — headings, lists, tables, code blocks, and inline emphasis all preserved
- **URL metadata triage** — `searxng_url_metadata` returns just title, author, publish date, language, site name, description, image, categories, and tags as JSON, at roughly an order of magnitude lower token cost than fetching the full body. Useful for picking which of several candidate URLs to read in full. Cache is shared with `searxng_read_url`, so a metadata fetch followed by a content fetch (or vice versa) costs one upstream HTTP request, not two.
- **PDF text extraction** from fetched URLs
- **Office document extraction** — DOCX, XLSX, PPTX plus legacy DOC, XLS, PPT. Documents render to Markdown rather than flat text so headings, tables, and list structure survive into the model's context (spreadsheets in particular benefit — a Markdown table is far more useful than CSV-flattened cells)
- **Pagination for long documents** — responses are windowed at 100k characters, and a truncated response ends with a notice naming the total size and the exact `start_index` for the next call. The full extracted text (up to `MAX_EXTRACTED_CHARS`) is cached, so paging through a large PDF costs one upstream fetch, not one per page
- **Image responses** — JPEG, PNG, GIF, and WebP URLs come back as MCP `ImageContent` blocks for vision-model consumption (the SDK base64-encodes the raw bytes on the wire). SVG is intentionally excluded — more useful to the model as text than as a binary blob. Raw size is capped by `MAX_IMAGE_BYTES`, separately from `MAX_BODY_BYTES`, so image and text limits can be tuned independently.
- **Automatic charset detection** — non-UTF-8 pages (Shift-JIS, windows-1252, ISO-8859-1, …) are decoded correctly before parsing
- **Readability-style content extraction** — navigation bars, footers, sidebars, and cookie banners are stripped automatically
- **Degraded-search visibility** — SearXNG answers with HTTP 200 even when some of its backends failed, so a search silently returns thinner results and the first visible symptom is usually someone concluding the model has regressed. The relay reads the `unresponsive_engines` field SearXNG reports and logs a `WARN` naming the engines and why they failed, so a broken backend is diagnosed from the relay's own logs rather than mistaken for a relay or model bug
- **Engine attribution on search results** — each result includes the list of SearXNG backend engines that returned it. A URL surfaced by three engines is a different signal than one surfaced by one, and the agent can weigh that without the server imposing a ranking on top. The `engines` search parameter closes the loop: an agent can re-query the specific backend that surfaced a promising result.
- **Per-domain fetch metrics** — `/metrics` exposes `mcp_fetches_by_domain_total{domain="…",outcome="success|error"}` so an operator can see which destination hosts are healthy and which aren't. Bounded cardinality: at most 512 distinct domains tracked, with the remainder rolled up under `domain="__overflow__"`.
- **Response caching** with configurable TTL and per-request cache bypass
- **SSRF protection** — non-globally-routable addresses are blocked at TCP-dial time (loopback, link-local, private, multicast, broadcast, unspecified, plus a hardcoded blocklist covering CGNAT, TEST-NET-{1,2,3}, benchmark, IETF protocol assignments, NAT64, Teredo, 6to4, IPv6 documentation, ORCHID, the discard prefix, future-reserved 240/4, and other reserved ranges the stdlib predicates miss). Redirect chains are revalidated at every hop to close the DNS-rebinding window. Operators can opt in to reaching internal resources (Confluence, Jira, wikis) via `FETCH_ALLOWED_HOSTS` / `FETCH_ALLOWED_CIDRS`; both require an explicit port, so allow-listing a wiki never also exposes the Redis or kubelet listener beside it.
- **Bearer token authentication** with multi-token tables (`MCP_AUTH_TOKEN`, `MCP_AUTH_TOKENS`, or `MCP_AUTH_TOKEN_FILE`) and per-identity audit logging
- **Per-caller rate limiting** — token-bucket throttle keyed by identity when authenticated and by source IP otherwise. Configurable RPS and burst, default 5 rps / burst 10. Exposed at `mcp_rate_limit_rejections_total`.
- **Prompt fencing** — every tool response is wrapped in a signed `<sec:fence>` element with a per-response random nonce, implementing arXiv:2511.19727. Public key exposed at `/fence/public-key` for forward compatibility with verifying clients. The signing key is per-process by default, or operator-supplied via `FENCE_SIGNING_KEY` / `FENCE_SIGNING_KEY_FILE` when a verifier needs a stable fingerprint to pin.
- **Reproducible container builds** — bit-for-bit. Given the same source commit and `SOURCE_DATE_EPOCH`, the build produces a byte-identical image, verifiable via `docker save <image> | sha256sum`. Toolchain pinned by digest, `go.sum` frozen, no embedded paths, VCS state, or build IDs. Details in [`supply-chain.md`](docs/supply-chain.md).
- **Structured startup banner** with all configuration values printed to stderr on start (secrets redacted)

---

## Requirements

- A running SearXNG instance with the JSON output format enabled
- Go 1.26+ (for building from source) or Docker

### Enabling JSON format in SearXNG

Add the following to your SearXNG `settings.yml`:

```yaml
search:
  formats:
    - html
    - json
```

---

## Quick start

### Docker (recommended)

```bash
docker run -d \
  -e SEARXNG_URL=https://your-searxng-instance.example.com \
  -e MCP_PORT=8080 \
  -e MCP_AUTH_TOKEN=$(openssl rand -hex 32) \
  -p 8080:8080 \
  ghcr.io/littleoffice/mcp-searxng-relay:latest
```

### Docker Compose

```yaml
services:
  mcp-searxng:
    image: ghcr.io/littleoffice/mcp-searxng-relay:latest
    restart: unless-stopped
    environment:
      SEARXNG_URL: https://your-searxng-instance.example.com
      MCP_PORT: "8080"
      MCP_AUTH_TOKEN: your-strong-random-token
    ports:
      - "8080:8080"
```

## Building the container image

Compute the two reproducibility inputs once, then choose your build tool:

```bash
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
SERVER_VERSION="$(git describe --tags --always)"
```

**Docker (with BuildKit / buildx):**

```bash
docker buildx build \
    --build-arg SERVER_VERSION="${SERVER_VERSION}" \
    --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    --output type=docker,rewrite-timestamp=true \
    -t mcp-searxng-relay:"${SERVER_VERSION}" .
```

**Podman:**

```bash
podman build \
    --build-arg SERVER_VERSION="${SERVER_VERSION}" \
    --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    --timestamp "${SOURCE_DATE_EPOCH}" \
    -t mcp-searxng-relay:"${SERVER_VERSION}" .
```

The multi-stage build compiles the binary on a digest-pinned `golang:1.26.6-trixie` builder and copies only the static binary and CA certificates into a `scratch` runtime image.

**Reproducibility.** Given the same source commit and `SOURCE_DATE_EPOCH` (canonically the commit's own timestamp), either invocation produces a byte-identical image — verifiable via `docker save <image> | sha256sum` or `podman save <image> | sha256sum`. The toolchain is pinned by content digest, the module graph is frozen by `go.sum`, and the build sets `-trimpath`, `-buildvcs=false`, `-buildid=`, and `-Wl,--build-id=none` so neither paths, VCS state, nor link-time build IDs leak into the binary. BuildKit's `rewrite-timestamp` and Podman's `--timestamp` both pin all layer file timestamps to the same value so the image envelope is reproducible, not just the binary inside. See [`supply-chain.md`](docs/supply-chain.md) for the full provenance statement and verification steps.

Note that Docker and Podman use slightly different on-disk manifest encodings, so images built with one and saved through the other will not have matching SHA-256s even when functionally identical. Pick a build tool and stick with it for cross-machine reproducibility checks.

### Kubernetes

**For production, use [searxng-helm](https://github.com/littleoffice/searxng-helm).** The chart deploys SearXNG and this relay together with a locked-down security context, deny-by-default NetworkPolicies, Secret-managed credentials, and cosign-signed releases. It is the reference deployment for the threat model this relay is built for. See its README for the full infrastructure security story, the `mcpRelay` values block, and the GitOps / external-secret-store integration notes.

**Minimal standalone manifests** are included in [`deploy/kubernetes/`](deploy/kubernetes/) for quick cluster testing without a Helm release: [`deployment.yaml`](deploy/kubernetes/deployment.yaml) with a locked-down `securityContext`, [`service.yaml`](deploy/kubernetes/service.yaml), [`kustomization.yaml`](deploy/kubernetes/kustomization.yaml), and [`secret.example.yaml`](deploy/kubernetes/secret.example.yaml) as a template for `MCP_AUTH_TOKEN_FILE`. These are intentionally minimal — single replica, no Ingress, no NetworkPolicy — and are a starting point, not a hardened deployment. Apply with `kubectl apply -k deploy/kubernetes/` after creating a real Secret out-of-band from `secret.example.yaml` (copy to `secret.yaml`, fill in tokens, apply once; it is deliberately not listed in `kustomization.yaml` so a re-apply cannot roll a real Secret back to the placeholder values). The full deployment-shape, token-rotation, and external-secret-store guidance is in [`deploy/kubernetes/README.md`](deploy/kubernetes/README.md).

---

## Configuration

All configuration is via environment variables. The server will refuse to start if `SEARXNG_URL` is not set. At least one of `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKENS` / `MCP_AUTH_TOKEN_FILE` is required when `MCP_PORT` is set.

| Variable | Required | Default | Description |
|---|---|---|---|
| `SEARXNG_URL` | **yes** | — | Base URL of your SearXNG instance (trailing slash stripped automatically) |
| `MCP_PORT` | no | — | Port to listen on in HTTP mode. If unset, the server uses stdio |
| `MCP_AUTH_TOKEN` | HTTP mode¹ | — | Single bearer token; identity is logged as `"default"`. Backwards-compatible with single-tenant deployments |
| `MCP_AUTH_TOKENS` | HTTP mode¹ | — | Comma-separated `identity:token` pairs for small static fleets, e.g. `alice:abc...,bob:def...` |
| `MCP_AUTH_TOKEN_FILE` | HTTP mode¹ | — | Path to a file with one `identity:token` per line; `#` comments and blank lines ignored |
| `MCP_HEALTH_TOKEN` | no | — | Optional bearer token that gates `GET /health`. A **separate** secret from the MCP tokens above — do not reuse a value. Unset (the default) leaves `/health` open. Same 32-character minimum. If you set it, **every** prober must send it (see [Health endpoint](#health-endpoint)) |
| `MCP_METRICS_TOKEN` | to scrape | — | Bearer token that gates `GET /metrics`. A **separate** secret from the MCP tokens above — do not reuse a value. Unset, `/metrics` returns `401` to everyone, including callers holding a valid MCP token. Same 32-character minimum. Required if you scrape metrics (see [Metrics](#metrics)) |
| `MCP_STATELESS` | no | `false` | If `true`, the SDK skips session-ID validation and treats each request as a fresh temporary session. See "Session modes" below |
| `MCP_SESSION_MAX_AGE` | no | `168h` | Stateful mode only. How long a session may live before the janitor closes it. Go duration syntax (`30m`, `12h`, `168h` — no `d` or `w`) |
| `MCP_SESSION_JANITOR_INTERVAL` | no | `15m` | Stateful mode only. How often the janitor sweeps for expired sessions. Same duration syntax |
| `MCP_RATE_LIMIT_RPS` | no | `5` | Per-caller sustained request rate (requests/second). Set to `0` to disable. Fractional values supported (e.g. `0.5` = one request every two seconds) |
| `MCP_RATE_LIMIT_BURST` | no | `2 × RPS, min 1` | Token-bucket burst capacity — the number of requests a caller can fire back-to-back before the sustained rate kicks in |
| `MCP_RATE_LIMIT_EXEMPT` | no | — | Comma-separated identity names that bypass the rate limiter entirely (e.g. `ci,uptime-monitor`). Useful for trusted internal callers and monitoring identities |
| `AUTH_USERNAME` | no | — | HTTP Basic Auth username for SearXNG (if your instance requires it) |
| `AUTH_PASSWORD` | no | — | HTTP Basic Auth password for SearXNG |
| `SEARXNG_TOKENS` | no | — | Comma-separated [private-engine tokens](https://docs.searxng.org/admin/settings/settings_engines.html#private-engines-tokens) sent as the `tokens` search parameter on every query. Engines carrying a `tokens:` list in SearXNG's `settings.yml` are invisible and unusable without one. Scopes this relay to a subset of the engines on a shared SearXNG instance. See [Scoping a relay to specific engines](#scoping-a-relay-to-specific-engines) |
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
| `PRUNE_SELECTOR` | no | `[class*="related"], [id*="related"]` | CSS selector whose matches are removed **before** trafilatura decides which subtree is the article. Without it, sites that wrap boilerplate in an attractive-looking container can have that container selected instead of the story — silently, with plausible text and no error. The default is the narrowest selector measured to fix a real case (a Register article where the most-popular sidebar was extracted in place of the body) with no change to a heise article. Set to an empty string to disable pruning. A malformed selector fails startup rather than being silently ignored. Note that `header` and `footer` are deliberately **not** included: `<article><header><h1>` is ordinary HTML5 and pruning it decapitates articles |
| `FETCH_ALLOWED_HOSTS` | no | — | Comma-separated `host:port` entries whose fetches bypass the public-IP SSRF check, so the fetch tool can reach named internal resources (e.g. `confluence.corp:443,wiki.internal:8443`). **The port is mandatory** — a bare hostname fails startup. Matched exactly on the request hostname (case- and trailing-dot-insensitive; no subdomain wildcards) and re-checked on every redirect hop. See [SSRF protection](#security-notes) |
| `FETCH_ALLOWED_CIDRS` | no | — | Comma-separated `range/prefix:port` entries treated as reachable even though the default policy would block them (e.g. `10.1.2.0/24:443,192.168.5.0/24:8443`). **The port is mandatory**; a default route (`0.0.0.0/0`, `::/0`) is refused. Checked against the *resolved* IP at dial time and on each redirect, so it stays robust against DNS rebinding. Each range's size is logged at startup. See [SSRF protection](#security-notes) |
| `FETCH_PROXY` | no | — | Egress proxy for the fetch tool (`http`, `https`, `socks5`, `socks5h`), e.g. `http://proxy.corp:3128`. On its own it applies **only** to hosts on `FETCH_ALLOWED_HOSTS`. Deliberately *not* read from `HTTP_PROXY`/`HTTPS_PROXY`. A malformed URL or unsupported scheme fails startup. See [SSRF protection](#security-notes) |
| `FETCH_PROXY_ALL` | no | `false` | Route **every** fetch through `FETCH_PROXY`, not just allow-listed hosts. For networks with no direct egress. Delegates the per-IP SSRF policy to the proxy: `FETCH_ALLOWED_CIDRS` and the public-IP check stop applying. Setting it without `FETCH_PROXY` fails startup. See [SSRF protection](#security-notes) |
| `FENCE_SIGNING_KEY` | no | — | Ed25519 private key used to sign `<sec:fence>` elements, supplied inline. Accepts PKCS#8 PEM, base64 PKCS#8 DER, a base64 32-byte seed, or a base64 64-byte private key — the encoding is auto-detected, and line-wrapped base64 is fine. When unset (the default) a fresh key is generated at every process start. Mutually exclusive with `FENCE_SIGNING_KEY_FILE`: setting both fails startup, as does a malformed key. See [Fence signing key](#security-notes) |
| `FENCE_SIGNING_KEY_FILE` | no | — | Path to a file holding the same key material, for Secret mounts and `podman secret`. Same encodings and same validation as `FENCE_SIGNING_KEY`. A file readable beyond its owner logs a warning but does not fail startup, since read-only mounts routinely land at `0444`. See [Fence signing key](#security-notes) |
| `LOG_LEVEL` | no | `info` | Log verbosity: `debug`, `info`, `warn`, `error`, `off` |
| `LOG_FORMAT` | no | `text` | Log format: `text` or `json` |

¹ HTTP mode requires *at least one* of the three auth-token variables. They can also be combined: later sources override earlier ones if the same digest appears in more than one. All tokens are independently validated against a 32-character minimum.

Generate a strong token:

```bash
openssl rand -hex 32
```

### Token file format

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

### Session modes

The MCP Streamable HTTP transport is stateful by default: the SDK assigns a session ID on `initialize`, the client echoes it on every subsequent request, and the SDK looks it up in an in-memory map. When the server restarts, that map is rebuilt empty — the client's old session ID returns 404, and many MCP clients fail to re-initialize automatically despite the spec requiring it. The result is "I redeployed and my agent is stuck until I restart it."

| Mode | `MCP_STATELESS` | When to use | Trade-off |
|---|---|---|---|
| **Stateful** *(default)* | `false` | Multi-tenant deployment where `session_id` must be server-issued and forgery-proof | Agent must re-handshake after every server restart |
| **Stateless** | `true` | Deployment that must survive server restarts without client reconnect | `session_id` becomes client-asserted (not server-validated); server-initiated notifications cannot reach the client |

For audit correlation in stateful mode, every tool-call log line carries both `identity` (which token authenticated the request) and `session_id` (which initialize handshake the request belongs to). The `session_id` connects tool calls back to the `"session initialized"` log line for the same session — that's where the client's identity is recorded at handshake time. Idle sessions are reaped after `MCP_SESSION_MAX_AGE` by a background janitor (defaults to 7 days); sessions cleanly closed by the client (DELETE) are tracked too and freed immediately.

In stateless mode the `session_id` field is still present and stable across requests from one client, but the binding is weaker: the SDK uses whatever value the client sends in `Mcp-Session-Id` without validating it (only generating a fresh one if the client didn't supply any). This means an authenticated client could, in principle, forge another `session_id` of its choice — which is harmless for honest clients but means you can't treat `session_id` as a server-verified attribute. `identity` remains server-validated in both modes, and is the canonical join key when forgery-resistance matters.

If you don't want client-asserted `session_id` showing up in your logs at all, set `mcp.ServerOptions.GetSessionID` to `func() string { return "" }` in `server.go:buildMCPServer`. The SDK will then omit the `Mcp-Session-Id` response header and `req.Session.ID()` returns empty for every request — true "sessionless" mode. Not exposed as an env var because the use case is narrow.

#### Tuning the session janitor

The two janitor knobs serve different purposes and are worth understanding before changing the defaults:

- **`MCP_SESSION_MAX_AGE`** is a *policy* setting. It caps how long any one session is allowed to live. Lower it (e.g. `24h`) when your environment rotates auth tokens daily — sessions older than the rotation period are using a token that no longer exists in the table, so reaping them forces a clean re-handshake with the current one. Lower it further for compliance frameworks that require periodic re-authentication. Raise it (e.g. `720h` / 30d) for batch or scheduled agents that legitimately go idle for long stretches.

- **`MCP_SESSION_JANITOR_INTERVAL`** is a *mechanism* setting. It controls how often the cleanup pass runs. Shorter intervals catch expired sessions sooner at the cost of a small amount of mutex contention; longer intervals are cheaper but allow more overshoot past `MCP_SESSION_MAX_AGE`. The default of `15m` means a session might live up to 15 minutes past its max age before being closed — fine for the policy "approximately a week" but worth lowering if your max age is itself short.

If you don't see the session cap (`mcp_active_sessions` in `/metrics`) climbing under load, the defaults are working and there's nothing to tune.

---

## MCP tools

### `searxng_web_search`

Execute a web search and return titles, URLs, and snippets.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `query` | string | **yes** | — | The search query |
| `num_results` | number | no | `10` | Number of results to return (max 20) |
| `pageno` | number | no | `1` | Result page number (max 100) |
| `categories` | string | no | general | Comma-separated SearXNG categories: `news`, `science`, `files`, `images`, etc. |
| `language` | string | no | `all` | Language code e.g. `en`, `de`, `fr` |
| `time_range` | string | no | — | Filter by recency: `day`, `month`, or `year` |
| `safesearch` | number | no | `0` | Safe-search level: `0` = off, `1` = moderate, `2` = strict |
| `engines` | string | no | instance default | Comma-separated SearXNG engine names to query, e.g. `wikipedia,github`. Names match the engine attribution on prior results, so an agent can re-query the backend that surfaced a promising hit. Input is lowercased and whitespace-trimmed; names the instance doesn't run are silently ignored by SearXNG (a query naming only unknown engines returns no results rather than an error) |

**Example — recent news in English:**
```json
{
  "query": "fusion energy breakthrough",
  "categories": "news",
  "language": "en",
  "time_range": "month",
  "num_results": 5
}
```

**Output shape.** Each result is rendered as a text block of the form:

    Title: Example article title
    URL: https://example.com/article
    Snippet: First sentence or two of the page…
    Engines: google, bing, duckduckgo

The `Engines` line is omitted when SearXNG didn't return the field (older SearXNG versions, or results from a single-engine configuration). The list reflects the engines that returned this URL, in the order SearXNG provides them. No score is computed on top — the agent is free to read engine count as a corroboration signal or ignore it.

---

### `searxng_read_url`

Fetch a URL and return its content. Handles HTML (converted to structured Markdown), PDF (text extracted via `pdf_oxide`), Office documents (DOCX, XLSX, PPTX, plus legacy DOC, XLS, PPT — converted to Markdown via `office_oxide`), plain text (charset-decoded), and images (JPEG, PNG, GIF, WebP returned as MCP `ImageContent` blocks for vision-model consumption — SVG is intentionally excluded, since it is more useful to the model as text than as a base64-encoded binary blob). Caches results by default; image responses bypass the text cache.

Long documents are paginated. Each response returns a window of at most 100,000 characters of the extracted text; when there is more, the response ends with a notice like `[content truncated — showing chars 0-100000 of 348211; call searxng_read_url again with start_index=100000 to continue]`. The full extracted text (up to `MAX_EXTRACTED_CHARS`) is cached on the first fetch, so follow-up pages are cache hits and cost no upstream request. Offsets in the notice are exact — the agent echoes them back verbatim; the server snaps any offset that would split a multibyte character and guarantees each page advances, so following continuation hints always terminates.

PDF text is delimited by `--- [PDF page N of M] ---` marker lines, one per page, so agents can answer "what's on page 47", cite page numbers, and orient themselves inside any pagination window. The markers are advisory: they sit inside the untrusted content fence, and a malicious PDF can embed lookalike text (see [SECURITY.md](docs/SECURITY.md)). Office documents get no page markers — DOCX has no intrinsic pages (pagination is computed at render time, not stored in the file), so the Markdown headings preserved by the converter are the navigational anchors there; PPTX slides and XLSX sheets surface as heading breaks.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | **yes** | — | The URL to fetch (http/https only) |
| `force_refresh` | boolean | no | `false` | Bypass the cache and fetch a fresh copy |
| `start_index` | integer | no | `0` | Offset into the extracted text to start from. Use the value from a previous response's truncation notice |
| `max_chars` | integer | no | `100000` | Characters of extracted text to return in this response (ceiling: 100000) |

Both pagination parameters are ignored for image URLs, which are returned whole as image content blocks.

**Example — force a fresh fetch:**
```json
{
  "url": "https://example.com/article",
  "force_refresh": true
}
```

**Example — continue reading a long document from where the last response stopped:**
```json
{
  "url": "https://example.com/big-report.pdf",
  "start_index": 100000
}
```

---

### `searxng_url_metadata`

Fetch only the structured metadata for a URL — title, author, publish date, language, site name, description, image, categories, and tags — without returning the page body. For PDFs, `page_count` is also returned, so an agent can gauge whether a candidate is a 3-page memo or a 400-page report before committing to a full read (it is deliberately absent for Office documents: DOCX has no intrinsic page count, since pagination is computed at render time). Roughly an order of magnitude cheaper in tokens than `searxng_read_url`, and intended as a triage step before committing to read a candidate URL in full. Results are cached and the cache is shared with `searxng_read_url`: a metadata fetch followed by a content fetch (or vice versa) costs one upstream HTTP request, not two.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | **yes** | — | The URL to fetch metadata for (http/https only) |
| `force_refresh` | boolean | no | `false` | Bypass the cache and fetch a fresh copy |

**Example — triage three candidates before reading one in full:**
```json
{ "url": "https://example.com/article-a" }
{ "url": "https://example.com/article-b" }
{ "url": "https://example.com/article-c" }
```

**Output shape.** A JSON object with the curated metadata fields. Fields the extractor could not populate are omitted rather than rendered as empty strings or `null`, so the response is variable-shape; at minimum `url` is always present:

```json
{
  "url": "https://example.com/article",
  "title": "Example article title",
  "author": "Jane Doe",
  "description": "First paragraph or meta-description.",
  "site_name": "Example.com",
  "date": "2026-03-12T14:23:00Z",
  "language": "en",
  "image": "https://example.com/article/cover.jpg",
  "categories": ["technology"],
  "tags": ["distributed-systems", "go"]
}
```

**When to use this vs `searxng_read_url`.** Use `searxng_url_metadata` to triage which of several candidate URLs is worth reading in full, for citation building, and for date/author/site verification when the body itself is not needed. Use `searxng_read_url` once you've committed to reading a specific URL. The two tools share a cache, so triaging with metadata first and then reading the chosen URLs in full does not double the upstream load.

---

### `searxng_session_sources`

Return the URLs this relay has fetched for the calling identity, newest first, byte-exact.

The problem it addresses is not retrieval — it is transcription. A model composing a final answer containing ten URLs is reproducing them from context that scrolled past thousands of tokens earlier, token by token, with nothing to check against. That step happens after the last tool call, in a message no MCP server ever sees, so nothing on the wire can validate it. This tool moves the correct bytes back to the position immediately before the answer is written, which is the only place a server can help. The same list answers the second failure — a plausible-looking URL for a page that was never fetched at all — because a URL absent from the list was not fetched.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `since_seq` | integer | no | `0` | Return only entries with a sequence number above this. Pass the highest `seq` from a previous call to see only what has been fetched since |

**Output shape.** A JSON object, one row per distinct URL rather than per fetch:

```json
{
  "note": "URLs below are byte-exact as fetched by this relay …",
  "total_fetches": 12,
  "returned": 9,
  "elided": 0,
  "sources": [
    {
      "url": "https://www.example.com/psu/flex-atx-350w",
      "requested_url": "https://example.com/psu/flex-atx-350w",
      "title": "FlexATX 350W review",
      "read": "full",
      "outcome": "ok",
      "chars_read": 18422,
      "total_chars": 18422,
      "fetched_at": "2026-08-18T09:14:02Z",
      "tool": "searxng_read_url",
      "seq": 12,
      "fetches": 2
    }
  ]
}
```

`read` is the field that distinguishes a source an agent may claim to have read from one it merely looked at: `full` (the whole extracted text), `partial` (one pagination window of a longer document), `metadata` (`searxng_url_metadata` only — the body was never returned), `image`, or `none` (the fetch failed). Failed fetches appear with `outcome: "error"` and the error text; omitting them would make a 404 indistinguishable from a URL never tried. `requested_url` appears only when a redirect moved the URL, and the post-redirect `url` is the one to cite — it is the only URL in the exchange the model never saw and so cannot reconstruct at all.

**Repeat fetches fold into one row.** A URL fetched more than once — triaged with metadata and then read, paged through a window at a time, or re-read after the cache expired — keeps a single row, and `fetches` counts the calls behind it. The row then reports the *deepest* read ever reached for that URL and the high-water mark of `chars_read` / `total_chars`: a later metadata-only call does not un-read a page already read in full, and a re-fetch that fails does not erase the copy that was returned. The recency fields (`seq`, `fetched_at`, `tool`, `from_cache`) always describe the most recent fetch, which is what `since_seq` and the newest-first ordering are asking about.

**History scope.** Per caller (identity + session ID), in-memory, the 50 most recent *sources* (`MCP_HISTORY_ENTRIES`). Slots hold sources rather than fetches — a six-window read of one long document costs one slot, not six — so the cap is a count of things you might cite, not of tool calls. Sources dropped to make room are reported as an `elided` count; `total_fetches` keeps counting calls, so it legitimately exceeds the number of rows. Keying on identity as well as session matters: under `MCP_STATELESS=true`, and in the documented sessionless configuration, the session ID is client-asserted or empty, and keying on it alone would let one caller read another's fetched URLs. History does not survive a restart and does not cross replicas — it only needs to outlive the conversation, and shared storage would widen it to "everything this identity ever fetched", which makes the list worse for its purpose rather than better. For multi-replica deployments, configure session affinity at the ingress.

**Fence encoding.** This response is wrapped in a `<sec:fence>` carrying `encoding="cdata"`. The ordinary escaped fence turns every `&` into `&amp;`, which for a payload whose entire purpose is byte-exact URLs is a self-inflicted corruption channel — and query-string-dense URLs hit it on nearly every entry. The signature still covers the pre-encoding bytes exactly as on the escaped path; `encoding` is inside the canonical signed form, so a verifier can tell how to recover them and an attacker cannot flip it. The rating stays `untrusted`: the relay authors the assertion ("I fetched X at T") but not the values — titles come from fetched pages — and marking it trusted would let any site launder text into a trusted fence by being fetched once.

---

## Using with Claude Desktop (stdio mode)

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "searxng": {
      "command": "/path/to/mcp-searxng-relay",
      "env": {
        "SEARXNG_URL": "https://your-searxng-instance.example.com"
      }
    }
  }
}
```

No `MCP_PORT` or `MCP_AUTH_TOKEN` needed in stdio mode — the process communicates over stdin/stdout and is not network-accessible.

---

## Using with Claude Desktop (HTTP mode)

If you prefer to run the server as a persistent background process rather than spawning it per-session:

```json
{
  "mcpServers": {
    "searxng": {
      "type": "http",
      "url": "http://localhost:8080",
      "headers": {
        "Authorization": "Bearer your-strong-random-token"
      }
    }
  }
}
```

> **Note:** Run the HTTP server behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik) in any non-local deployment. The server itself speaks plain HTTP.

---

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

## Security notes

**Prompt injection.** Both tools return content sourced from the open web — titles, snippets, and page bodies written by third parties. A malicious site can embed instructions in that content (including in invisible or hidden elements) in an attempt to hijack the agent's behaviour, cause unexpected tool calls, or exfiltrate conversation context. This is the primary runtime risk when using this server with an LLM agent.

This server implements the prompt-fencing specification from [Peh, S. (2025), "Prompt Fencing: A Cryptographic Approach to Establishing Security Boundaries in Large Language Model Prompts" (arXiv:2511.19727)](https://arxiv.org/abs/2511.19727). Every tool response is wrapped in a `<sec:fence>` element with structured metadata, preceded by a short awareness preamble that tells the consuming model how to interpret the boundary:

```xml
<sec:fence xmlns:sec="http://promptfence.org/security/1.0"
           signature="MEYCIQDx5w2l7..."
           kid="3f9a1c7e2b4d8056"
           nonce="a9f7e2c14b8d6f31..."
           rating="untrusted"
           source="https://example.com/article"
           timestamp="2026-05-07T14:23:00Z"
           type="content"
           version="1.0">
<extracted content>
</sec:fence>
```

What this provides today:

- **Key identification and format versioning.** Every fence carries `kid` — the same fingerprint reported by `/fence/public-key` — and `version`. `kid` lets a verifier holding several keys select one instead of trial-verifying against all of them, which is what makes key rotation workable: fences signed by an outgoing key stay in the context window and keep arriving while the new key rolls out, and without `kid` "signed by a key I have since retired" and "forged" both present as "nothing in my set verifies this". Both attributes are inside the canonical signed form, so an attacker cannot rewrite `kid` to name a key they control, or downgrade `version` to reach an older verification path, without invalidating the signature.
- **Boundary-escape protection.** Each fence carries a 128-bit random `nonce` (from `crypto/rand`). An attacker who controls fetched content cannot guess the nonce, so they cannot forge a closing tag that prematurely ends the fence or open a new "trusted" fence inside it. The awareness preamble tells the consuming model to honour only the boundary identified by the per-response nonce.
- **Forward-compatible signatures.** Every fence carries an Ed25519 signature so a future fence-verifying client (or an external verifying gateway) can authenticate that fenced content was emitted by this specific server process. The signed bytes are a domain-separated, length-prefixed serialisation — `"PromptFence/v1.0" || 0x00 || uint64_be(len(content)) || content || canonical_metadata` — fed to PureEd25519 per RFC 8032 §5.1 (the signing operation hashes the message internally with SHA-512; we do not pre-hash). This is a deliberate deviation from paper §4.3's literal `Ed25519(SHA-256(C || M))` construction, which silently changes the security argument by feeding a 32-byte digest into a signature scheme that already hashes its input. The domain tag prevents cross-protocol signature confusion; the length prefix removes the boundary ambiguity a bare `content || canonical_metadata` concatenation would leave. Content is signed in its pre-XML-escape form, so a verifier xml-unescapes the parsed element body before verifying. The exact wire format is documented in the `fence.go` `computeFenceSignature` and `buildFenceSigningInput` comment blocks. **No MCP client currently verifies these signatures**; they are present for forward compatibility.

Limitations, stated honestly:

- Without a verifier, the signatures provide no cryptographic guarantee. Boundary-escape protection comes entirely from the per-response nonce.
- The Prompt Fencing paper measured 100% prevention of direct injection in their experimental setting (n=300 attempts across two frontier models), but that result depends on model compliance with the awareness preamble. Smaller or specialised models may behave differently.
- Semantic attacks — where untrusted content tries to *persuade* rather than *impersonate* — are not addressed by any fencing scheme.

**Public key.** The Ed25519 public key for the running server is exposed at `GET /fence/public-key` (HTTP mode, unauthenticated — a public key is by definition not a secret). The startup banner prints the same key's fingerprint, so the two can be cross-checked. That `fingerprint` field is also the value each fence carries as its `kid`, so a verifier can key its trusted-key set on it directly; the field is deliberately not renamed to `kid` in the endpoint response, since anything already parsing it expects `fingerprint`.

**Fence signing key.** By default the signing key is generated fresh at every process start, so the fingerprint changes across process lifetimes. That default is deliberate: without an external trust anchor (a CA, a published JWK set, a KMS), persisting a key would imply a continuity property this server cannot deliver on its own.

It is also of no use to a verifier. Anything that actually checks these signatures — a fence-verifying client, or the external security gateway of paper §4.5 — needs a key it can pin. Against a key that rotates every restart its only options are to re-fetch `/fence/public-key` at verification time, which reduces the check to "signed by whoever answered", or to re-pin a fingerprint by hand after every deploy.

Operators running such a verifier can therefore supply their own key, which puts the trust anchor in their KMS or secret store rather than in this process:

```bash
# PKCS#8 PEM — the usual choice for a mounted Secret
openssl genpkey -algorithm ed25519 -out fence.pem

# or a bare 32-byte seed, if an inline env var is easier to manage
# (any 32 bytes is a valid Ed25519 seed)
openssl rand -base64 32
```

```bash
FENCE_SIGNING_KEY_FILE=/etc/mcp-auth/fence-key    # mounted file
FENCE_SIGNING_KEY="$(openssl rand -base64 32)"    # or inline
```

The banner states which mode is active, so a misconfiguration is visible at a glance rather than only when a verifier starts rejecting fences:

```
fence key        3f9a1c7e2b4d8056 (persistent, from FENCE_SIGNING_KEY_FILE (PKCS#8 PEM))
fence key        a17c04e9b3f2d158 (ephemeral, rotates on restart)
```

Persistent mode also emits a `warn` line at startup, for the same reason widening the SSRF policy does: it reverses a deliberate default, and it extends the blast radius of a key leak from one process lifetime to "until the operator rotates". Rotate this key on whatever cadence you rotate your other signing material — there is no automatic expiry.

A multi-replica deployment gets a second benefit. Each replica otherwise generates its own key, so a verifier facing a load-balanced Service would have to trust every pod's key and re-learn them on every rollout. A shared key from one Secret means all replicas sign identically.

Two things a persistent key does **not** do, stated plainly:

- **It does not give you verification.** It makes verification *possible* by giving a verifier something stable to pin. Nothing in this server checks signatures, and a signature nobody verifies provides no guarantee regardless of how the key is managed.
- **It does not solve key distribution**, which is the harder half. A gateway that fetches whatever `/fence/public-key` currently returns is trusting the very endpoint it is trying to authenticate: an attacker who can impersonate the relay serves their own key too. Pin the fingerprint out-of-band, or fetch it once over an authenticated channel and alert on change. Note also that stdio mode exposes no HTTP endpoints at all, so in that mode the public key has to come from the banner or be derived from the private key you already hold.

For high-risk deployments, consider restricting the tools to a known allowlist of domains, running the agent with a minimal permission scope, and auditing tool call sequences in your application layer.

**SSRF protection.** The URL fetch tool (`searxng_read_url`) resolves hostnames at TCP-dial time and rejects any address that is not a globally routable unicast IP. Two layers run on every dial and on every redirect hop:

1. Stdlib predicates: `IsLoopback`, `IsLinkLocalUnicast`, `IsLinkLocalMulticast`, `IsPrivate` (RFC 1918 + RFC 4193 ULA), `IsUnspecified`, `IsMulticast`, and `!IsGlobalUnicast` (which catches IPv4 directed broadcast).
2. A hardcoded list of reserved CIDRs the stdlib predicates miss, each annotated with the RFC that reserves it: `0.0.0.0/8` (RFC 1122), `100.64.0.0/10` CGNAT (RFC 6598), `192.0.0.0/24` IETF protocol assignments (RFC 6890), `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` TEST-NET-1/2/3 (RFC 5737), `192.88.99.0/24` deprecated 6to4 anycast (RFC 7526), `198.18.0.0/15` benchmark (RFC 2544), `240.0.0.0/4` future-reserved including `255.255.255.255` (RFC 1112), `64:ff9b::/96` and `64:ff9b:1::/48` NAT64 (RFC 6052/8215), `100::/64` discard prefix (RFC 6666), `2001::/32` Teredo (RFC 4380), `2001:2::/48` IPv6 benchmark (RFC 5180), `2001:10::/28` and `2001:20::/28` ORCHID/ORCHIDv2 (RFC 4843/7343), `2001:db8::/32` documentation (RFC 3849), `2002::/16` 6to4 (RFC 3056).

Both checks run before any byte hits the wire, and the redirect chain is revalidated at each hop, so an attacker who controls DNS for a public-looking host cannot rebind to an internal address between the check and the connect.

*Reaching internal resources (opt-in).* The default above blocks all non-public addresses, which is the right posture for a tool that fetches attacker-influenced URLs. Operators who run the relay inside a trusted network and want it to read internal resources — a self-hosted Confluence, Jira, GitLab, or wiki — can widen the policy with two allow-lists, **both empty by default** (so the default behaviour is unchanged):

- `FETCH_ALLOWED_HOSTS` — exact `host:port` entries that skip the public-IP check. The match is on the *request* hostname, not a resolved IP, so you can name an internal host without pinning its address; the caller cannot forge it (the hostname comes from the URL an authenticated caller asked for) and you control DNS for your own names, so this does not reopen the rebinding hole. Matching is case- and trailing-dot-insensitive and exact — `confluence.corp:443` does **not** match `sub.confluence.corp:443`.

  **The port is mandatory.** Write `host:port`; a bare hostname is a startup error. This is because allow-listing a hostname alone would hand the fetch tool whatever *else* that machine is listening on — Redis on 6379, etcd on 2379, a kubelet on 10250. An authenticated caller only has to ask for `http://confluence.corp:6379/`, and a redirect from the allow-listed service reaches the same places. Naming the port makes you state the reach you actually intend:

  ```
  FETCH_ALLOWED_HOSTS=confluence.corp:443,wiki.internal:8443
  ```

  **You do not have to spell the port out in URLs.** The entry is compared against the request's *effective* port, with the scheme default filled in first, so `confluence.corp:443` matches a plain `https://confluence.corp/page` and `wiki.internal:80` matches `http://wiki.internal/page`. A host serving both schemes needs both entries (`wiki.internal:80,wiki.internal:443`); ports accumulate per host rather than overwriting.

  IPv6 literals take the bracketed URL form: `[fd00::1]:8443`.

  A bad entry — no port, an empty or out-of-range port, or a value that is really a URL — fails startup with a message naming the entry and the form expected. It is never silently dropped: an allow-list line that parses but can never match is the worst outcome available here, because you would believe access was granted and the fetch would fail far from the config that caused it.
- `FETCH_ALLOWED_CIDRS` — IP ranges treated as reachable, written `range/prefix:port`. Checked against the *resolved* IP at dial time and on every redirect hop, so it remains rebinding-safe: an attacker who rebinds a public-looking name to a private IP is still blocked unless that exact IP falls inside a range you listed, on a port you listed.

  **The port is mandatory here too, and it matters more than it does for hostnames.** A hostname names one machine, so the port was the whole of its exposure. A range already covers many machines, and leaving the port open multiplies that by 65535:

  | Entry | Addresses | Reachable address:port pairs |
  |---|---:|---:|
  | `10.1.2.0/24:443` | 256 | 256 |
  | `10.1.2.0/24` *(rejected)* | 256 | 16,776,960 |
  | `10.0.0.0/8:443` | 16,777,216 | 16,777,216 |
  | `10.0.0.0/8` *(rejected)* | 16,777,216 | 1,099,494,850,560 |

  IPv6 works the same way — `fd00:1234::/64:8443`. The colons are not ambiguous: a CIDR always ends in `/<prefixlen>`, and a prefix length is digits only, so the port is whatever follows the last colon after the slash.

  **A default route is refused, not warned about.** `0.0.0.0/0` or `::/0` does not widen the address policy, it removes it — loopback, link-local and the cloud metadata endpoint all become reachable, and the fetch tool is left with no address restriction at all. If enforcement genuinely belongs somewhere else, say so with `FETCH_PROXY_ALL`, which is explicit about the delegation.

  **Width is reported, not capped.** Every allowed range is logged at startup with the number of addresses it covers, and separately if it sweeps in a sensitive address:

  ```
  WARN fetch allow-list covers an IP range cidr=10.0.0.0/8 addresses=16777216 ports=443
  WARN fetch allow-list covers a sensitive address cidr=169.254.0.0/16 address=169.254.169.254
       what="cloud metadata endpoint (IMDS) — hands out instance credentials"
  ```

  A flat internal `/8` is unusual but real, and refusing it would push operators to `FETCH_PROXY_ALL` — which stops the relay resolving destinations at all. A wide-but-visible range is the better outcome. The distinction the warning draws is deliberate versus swept-up: `127.0.0.1/32:8080` is someone who meant it; a `/8` that happens to contain link-local is someone who did not look.

  **Prefer `FETCH_ALLOWED_HOSTS` where you can.** A hostname names the one service you meant. Reach for a range only when you genuinely cannot pin the names.

The two are independent (OR semantics): a fetch is permitted if its host and port are allow-listed, **or** its resolved IP is public, **or** its resolved IP and port are inside an allowed CIDR entry. Both are re-evaluated on every redirect hop, so an open redirect on an allow-listed host still cannot pivot to a blocked internal address — nor, when the entry is port-scoped, to a different port on the allow-listed host itself.

Two cautions when using these:

- An allowed CIDR overrides *all* default blocks for the addresses it covers, **including loopback and link-local**. Listing a range is an explicit statement that it is safe to reach. Keep ranges tight — in particular, do not list `169.254.0.0/16` unless you truly intend to expose the cloud metadata endpoint at `169.254.169.254`.
- A malformed CIDR fails startup with a clear error rather than being silently dropped — a typo in a security control should stop the server, not quietly widen or narrow it.

When either list is non-empty the startup banner reflects the widened policy (a `fetch policy` row plus the exact `allowed hosts` / `allowed cidrs` you configured), and a `warn`-level audit line is emitted, so it is obvious from the logs that the fetch tool can now reach internal targets and precisely which ones.

*Reaching resources through an egress proxy (opt-in).* Some networks give the relay no route to an internal segment, or no direct route outward at all; the only way through is a forward proxy. Two more variables opt in, both unset by default:

- `FETCH_PROXY` — the proxy URL. On its own it applies **only** to hosts on `FETCH_ALLOWED_HOSTS`. This costs nothing in enforcement: allow-listed hosts already skip the per-IP check by design, so routing them via a proxy gives up nothing that was still running. Every other fetch continues to be dialled directly with the full public-IP policy in force.
- `FETCH_PROXY_ALL` — route *every* fetch through the proxy. This is for deployments with no direct egress, where the alternative is not a stricter posture but a non-functioning tool. Understand it as a delegation: the proxy performs the connection and therefore the DNS resolution, so the relay never learns the destination IP, and `assertPublicIP` and `FETCH_ALLOWED_CIDRS` stop participating. Your egress proxy becomes the enforcement point. Redirect hops are likewise left to the proxy (the hop limit still applies), because a local lookup could not constrain them and such networks often give the relay no resolver at all.

Neither variable is read from the ambient `HTTP_PROXY` / `HTTPS_PROXY`. Those get set by base images, CI systems, and cluster admission controllers for unrelated reasons, and honouring them here would let a variable nobody set for this purpose silently change a security control; they also carry the opposite default (proxy everything except `NO_PROXY`) to this subsystem's default-deny stance. The SearXNG client still honours them, since its single destination is operator-controlled and carries no SSRF exposure.

Two notes:

- Dials to the configured proxy skip the per-IP check — naming it in `FETCH_PROXY` is itself the statement that it is safe to reach, and requiring `10.0.0.0/8` in `FETCH_ALLOWED_CIDRS` just to reach a proxy would be a far worse trade. A fetch whose *target* URL names the proxy is refused, so this exemption cannot be reached from a caller-supplied URL.
- A proxy scoped to allow-listed hosts logs at `info`. `FETCH_PROXY_ALL` emits a `warn`-level audit line, and both appear as a `fetch proxy` row in the startup banner with any password in the URL redacted.

**Authentication.** Incoming `Authorization` headers are run through SHA-256 once and looked up in an in-memory table keyed by the SHA-256 of each configured `"Bearer <token>"`. The lookup operates on fixed-length 32-byte keys, so it cannot leak token length via response-timing differences (a bare byte-by-byte equality check would short-circuit at the first differing byte). Only digests sit in process memory after startup — the raw tokens are only ever read from the env / token file during parsing. Tokens themselves never appear in logs; the startup banner shows only the count of configured tokens and distinct identities. On successful match, the identity associated with that token is attached to the request context and recorded in every tool-call log line (`identity=<name>`) for audit correlation.

**Cross-origin protection.** The Streamable HTTP transport is wrapped in Go's `net/http.CrossOriginProtection` by the go-sdk (v1.4.1+, applied as the fix for CVE-2026-33252 — "Cross-Site Tool Execution for HTTP Servers without Authorization"). Browser-originated POSTs whose `Sec-Fetch-Site` or `Origin` headers indicate a cross-origin request are rejected, as are POSTs without `Content-Type: application/json`. Non-browser clients — `curl`, Go `http.Client`, AI-agent traffic — send neither `Sec-Fetch-Site` nor `Origin` and pass through unaffected, so legitimate remote-agent usage is unimpacted. This is in addition to bearer-token authentication, not a substitute: the cross-origin check fires before request processing, but any request that survives it still has to present a valid token to reach the MCP handler.

**Container hardening.** The Docker image runs as a non-root user (UID 1001) on a minimal `scratch` base — the runtime image contains only the statically linked binary and CA certificates, with no shell, package manager, or OS userland.

**PDF and Office safety.** PDF extraction uses `pdf_oxide` and Office extraction (DOCX/XLSX/PPTX + legacy DOC/XLS/PPT) uses `office_oxide`, both of which are Rust cores that guarantee zero panics and zero timeouts across all inputs. A malformed or adversarially crafted document will return an error, not crash the server process.

**Reporting and provenance.** Security issues should be reported privately — see [`SECURITY.md`](docs/SECURITY.md) for the disclosure process and scope. The codebase is primarily AI-generated and reviewed, built, and tested by a single human maintainer before release; [`supply-chain.md`](docs/supply-chain.md) is the full dependency, build-provenance, and development-process statement, written for reviewers evaluating the project for a controlled environment.

---

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

---

## Session limits

In HTTP mode the server caps concurrent sessions at 1,000. Requests to initialise beyond this limit receive a `503 Service Unavailable` response. Sessions are removed when the client sends a `DELETE` request.

---

## Operations

Notes for running the server in production. Most of this lives in the code and the comments, but it is the kind of detail an operator needs *before* the first incident, not after.

### Health endpoint

`GET /health` is an unauthenticated liveness + readiness probe. It returns:

| Status | Body | Meaning |
|---|---|---|
| `200 OK` | `{"status":"ok","searxng":"reachable"}` | Server is running and the upstream SearXNG instance answered with HTTP < 500. |
| `503 Service Unavailable` | `{"status":"degraded","searxng":"unreachable"}` | Server is running but the upstream SearXNG probe failed. |

The upstream-reachability result is cached for 10 seconds so a polling load balancer does not hammer SearXNG. The endpoint is **open by default** (probes do not need to ship a bearer token) and intentionally not rate-limited (a high-frequency LB poller should never get 429 from `/health`).

**Optionally requiring a token.** Set `MCP_HEALTH_TOKEN` to gate `/health` behind a bearer token — useful when the endpoint is reachable beyond the local host, since an open `/health` both discloses upstream-reachability status and (once per 10 s cache window) triggers a probe against SearXNG. The token is a **separate secret** from the MCP bearer tokens: the probe and the MCP endpoint are different trust domains, so they must not share a credential. It is validated against the same 32-character minimum, and a too-short value fails startup.

> **⚠️ If you set `MCP_HEALTH_TOKEN`, every prober must send it.** The token is enforced for *all* callers of `/health`, so any health checker that does not present `Authorization: Bearer <token>` will start getting `401` and mark the service unhealthy. That includes external load balancers, uptime monitors, and Kubernetes `httpGet` probes. The one prober wired up automatically is the container `--healthcheck` self-probe, which reads the same env var (see below). For a Kubernetes `httpGet` probe, add the header explicitly:
>
> ```yaml
> readinessProbe:
>   httpGet:
>     path: /health
>     port: http
>     httpHeaders:
>       - name: Authorization
>         value: Bearer <your-health-token>
> ```

The included [`deployment.yaml`](deploy/kubernetes/deployment.yaml) uses `/health` only as the readiness probe; liveness is a plain TCP-socket probe. This is deliberate: a transient SearXNG outage should not cascade into kubelet killing the pod, only into traffic being routed away until SearXNG recovers. (A TCP-socket liveness probe needs no `Authorization` header even when `MCP_HEALTH_TOKEN` is set, since it never hits `/health`.)

### `--healthcheck` CLI flag

The container `HEALTHCHECK` directive in the [`Dockerfile`](Dockerfile) invokes `mcp-searxng-relay --healthcheck`, which is a self-probe: the binary makes a single `GET` to `http://127.0.0.1:$MCP_PORT/health` with a 5-second timeout, exits `0` if the response is `200`, and exits `1` otherwise. The flag exists because the `scratch` runtime image has no shell, `curl`, or `wget` to write a conventional probe with — the binary has to be its own probe. When `MCP_HEALTH_TOKEN` is set, the self-probe reads that same env var and sends the `Authorization: Bearer` header automatically, so a single environment entry covers both the server and its own probe.

This is for plain `docker run` / Compose deployments. Kubernetes uses the HTTP probes in `deployment.yaml` and ignores the `HEALTHCHECK` directive.

### Graceful shutdown

On `SIGTERM` or `SIGINT` the server stops accepting new connections, then gives in-flight requests up to **30 seconds** to complete before exiting. The session janitor (stateful mode) is stopped at the same time. If the drain window expires with requests still in flight, the process exits non-zero.

Two deployment knobs interact with this:

- **Kubernetes `terminationGracePeriodSeconds`.** Defaults to 30s on most clusters, which exactly matches the drain timeout — leaving zero margin for kubelet to deliver SIGTERM, the server to receive it, and the response to flush. Set `terminationGracePeriodSeconds: 45` (or higher) on the Pod spec so the drain has a real chance to finish.
- **Compose `stop_grace_period`.** Defaults to 10s, which is shorter than the server's drain timeout. Set `stop_grace_period: 45s` on the service so SIGKILL does not arrive mid-drain.

For multi-replica deployments behind an Ingress or load balancer, the LB needs to deregister the Pod before SIGTERM arrives — otherwise traffic continues arriving during the drain window. Kubernetes handles this automatically once readiness probes start failing, which is one reason `/health` is the *readiness* probe and not the liveness one.

### HTTP server timeouts

The server's stdlib `http.Server` is configured with three deliberate values:

| Setting | Value | Reason |
|---|---|---|
| `ReadTimeout` | `30s` | Bounds how long a slow client can hold the request-line, headers, and body read. Long enough for typical JSON-RPC bodies; short enough to discourage slowloris-style attacks. |
| `WriteTimeout` | **disabled (`0`)** | The go-sdk manages per-stream deadlines for SSE responses. A server-level write deadline would prematurely close long-lived event streams during tool calls that take more than a few seconds. |
| `IdleTimeout` | `120s` | Keepalive idle window. Above typical client think-time between tool calls; below the point at which dead connections accumulate. |

When fronting the server with a reverse proxy (recommended for any non-local deployment — see [Security notes](#security-notes)), the proxy's own timeouts must accommodate streaming responses:

- **nginx.** Set `proxy_read_timeout` and `proxy_send_timeout` to at least the longest tool-call wall time you expect — a reasoning agent over a large PDF or Office document can take 30+ seconds. Disable `proxy_buffering` for the MCP route so SSE chunks reach the client immediately.
- **Caddy.** The bundled [`Caddyfile`](deploy/podman/Caddyfile) sets `flush_interval -1` on the MCP reverse_proxy directive, which is what disables Caddy's response buffering for streaming.
- **Traefik.** Use the `forwardingTimeouts.responseHeaderTimeout` field and ensure the entrypoint is not configured with an aggressive idle timeout.

If you see tool calls failing with truncated SSE streams in a reverse-proxy deployment, the proxy's read/write timeout is almost always the cause, not the relay's.

---

## Building the Docker image

```bash
docker build -t mcp-searxng-relay .
```

The multi-stage build compiles the binary on the digest-pinned `golang:1.26.6-trixie` builder and copies only the static binary and CA certificates into a `scratch` runtime image.

---

## Logging

All log output goes to **stderr**. Set `LOG_FORMAT=json` for structured logging compatible with log aggregators.

On startup the server prints a configuration banner to stderr regardless of log level. The banner lists all active settings with secrets redacted. `AUTH_USERNAME` is only shown when it is set.

```
######################################################################################################################

mcp-searxng-relay v1.0.0

######################################################################################################################

mode             streamable-http
address          :3000
searxng          http://searxng:8080
password         [not set]
user-agent       Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
cache ttl        5m0s
cache entries    1000 max
body limit       500000 bytes
pdf limit        50000000 bytes
office limit     50000000 bytes
image limit      7500000 bytes
log level        info
log format       text
session mode     stateless
auth tokens      3 configured (3 identities)
rate limit       5 rps, burst 10
fence key        3e21267250e41cbb

######################################################################################################################
```

Once the server is running, typical log lines look like this (stateful mode, `LOG_FORMAT=text`):

```
time=2026-05-24T07:41:10.301Z level=INFO msg="url fetched" url=https://github.com/asgeirtj/system_prompts_leaks content_type="text/html; charset=utf-8" bytes_raw=372821 chars_extracted=5469
time=2026-05-24T07:41:10.302Z level=INFO msg="fetch completed" url=https://github.com/asgeirtj/system_prompts_leaks kind=text identity=zed session_id=O3GD67SQIYXDYN57XCVQMZYKDI
time=2026-05-24T07:43:39.212Z level=INFO msg="search completed" query="site:github.com/asgeirtj/system_prompts_leaks \"Claude Code\" system prompt" page=1 results=10 categories="" identity=zed session_id=O3GD67SQIYXDYN57XCVQMZYKDI
time=2026-05-24T07:43:52.249Z level=INFO msg="url fetched" url=https://github.com/asgeirtj/system_prompts_leaks/blob/main/Anthropic/claude-code.md content_type="text/html; charset=utf-8" bytes_raw=500000 chars_extracted=185
time=2026-05-24T07:43:52.253Z level=INFO msg="fetch completed" url=https://github.com/asgeirtj/system_prompts_leaks/blob/main/Anthropic/claude-code.md kind=text identity=zed session_id=O3GD67SQIYXDYN57XCVQMZYKDI
time=2026-05-24T07:44:07.656Z level=INFO msg="url fetched" url=https://raw.githubusercontent.com/asgeirtj/system_prompts_leaks/main/Anthropic/claude-code.md content_type="text/plain; charset=utf-8" bytes_raw=58874 chars_extracted=58873
time=2026-05-24T07:44:07.657Z level=INFO msg="fetch completed" url=https://raw.githubusercontent.com/asgeirtj/system_prompts_leaks/main/Anthropic/claude-code.md kind=text identity=zed session_id=O3GD67SQIYXDYN57XCVQMZYKDI
```

A search where some SearXNG backends failed is not an error — the upstream answers `200` with whatever the surviving engines produced — but it is a degraded answer, and it is logged as one:

```
level=WARN msg="searxng search was degraded: some engines did not respond"
  unresponsive_engines=google,bing unresponsive_count=2
  detail="google: Suspended: Access denied; bing: timeout"
  query="..." results=7
  hint="results are incomplete; check the named engines in your SearXNG instance
        before treating thin results as a relay or model problem"
```

Engines break — upstream markup changes, an API is deprecated, a captcha wall goes up — and SearXNG suspends them and carries on. Without this line the degradation is invisible all the way up the stack: fewer results reach the agent, its answers get worse, and nothing anywhere says why. Deployments with many engines configured will see intermittent entries as engines cycle through suspension; that is noise worth having, because the alternative is silence.

The `session_id` field joins each tool call back to the `"session initialized"` line where the client's `identity` was first recorded; combined they form the audit trail. The `"unauthorized request"` line shows what a failed bearer-token attempt looks like — the rejected `Authorization` value is never logged, only the remote address. In `LOG_FORMAT=json` the same fields appear as a flat JSON object per line, which is what most log aggregators expect.

---

## Metrics

In HTTP mode, `GET /metrics` returns Prometheus text-format counters, gated by `MCP_METRICS_TOKEN`.

> **⚠️ `MCP_METRICS_TOKEN` is required to scrape.** With it unset, `/metrics` returns `401` to *every* caller — including one holding a valid MCP token. Set it to a value from `openssl rand -hex 32` and give that value to your scraper:
>
> ```
> MCP_METRICS_TOKEN=<openssl rand -hex 32>
> ```
>
> **It must not be one of your MCP tokens.** `mcp_fetches_by_domain_total` names up to 512 destination hostnames this relay has fetched, across *all* callers. Served to the MCP token table, that lets each tenant read which hosts every other tenant has been reading — and on a relay with `FETCH_ALLOWED_HOSTS` configured, those are your internal hostnames. A scraper is not a tenant and a tenant is not a scraper; the credential separates them in both directions.
>
> The endpoint is closed rather than open by default because a boundary that only exists once configured is not a boundary — it would silently fail to hold on every deployment that had not yet read this paragraph. `/health` takes the opposite default (open unless `MCP_HEALTH_TOKEN` is set) because it discloses two fixed fields, not the fleet's egress profile.
>
> The startup banner's `metrics auth` row reports `CLOSED` when no token is set, and the server logs a warn line at startup saying so, so a blank dashboard is diagnosable from this end rather than from the scraper's.


The exposed series are:

| Series | Labels | Notes |
|---|---|---|
| `mcp_searches_total` | — | All calls to `searxng_web_search` |
| `mcp_search_errors_total` | — | Subset of the above that returned an error |
| `mcp_metadata_total` | — | All calls to `searxng_url_metadata` |
| `mcp_metadata_errors_total` | — | Subset of the above that returned an error |
| `mcp_session_sources_total` | — | All calls to `searxng_session_sources`. Read as a ratio against `mcp_fetches_total`: it says how often agents verify their URLs before answering |
| `mcp_session_sources_elided_total` | — | Calls that returned an incomplete list, i.e. an agent may have answered against a record that no longer held everything it read. Persistently non-zero is the signal to raise `MCP_HISTORY_ENTRIES` |
| `mcp_history_evictions_total` | — | Sources dropped from a caller's history to make room. Says how far past the cap callers run; on its own it can be one busy caller that never reads its list back, so tune on the elided counter above |
| `mcp_fetches_total` | — | All calls to `searxng_read_url` |
| `mcp_fetch_errors_total` | — | Subset that returned an error |
| `mcp_fetches_by_type_total` | `type=html\|pdf\|office\|plain\|image` | Successful fetches by extractor used |
| `mcp_fetches_by_domain_total` | `domain=<host>`, `outcome=success\|error` | Per-domain success/failure counters |
| `mcp_cache_hits_total` | — | `searxng_read_url` requests served from cache |
| `mcp_cache_misses_total` | — | Requests that fell through to a network fetch |
| `mcp_cache_force_refresh_total` | — | Requests with `force_refresh=true` |
| `mcp_rate_limit_rejections_total` | — | HTTP requests rejected by the per-caller rate limiter (429 responses). Rejection details — identity, remote, retry — are in the structured WARN log; no per-identity label here by design |
| `mcp_active_sessions` | — | Gauge: current live MCP sessions (stateful mode only) |
| `mcp_search_duration_seconds` | `le` | Histogram: SearXNG search round-trip latency. Buckets from 50ms to 30s |
| `mcp_fetch_duration_seconds` | `le` | Histogram: URL fetch pipeline latency (dial through extraction), observed for both `searxng_read_url` and `searxng_url_metadata`. Includes cache hits, which land in the lowest bucket — alert on upper quantiles (e.g. `histogram_quantile(0.99, ...)`) and read the p50 alongside `mcp_cache_hits_total`. The top bucket matches the 30s fetch client timeout, so `+Inf` observations are timeout-adjacent requests |

### Per-domain cardinality

`mcp_fetches_by_domain_total` is bounded to 512 distinct domains. Once that cap is reached, additional unique destinations are aggregated under the synthetic label value `domain="__overflow__"` rather than expanding the label set further. The cap is a deliberate design choice: an agent fetching many unique hosts shouldn't be able to grow process memory or Prometheus's index without bound.

If the overflow counter is non-zero in your environment, either your agent fleet legitimately touches more than 512 domains (in which case raise `maxTrackedDomains` in `metrics.go` and rebuild) or something is wrong with the queries you're handing the tool (in which case the overflow is doing its job by signalling that). Operators who want a full audit of every URL fetched should rely on the structured fetch log lines (`url=…`) rather than the metrics counter; the metric is observability, not provenance.

### What the per-domain metric is *not*

It is not a blocklist input that the server reads back. The project does not auto-block domains based on failure rates — that decision belongs to the operator. The intended workflow is: operator reviews the per-domain failure counts in their Prometheus / Grafana setup, decides which (if any) hosts to drop, and updates their static configuration accordingly. Compared to a system that mutates its own behaviour, this keeps the server's behaviour at any given moment a function of its config alone, which is what makes it auditable.
