# mcp-searxng-relay

A Model Context Protocol (MCP) server giving AI agents web search and URL fetching through your own self-hosted [SearXNG](https://github.com/searxng/searxng) instance — built for environments where search must stay on approved infrastructure and every query must be auditable. No third-party search APIs, no external data brokers; queries never leave infrastructure you control.

**Who this is for.** Teams running AI agents in corporate or government environments where outbound search is restricted, monitored, or both — and where "we use a hosted search API" is not an acceptable answer. The project prioritizes a defensible security posture and a clean audit trail over breadth of features. 

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
- [Using with Claude Desktop (stdio mode)](#using-with-claude-desktop-stdio-mode)
- [Using with Claude Desktop (HTTP mode)](#using-with-claude-desktop-http-mode)
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

- **Web search** via SearXNG with full control over language, category, time range, safe-search level, and result count
- **URL fetching** with structured Markdown output — headings, lists, tables, code blocks, and inline emphasis all preserved
- **URL metadata triage** — `searxng_url_metadata` returns just title, author, publish date, language, site name, description, image, categories, and tags as JSON, at roughly an order of magnitude lower token cost than fetching the full body. Useful for picking which of several candidate URLs to read in full. Cache is shared with `searxng_read_url`, so a metadata fetch followed by a content fetch (or vice versa) costs one upstream HTTP request, not two.
- **PDF text extraction** from fetched URLs
- **Image responses** — JPEG, PNG, GIF, and WebP URLs come back as MCP `ImageContent` blocks for vision-model consumption (the SDK base64-encodes the raw bytes on the wire). SVG is intentionally excluded — more useful to the model as text than as a binary blob. Raw size is capped by `MAX_IMAGE_BYTES`, separately from `MAX_BODY_BYTES`, so image and text limits can be tuned independently.
- **Automatic charset detection** — non-UTF-8 pages (Shift-JIS, windows-1252, ISO-8859-1, …) are decoded correctly before parsing
- **Readability-style content extraction** — navigation bars, footers, sidebars, and cookie banners are stripped automatically
- **Engine attribution on search results** — each result includes the list of SearXNG backend engines that returned it. A URL surfaced by three engines is a different signal than one surfaced by one, and the agent can weigh that without the server imposing a ranking on top.
- **Per-domain fetch metrics** — `/metrics` exposes `mcp_fetches_by_domain_total{domain="…",outcome="success|error"}` so an operator can see which destination hosts are healthy and which aren't. Bounded cardinality: at most 512 distinct domains tracked, with the remainder rolled up under `domain="__overflow__"`.
- **Response caching** with configurable TTL and per-request cache bypass
- **SSRF protection** — non-globally-routable addresses are blocked at TCP-dial time (loopback, link-local, private, multicast, broadcast, unspecified, plus a hardcoded blocklist covering CGNAT, TEST-NET-{1,2,3}, benchmark, IETF protocol assignments, NAT64, Teredo, 6to4, IPv6 documentation, ORCHID, the discard prefix, future-reserved 240/4, and other reserved ranges the stdlib predicates miss). Redirect chains are revalidated at every hop to close the DNS-rebinding window.
- **Bearer token authentication** with multi-token tables (`MCP_AUTH_TOKEN`, `MCP_AUTH_TOKENS`, or `MCP_AUTH_TOKEN_FILE`) and per-identity audit logging
- **Per-caller rate limiting** — token-bucket throttle keyed by identity when authenticated and by source IP otherwise. Configurable RPS and burst, default 5 rps / burst 10. Exposed at `mcp_rate_limit_rejections_total`.
- **Prompt fencing** — every tool response is wrapped in a signed `<sec:fence>` element with a per-response random nonce, implementing arXiv:2511.19727. Public key exposed at `/fence/public-key` for forward compatibility with verifying clients.
- **Reproducible container builds** — bit-for-bit. Given the same source commit and `SOURCE_DATE_EPOCH`, the build produces a byte-identical image, verifiable via `docker save <image> | sha256sum`. Toolchain pinned by digest, `go.sum` frozen, no embedded paths, VCS state, or build IDs. Details in [`docs/supply-chain.md`](docs/supply-chain.md).
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
  ghcr.io/your-org/mcp-searxng-relay:latest
```

### Docker Compose

```yaml
services:
  mcp-searxng:
    image: ghcr.io/your-org/mcp-searxng-relay:latest
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

The multi-stage build compiles the binary on a digest-pinned `golang:1.26.3-trixie` builder and copies only the static binary and CA certificates into a `scratch` runtime image.

**Reproducibility.** Given the same source commit and `SOURCE_DATE_EPOCH` (canonically the commit's own timestamp), either invocation produces a byte-identical image — verifiable via `docker save <image> | sha256sum` or `podman save <image> | sha256sum`. The toolchain is pinned by content digest, the module graph is frozen by `go.sum`, and the build sets `-trimpath`, `-buildvcs=false`, `-buildid=`, and `-Wl,--build-id=none` so neither paths, VCS state, nor link-time build IDs leak into the binary. BuildKit's `rewrite-timestamp` and Podman's `--timestamp` both pin all layer file timestamps to the same value so the image envelope is reproducible, not just the binary inside. See [`docs/supply-chain.md`](docs/supply-chain.md) for the full provenance statement and verification steps.

Note that Docker and Podman use slightly different on-disk manifest encodings, so images built with one and saved through the other will not have matching SHA-256s even when functionally identical. Pick a build tool and stick with it for cross-machine reproducibility checks.

### Kubernetes

Ready-to-apply manifests are included in the repository root: [`deployment.yaml`](deployment.yaml) with a locked-down `securityContext`, [`service.yaml`](service.yaml), [`kustomization.yaml`](kustomization.yaml), and [`secret_example.yaml`](secret_example.yaml) as a template for `MCP_AUTH_TOKEN_FILE`. Apply with `kubectl apply -k .` after creating a real Secret out-of-band from `secret_example.yaml` — copy it to `secret.yaml`, fill in tokens generated with `openssl rand -hex 32`, and apply that file once before the `kubectl apply -k .` (it is deliberately not listed in `kustomization.yaml` so a re-apply cannot roll a real Secret back to the placeholder values). The `Deployment` defaults to a single replica in stateful mode for audit-friendly behaviour; switch to stateless multi-replica by setting `MCP_STATELESS=true` and scaling `replicas`. For integration with external secret stores (External Secrets Operator, Sealed Secrets, CSI Secrets Store), replace the Secret with the appropriate resource in your own overlay.

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
| `MCP_STATELESS` | no | `false` | If `true`, the SDK skips session-ID validation and treats each request as a fresh temporary session. See "Session modes" below |
| `MCP_SESSION_MAX_AGE` | no | `168h` | Stateful mode only. How long a session may live before the janitor closes it. Go duration syntax (`30m`, `12h`, `168h` — no `d` or `w`) |
| `MCP_SESSION_JANITOR_INTERVAL` | no | `15m` | Stateful mode only. How often the janitor sweeps for expired sessions. Same duration syntax |
| `MCP_RATE_LIMIT_RPS` | no | `5` | Per-caller sustained request rate (requests/second). Set to `0` to disable. Fractional values supported (e.g. `0.5` = one request every two seconds) |
| `MCP_RATE_LIMIT_BURST` | no | `2 × RPS, min 1` | Token-bucket burst capacity — the number of requests a caller can fire back-to-back before the sustained rate kicks in |
| `MCP_RATE_LIMIT_EXEMPT` | no | — | Comma-separated identity names that bypass the rate limiter entirely (e.g. `ci,uptime-monitor`). Useful for trusted internal callers and monitoring identities |
| `AUTH_USERNAME` | no | — | HTTP Basic Auth username for SearXNG (if your instance requires it) |
| `AUTH_PASSWORD` | no | — | HTTP Basic Auth password for SearXNG |
| `USER_AGENT` | no | `mcp-searxng-relay/<version>` | User-Agent header sent with all outbound requests |
| `CACHE_TTL_SECONDS` | no | `300` | How long fetched URL content is cached (seconds) |
| `CACHE_MAX_ENTRIES` | no | `1000` | Maximum number of URLs held in the in-memory cache. Oldest entries are evicted automatically when the cap is reached |
| `MAX_BODY_BYTES` | no | `500000` | Maximum response body size read from fetched URLs (bytes) |
| `MAX_PDF_BYTES` | no | `50000000` | Maximum response body size for PDF URLs (bytes). PDFs get a separate, larger limit since a multi-hundred-page document can easily be 50 MB |
| `MAX_IMAGE_BYTES` | no | `7500000` | Maximum raw size for image responses (bytes). The wire form is ~33% larger after base64 encoding |
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

Fetch a URL and return its content. Handles HTML (converted to structured Markdown), PDF (text extracted via `pdf_oxide`), plain text (charset-decoded), and images (JPEG, PNG, GIF, WebP returned as MCP `ImageContent` blocks for vision-model consumption — SVG is intentionally excluded, since it is more useful to the model as text than as a base64-encoded binary blob). Caches results by default; image responses bypass the text cache.

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `url` | string | **yes** | — | The URL to fetch (http/https only) |
| `force_refresh` | boolean | no | `false` | Bypass the cache and fetch a fresh copy |

**Example — force a fresh fetch:**
```json
{
  "url": "https://example.com/article",
  "force_refresh": true
}
```

---

### `searxng_url_metadata`

Fetch only the structured metadata for a URL — title, author, publish date, language, site name, description, image, categories, and tags — without returning the page body. Roughly an order of magnitude cheaper in tokens than `searxng_read_url`, and intended as a triage step before committing to read a candidate URL in full. Results are cached and the cache is shared with `searxng_read_url`: a metadata fetch followed by a content fetch (or vice versa) costs one upstream HTTP request, not two.

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

## Security notes

**Prompt injection.** Both tools return content sourced from the open web — titles, snippets, and page bodies written by third parties. A malicious site can embed instructions in that content (including in invisible or hidden elements) in an attempt to hijack the agent's behaviour, cause unexpected tool calls, or exfiltrate conversation context. This is the primary runtime risk when using this server with an LLM agent.

This server implements the prompt-fencing specification from [Peh, S. (2025), "Prompt Fencing: A Cryptographic Approach to Establishing Security Boundaries in Large Language Model Prompts" (arXiv:2511.19727)](https://arxiv.org/abs/2511.19727). Every tool response is wrapped in a `<sec:fence>` element with structured metadata, preceded by a short awareness preamble that tells the consuming model how to interpret the boundary:

```xml
<sec:fence xmlns:sec="http://promptfence.org/security/1.0"
           signature="MEYCIQDx5w2l7..."
           nonce="a9f7e2c14b8d6f31..."
           rating="untrusted"
           source="https://example.com/article"
           timestamp="2026-05-07T14:23:00Z"
           type="content">
<extracted content>
</sec:fence>
```

What this provides today:

- **Boundary-escape protection.** Each fence carries a 128-bit random `nonce` (from `crypto/rand`). An attacker who controls fetched content cannot guess the nonce, so they cannot forge a closing tag that prematurely ends the fence or open a new "trusted" fence inside it. The awareness preamble tells the consuming model to honour only the boundary identified by the per-response nonce.
- **Forward-compatible signatures.** Every fence carries an Ed25519 signature so a future fence-verifying client (or an external verifying gateway) can authenticate that fenced content was emitted by this specific server process. The signed bytes are a domain-separated, length-prefixed serialisation — `"PromptFence/v1.0" || 0x00 || uint64_be(len(content)) || content || canonical_metadata` — fed to PureEd25519 per RFC 8032 §5.1 (the signing operation hashes the message internally with SHA-512; we do not pre-hash). This is a deliberate deviation from paper §4.3's literal `Ed25519(SHA-256(C || M))` construction, which silently changes the security argument by feeding a 32-byte digest into a signature scheme that already hashes its input. The domain tag prevents cross-protocol signature confusion; the length prefix removes the boundary ambiguity a bare `content || canonical_metadata` concatenation would leave. Content is signed in its pre-XML-escape form, so a verifier xml-unescapes the parsed element body before verifying. The exact wire format is documented in the `fence.go` `computeFenceSignature` and `buildFenceSigningInput` comment blocks. **No MCP client currently verifies these signatures**; they are present for forward compatibility.

Limitations, stated honestly:

- Without a verifier, the signatures provide no cryptographic guarantee. Boundary-escape protection comes entirely from the per-response nonce.
- The Prompt Fencing paper measured 100% prevention of direct injection in their experimental setting (n=300 attempts across two frontier models), but that result depends on model compliance with the awareness preamble. Smaller or specialised models may behave differently.
- Semantic attacks — where untrusted content tries to *persuade* rather than *impersonate* — are not addressed by any fencing scheme.

**Public key.** The Ed25519 public key for the running server is exposed at `GET /fence/public-key` (HTTP mode, unauthenticated — a public key is by definition not a secret). The signing key is regenerated on every server restart, so the key fingerprint changes across process lifetimes. Operators who need stable verification across restarts should run the server behind a supervisor that holds a long-lived key — out of scope for this server.

For high-risk deployments, consider restricting the tools to a known allowlist of domains, running the agent with a minimal permission scope, and auditing tool call sequences in your application layer.

**SSRF protection.** The URL fetch tool (`searxng_read_url`) resolves hostnames at TCP-dial time and rejects any address that is not a globally routable unicast IP. Two layers run on every dial and on every redirect hop:

1. Stdlib predicates: `IsLoopback`, `IsLinkLocalUnicast`, `IsLinkLocalMulticast`, `IsPrivate` (RFC 1918 + RFC 4193 ULA), `IsUnspecified`, `IsMulticast`, and `!IsGlobalUnicast` (which catches IPv4 directed broadcast).
2. A hardcoded list of reserved CIDRs the stdlib predicates miss, each annotated with the RFC that reserves it: `0.0.0.0/8` (RFC 1122), `100.64.0.0/10` CGNAT (RFC 6598), `192.0.0.0/24` IETF protocol assignments (RFC 6890), `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` TEST-NET-1/2/3 (RFC 5737), `192.88.99.0/24` deprecated 6to4 anycast (RFC 7526), `198.18.0.0/15` benchmark (RFC 2544), `240.0.0.0/4` future-reserved including `255.255.255.255` (RFC 1112), `64:ff9b::/96` and `64:ff9b:1::/48` NAT64 (RFC 6052/8215), `100::/64` discard prefix (RFC 6666), `2001::/32` Teredo (RFC 4380), `2001:2::/48` IPv6 benchmark (RFC 5180), `2001:10::/28` and `2001:20::/28` ORCHID/ORCHIDv2 (RFC 4843/7343), `2001:db8::/32` documentation (RFC 3849), `2002::/16` 6to4 (RFC 3056).

Both checks run before any byte hits the wire, and the redirect chain is revalidated at each hop, so an attacker who controls DNS for a public-looking host cannot rebind to an internal address between the check and the connect.

**Authentication.** Incoming `Authorization` headers are run through SHA-256 once and looked up in an in-memory table keyed by the SHA-256 of each configured `"Bearer <token>"`. The lookup operates on fixed-length 32-byte keys, so it cannot leak token length via response-timing differences (a bare byte-by-byte equality check would short-circuit at the first differing byte). Only digests sit in process memory after startup — the raw tokens are only ever read from the env / token file during parsing. Tokens themselves never appear in logs; the startup banner shows only the count of configured tokens and distinct identities. On successful match, the identity associated with that token is attached to the request context and recorded in every tool-call log line (`identity=<name>`) for audit correlation.

**Cross-origin protection.** The Streamable HTTP transport is wrapped in Go's `net/http.CrossOriginProtection` by the go-sdk (v1.4.1+, applied as the fix for CVE-2026-33252 — "Cross-Site Tool Execution for HTTP Servers without Authorization"). Browser-originated POSTs whose `Sec-Fetch-Site` or `Origin` headers indicate a cross-origin request are rejected, as are POSTs without `Content-Type: application/json`. Non-browser clients — `curl`, Go `http.Client`, AI-agent traffic — send neither `Sec-Fetch-Site` nor `Origin` and pass through unaffected, so legitimate remote-agent usage is unimpacted. This is in addition to bearer-token authentication, not a substitute: the cross-origin check fires before request processing, but any request that survives it still has to present a valid token to reach the MCP handler.

**Container hardening.** The Docker image runs as a non-root user (UID 1001) on a minimal `scratch` base — the runtime image contains only the statically linked binary and CA certificates, with no shell, package manager, or OS userland.

**PDF safety.** PDF extraction uses pdf_oxide, whose Rust core guarantees zero panics and zero timeouts across all inputs. A malformed or adversarially crafted PDF will return an error, not crash the server process.

**Reporting and provenance.** Security issues should be reported privately — see [`docs/SECURITY.md`](docs/SECURITY.md) for the disclosure process and scope. The codebase is primarily AI-generated and reviewed, built, and tested by a single human maintainer before release; [`docs/supply-chain.md`](docs/supply-chain.md) is the full dependency, build-provenance, and development-process statement, written for reviewers evaluating the project for a controlled environment.

---

## Rate limiting

In HTTP mode the server applies a per-caller token-bucket rate limit to requests under `/`. Defaults are `5` requests per second sustained with a burst of `10` — comfortable for a single agent reasoning with the tools (typical pattern is 1–3 tool calls per agent turn with seconds of model think-time between) while still bounding the damage a runaway agent or leaked token can do. Set `MCP_RATE_LIMIT_RPS=0` to disable.

Buckets are keyed by **identity** when the request carries a recognised bearer token, and by **remote IP** otherwise. The fallback is intentional: an unauthenticated attacker brute-forcing tokens from a single host shares one IP-keyed bucket regardless of which token guess they present, so the limiter throttles the attack at the network edge rather than at the auth check. Authenticated callers are billed against their identity — multiple agents using the same token share one bucket, which is the right semantic for "this credential's usage budget."

Rejections return HTTP `429 Too Many Requests` with a `Retry-After` header containing an integer second count. Every rejection emits a structured WARN log line with `identity` (when known), `remote`, `method`, `path`, and `retry_after` so the audit trail records denied traffic the same way it records unauthorised traffic. The Prometheus counter `mcp_rate_limit_rejections_total` aggregates rejections for dashboards and alerting (no per-identity label by design — rejection events are already in the structured log when forensics needs them).

The bucket store is an LRU capped at 10,000 entries. Identities are bounded by the configured auth-token table so they all fit comfortably; the cap bounds memory under an IP-rotation attack, at the cost that evicted buckets reset to full on next contact (which doesn't materially affect throttling for distinct attackers).

**What this doesn't cover.** `/health` is never rate-limited so a polling load balancer can't be flagged as abusive. `/metrics` is also exempt — a scraper that's polling on a fixed interval shouldn't produce gaps in Prometheus that look like outages, and an abusive scraper is better contained by withholding the token than by 429-ing the metrics endpoint. `/fence/public-key` is unauthenticated and unthrottled (it's a public key, public). Stdio mode has no HTTP middleware and therefore no rate limit, but it's also a single trusted process with no remote attack surface.

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

The upstream-reachability result is cached for 10 seconds so a polling load balancer does not hammer SearXNG. The endpoint is intentionally unauthenticated (probes do not need to ship a bearer token) and intentionally not rate-limited (a high-frequency LB poller should never get 429 from `/health`).

The included [`deployment.yaml`](deployment.yaml) uses `/health` only as the readiness probe; liveness is a plain TCP-socket probe. This is deliberate: a transient SearXNG outage should not cascade into kubelet killing the pod, only into traffic being routed away until SearXNG recovers.

### `--healthcheck` CLI flag

The container `HEALTHCHECK` directive in the [`Dockerfile`](Dockerfile) invokes `mcp-searxng-relay --healthcheck`, which is a self-probe: the binary makes a single `GET` to `http://127.0.0.1:$MCP_PORT/health` with a 5-second timeout, exits `0` if the response is `200`, and exits `1` otherwise. The flag exists because the `scratch` runtime image has no shell, `curl`, or `wget` to write a conventional probe with — the binary has to be its own probe.

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

- **nginx.** Set `proxy_read_timeout` and `proxy_send_timeout` to at least the longest tool-call wall time you expect — a reasoning agent over a large PDF can take 30+ seconds. Disable `proxy_buffering` for the MCP route so SSE chunks reach the client immediately.
- **Caddy.** The bundled [`Caddyfile`](Caddyfile) sets `flush_interval -1` on the MCP reverse_proxy directive, which is what disables Caddy's response buffering for streaming.
- **Traefik.** Use the `forwardingTimeouts.responseHeaderTimeout` field and ensure the entrypoint is not configured with an aggressive idle timeout.

If you see tool calls failing with truncated SSE streams in a reverse-proxy deployment, the proxy's read/write timeout is almost always the cause, not the relay's.

---

## Building the Docker image

```bash
docker build -t mcp-searxng-relay .
```

The multi-stage build compiles the binary on `golang:1.26` (Debian) and copies only the static binary and CA certificates into a `scratch` runtime image.

---

## Logging

All log output goes to **stderr**. Set `LOG_FORMAT=json` for structured logging compatible with log aggregators.

On startup the server prints a configuration banner to stderr regardless of log level. The banner lists all active settings with secrets redacted. `AUTH_USERNAME` is only shown when it is set.

```
##################################################

mcp-searxng-relay   v1.6.0
mode             streamable-http
address          :8080
searxng          https://search.example.com
username         admin
password         [set]
user-agent       mcp-searxng-relay/v1.6.0
cache ttl        5m0s
cache entries    1000 max
body limit       500000 bytes
pdf limit        50000000 bytes
image limit      7500000 bytes
log level        info
log format       text
session mode     stateful
session max age  168h0m0s
janitor interval 15m0s
rate limit       5 rps, burst 10
auth tokens      3 configured (2 identities)
fence key        Ed25519 fp:a3f7e2c14b8d6f31

##################################################
```

Once the server is running, typical log lines look like this (stateful mode, `LOG_FORMAT=text`):

```
time=2026-05-13T20:00:00.001Z level=INFO msg="session janitor started" interval=15m0s max_age=168h0m0s
time=2026-05-13T20:14:22.118Z level=INFO msg="session initialized" session_id=JF7PTMDNI65MP5HNGE6XSZIKGB identity=alice
time=2026-05-13T20:14:25.402Z level=INFO msg="search completed" query="quantum computing breakthroughs 2026" page=1 results=10 categories=news identity=alice session_id=JF7PTMDNI65MP5HNGE6XSZIKGB
time=2026-05-13T20:14:31.815Z level=INFO msg="fetch completed" url="https://arxiv.org/abs/2511.19727" kind=text identity=alice session_id=JF7PTMDNI65MP5HNGE6XSZIKGB
time=2026-05-13T20:18:47.220Z level=WARN msg="unauthorized request" method=POST path=/ remote=203.0.113.42:51234
time=2026-05-13T23:14:22.103Z level=INFO msg="janitor closing idle session" session_id=JF7PTMDNI65MP5HNGE6XSZIKGB
time=2026-05-13T20:14:55.612Z level=WARN msg="rate limit exceeded" method=POST path=/ remote=192.168.1.23:51234 identity=alice retry_after=1s
```

The `session_id` field joins each tool call back to the `"session initialized"` line where the client's `identity` was first recorded; combined they form the audit trail. The `"unauthorized request"` line shows what a failed bearer-token attempt looks like — the rejected `Authorization` value is never logged, only the remote address. In `LOG_FORMAT=json` the same fields appear as a flat JSON object per line, which is what most log aggregators expect.

---

## Metrics

In HTTP mode, `GET /metrics` returns Prometheus text-format counters. Authentication applies (same bearer token as the tool endpoints).

The exposed series are:

| Series | Labels | Notes |
|---|---|---|
| `mcp_searches_total` | — | All calls to `searxng_web_search` |
| `mcp_search_errors_total` | — | Subset of the above that returned an error |
| `mcp_metadata_total` | — | All calls to `searxng_url_metadata` |
| `mcp_metadata_errors_total` | — | Subset of the above that returned an error |
| `mcp_fetches_total` | — | All calls to `searxng_read_url` |
| `mcp_fetch_errors_total` | — | Subset that returned an error |
| `mcp_fetches_by_type_total` | `type=html\|pdf\|plain\|image` | Successful fetches by extractor used |
| `mcp_fetches_by_domain_total` | `domain=<host>`, `outcome=success\|error` | Per-domain success/failure counters |
| `mcp_cache_hits_total` | — | `searxng_read_url` requests served from cache |
| `mcp_cache_misses_total` | — | Requests that fell through to a network fetch |
| `mcp_cache_force_refresh_total` | — | Requests with `force_refresh=true` |
| `mcp_rate_limit_rejections_total` | — | HTTP requests rejected by the per-caller rate limiter (429 responses). Rejection details — identity, remote, retry — are in the structured WARN log; no per-identity label here by design |
| `mcp_active_sessions` | — | Gauge: current live MCP sessions (stateful mode only) |

### Per-domain cardinality

`mcp_fetches_by_domain_total` is bounded to 512 distinct domains. Once that cap is reached, additional unique destinations are aggregated under the synthetic label value `domain="__overflow__"` rather than expanding the label set further. The cap is a deliberate design choice: an agent fetching many unique hosts shouldn't be able to grow process memory or Prometheus's index without bound.

If the overflow counter is non-zero in your environment, either your agent fleet legitimately touches more than 512 domains (in which case raise `maxTrackedDomains` in `metrics.go` and rebuild) or something is wrong with the queries you're handing the tool (in which case the overflow is doing its job by signalling that). Operators who want a full audit of every URL fetched should rely on the structured fetch log lines (`url=…`) rather than the metrics counter; the metric is observability, not provenance.

### What the per-domain metric is *not*

It is not a blocklist input that the server reads back. The project does not auto-block domains based on failure rates — that decision belongs to the operator. The intended workflow is: operator reviews the per-domain failure counts in their Prometheus / Grafana setup, decides which (if any) hosts to drop, and updates their static configuration accordingly. Compared to a system that mutates its own behaviour, this keeps the server's behaviour at any given moment a function of its config alone, which is what makes it auditable.
