# Security model

The threats the relay is built against and the controls that answer them. Signed fences have their own page: [Prompt fencing](prompt-fencing.md).

## Contents

- [Prompt injection](#prompt-injection)
- [Hidden-text removal](#hidden-text-removal)
- [SSRF protection](#ssrf-protection)
  - [Reaching internal resources (opt-in)](#reaching-internal-resources-opt-in)
  - [Reaching resources through an egress proxy (opt-in)](#reaching-resources-through-an-egress-proxy-opt-in)
- [Authentication](#authentication)
- [OAuth 2.0 verification](#oauth-20-verification)
- [Cross-origin protection](#cross-origin-protection)
- [Container hardening](#container-hardening)
- [PDF and Office safety](#pdf-and-office-safety)
- [Reporting and provenance](#reporting-and-provenance)

## Prompt injection

The tools return content sourced from the open web — titles, snippets, and page bodies written by third parties. A malicious site can embed instructions in that content (including in invisible or hidden elements) in an attempt to hijack the agent's behaviour, cause unexpected tool calls, or exfiltrate conversation context. This is the primary runtime risk when using this server with an LLM agent.

For high-risk deployments, consider restricting the tools to a known allowlist of domains, running the agent with a minimal permission scope, and auditing tool call sequences in your application layer.

## Hidden-text removal

Fences prove where text came from; they do nothing about instructions *inside* that text, and the awareness preamble is only a nudge to the model. Some injection channels can be closed deterministically instead, because they consist of text a person reading the page never sees:

- **Invisible characters.** Before any fetched text is cached, fenced and signed, the relay removes:
  - Unicode tag characters `U+E0000`–`U+E007F` — an invisible mirror of ASCII that can spell a whole sentence;
  - zero-width characters `U+200B`, `U+200C`, `U+200D`, `U+2060`–`U+2064`, `U+FEFF`;
  - bidi controls `U+202A`–`U+202E` and `U+2066`–`U+2069`.

  Two exceptions keep ordinary emoji intact: a `U+200D` ZERO WIDTH JOINER between two emoji (family, profession and rainbow-flag sequences), and the tag sequence of a subdivision flag — `U+1F3F4`, then 1–6 tag letters/digits, then `U+E007F` (the England, Scotland and Wales flags). A longer or malformed "flag" is stripped. This applies to page bodies (HTML, PDF, Office, plain text), the metadata fields `searxng_url_metadata` returns (title, author, description, site name, language, categories, tags — and so the titles `searxng_session_sources` lists), and search-result titles and snippets. It never applies to URLs, which stay byte-exact. Pagination offsets (`start_index`) are computed on the cleaned text. `FETCH_KEEP_INVISIBLE_CHARS=true` turns it off.
- **Hidden HTML elements.** Before the extractor sees an HTML page, the relay removes every element a browser would not render, with its whole subtree: the `hidden` attribute, `aria-hidden="true"`, `<template>`, `<input type="hidden">`, and inline styles declaring `display:none`, `visibility:hidden` (or `collapse`), `opacity:0` or `font-size:0`. Inline styles are parsed tolerantly — any case and whitespace, comments, `!important`, and zero written as `0`, `0.0`, `0px`, `0em`, `0%` — and resolved as the browser would within one `style` attribute (a later declaration wins unless an earlier one was `!important`). Removal happens before trafilatura chooses the article, so neither it nor its readability and dom-distiller fallbacks can pick the text up. `hidden="until-found"` is kept: the browser reveals it on find-in-page, the same as a collapsed `<details>`. `FETCH_KEEP_HIDDEN_TEXT=true` turns it off.

Nothing is dropped silently. Each removal is counted (`mcp_invisible_chars_removed_total`, `mcp_hidden_elements_removed_total`) and logged (counts and URL only, never the removed text), and when a response's text had something removed its awareness preamble gains one fixed sentence, for example *"This content contained 2 hidden page elements and 12 invisible characters, which the relay removed. Hidden text is a common way to smuggle instructions."* The note goes in the preamble, never inside the content fence, where page text could forge it; under format 1.1 it is signed with the rest of the preamble.

What this does not cover:

- **Hiding through a stylesheet or a class** (`<p class="sr-only">`, a rule in a `<style>` block or an external `.css` file) cannot be detected without rendering the page in a browser engine, and the relay does not try. Only what an element says about itself is checked.
- **Page metadata visitors never see** — `<meta name="description">`, Open Graph and similar tags, which `searxng_url_metadata` returns — is a separate channel that hidden-element removal does not touch. It gets the invisible-character filter, but otherwise it is unfiltered, page-supplied text and should be read as such.
- **Visible text.** An instruction written in plain sight, or styled to be unreadable some other way (white on white, off-screen positioning, a tiny but non-zero font), is outside what these filters can decide.

## SSRF protection

The URL fetch tool (`searxng_read_url`) resolves hostnames at TCP-dial time and rejects any address that is not a globally routable unicast IP. Two layers run on every dial and on every redirect hop:

1. Stdlib predicates: `IsLoopback`, `IsLinkLocalUnicast`, `IsLinkLocalMulticast`, `IsPrivate` (RFC 1918 + RFC 4193 ULA), `IsUnspecified`, `IsMulticast`, and `!IsGlobalUnicast` (which catches IPv4 directed broadcast).
2. A hardcoded list of reserved CIDRs the stdlib predicates miss, each annotated with the RFC that reserves it: `0.0.0.0/8` (RFC 1122), `100.64.0.0/10` CGNAT (RFC 6598), `192.0.0.0/24` IETF protocol assignments (RFC 6890), `192.0.2.0/24` / `198.51.100.0/24` / `203.0.113.0/24` TEST-NET-1/2/3 (RFC 5737), `192.88.99.0/24` deprecated 6to4 anycast (RFC 7526), `198.18.0.0/15` benchmark (RFC 2544), `240.0.0.0/4` future-reserved including `255.255.255.255` (RFC 1112), `64:ff9b::/96` and `64:ff9b:1::/48` NAT64 (RFC 6052/8215), `100::/64` discard prefix (RFC 6666), `2001::/32` Teredo (RFC 4380), `2001:2::/48` IPv6 benchmark (RFC 5180), `2001:10::/28` and `2001:20::/28` ORCHID/ORCHIDv2 (RFC 4843/7343), `2001:db8::/32` documentation (RFC 3849), `2002::/16` 6to4 (RFC 3056).

Both checks run before any byte hits the wire, and the redirect chain is revalidated at each hop, so an attacker who controls DNS for a public-looking host cannot rebind to an internal address between the check and the connect.

### Reaching internal resources (opt-in)

The default above blocks all non-public addresses, which is the right posture for a tool that fetches attacker-influenced URLs. Operators who run the relay inside a trusted network and want it to read internal resources — a self-hosted Confluence, Jira, GitLab, or wiki — can widen the policy with two allow-lists, **both empty by default** (so the default behaviour is unchanged):

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

### Reaching resources through an egress proxy (opt-in)

Some networks give the relay no route to an internal segment, or no direct route outward at all; the only way through is a forward proxy. Two more variables opt in, both unset by default:

- `FETCH_PROXY` — the proxy URL. On its own it applies **only** to hosts on `FETCH_ALLOWED_HOSTS`. This costs nothing in enforcement: allow-listed hosts already skip the per-IP check by design, so routing them via a proxy gives up nothing that was still running. Every other fetch continues to be dialled directly with the full public-IP policy in force.
- `FETCH_PROXY_ALL` — route *every* fetch through the proxy. This is for deployments with no direct egress, where the alternative is not a stricter posture but a non-functioning tool. Understand it as a delegation: the proxy performs the connection and therefore the DNS resolution, so the relay never learns the destination IP, and `assertPublicIP` and `FETCH_ALLOWED_CIDRS` stop participating. Your egress proxy becomes the enforcement point. Redirect hops are likewise left to the proxy (the hop limit still applies), because a local lookup could not constrain them and such networks often give the relay no resolver at all.

Neither variable is read from the ambient `HTTP_PROXY` / `HTTPS_PROXY`. Those get set by base images, CI systems, and cluster admission controllers for unrelated reasons, and honouring them here would let a variable nobody set for this purpose silently change a security control; they also carry the opposite default (proxy everything except `NO_PROXY`) to this subsystem's default-deny stance. The SearXNG client still honours them, since its single destination is operator-controlled and carries no SSRF exposure.

Two notes:

- Dials to the configured proxy skip the per-IP check — naming it in `FETCH_PROXY` is itself the statement that it is safe to reach, and requiring `10.0.0.0/8` in `FETCH_ALLOWED_CIDRS` just to reach a proxy would be a far worse trade. A fetch whose *target* URL names the proxy is refused, so this exemption cannot be reached from a caller-supplied URL.
- A proxy scoped to allow-listed hosts logs at `info`. `FETCH_PROXY_ALL` emits a `warn`-level audit line, and both appear as a `fetch proxy` row in the startup banner with any password in the URL redacted.

## Authentication

Incoming `Authorization` headers are run through SHA-256 once and looked up in an in-memory table keyed by the SHA-256 of each configured `"Bearer <token>"`. The lookup operates on fixed-length 32-byte keys, so it cannot leak token length via response-timing differences (a bare byte-by-byte equality check would short-circuit at the first differing byte). Only digests sit in process memory after startup — the raw tokens are only ever read from the env / token file during parsing. Tokens themselves never appear in logs; the startup banner shows only the count of configured tokens and distinct identities. On successful match, the identity associated with that token is attached to the request context and recorded in every tool-call log line (`identity=<name>`) for audit correlation.

## OAuth 2.0 verification

When `MCP_OAUTH_ISSUER` is set, a presented `Bearer` JWT that misses the static digest table is verified against the configured issuer instead: the signature is checked against the issuer's JWKS (fetched and rotated automatically, or hot-reloaded from `MCP_OAUTH_JWKS_FILE`), and the `iss` / `aud` / `exp` / `nbf` claims — plus an optional required scope — are validated before the identity claim is attached to the request context in exactly the same way a static token's identity is. Only asymmetric signing algorithms are accepted (RS/PS/ES families); the HMAC families and `alg=none` are refused by construction, which closes the RS256→HS256 key-confusion class of forgery. The relay never issues, stores, or refreshes tokens — it is a Resource Server that only verifies them. Verification failures are logged without the offered token, and a `401` advertises the RFC 9728 metadata document so a compliant client can discover where to authenticate. See [OAuth 2.0 / OIDC](configuration.md#oauth-20--oidc).

## Cross-origin protection

The Streamable HTTP transport is wrapped in Go's `net/http.CrossOriginProtection` by the go-sdk (v1.4.1+, applied as the fix for CVE-2026-33252 — "Cross-Site Tool Execution for HTTP Servers without Authorization"). Browser-originated POSTs whose `Sec-Fetch-Site` or `Origin` headers indicate a cross-origin request are rejected, as are POSTs without `Content-Type: application/json`. Non-browser clients — `curl`, Go `http.Client`, AI-agent traffic — send neither `Sec-Fetch-Site` nor `Origin` and pass through unaffected, so legitimate remote-agent usage is unimpacted. This is in addition to bearer-token authentication, not a substitute: the cross-origin check fires before request processing, but any request that survives it still has to present a valid token to reach the MCP handler.

## Container hardening

The Docker image runs as a non-root user (UID 1001) on a minimal `scratch` base — the runtime image contains only the statically linked binary and CA certificates, with no shell, package manager, or OS userland.

## PDF and Office safety

PDF extraction uses `pdf_oxide` and Office extraction (DOCX/XLSX/PPTX + legacy DOC/XLS/PPT) uses `office_oxide`, both of which are Rust cores that guarantee zero panics and zero timeouts across all inputs. A malformed or adversarially crafted document will return an error, not crash the server process.

## Reporting and provenance

Security issues should be reported privately — see [`SECURITY.md`](SECURITY.md) for the disclosure process and scope. The codebase is primarily AI-generated and reviewed, built, and tested by a single human maintainer before release; [`supply-chain.md`](supply-chain.md) is the full dependency, build-provenance, and development-process statement, written for reviewers evaluating the project for a controlled environment.
