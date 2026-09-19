# Caches

The relay holds seven distinct pieces of cached or bounded state. They serve
different purposes, have different eviction rules, and protect different
components — and two of them are not really caches at all, which matters when
you are tuning them.

This document is for operators sizing a deployment or diagnosing one. The
per-variable reference is in the [README configuration table](../README.md#configuration).

## Contents

- [Inventory](#inventory)
- [The URL content cache](#the-url-content-cache)
- [The per-caller source ledger](#the-per-caller-source-ledger)
- [How they interact](#how-they-interact)
- [What is deliberately not cached](#what-is-deliberately-not-cached)
- [Impact by component](#impact-by-component)
- [Sizing and tuning](#sizing-and-tuning)

---

## Inventory

| # | Cache | Scope of key | Bound | Eviction | Survives restart |
|---|---|---|---|---|---|
| 1 | **URL content** (`Server.cache`) | URL only — **global across callers** | `CACHE_MAX_ENTRIES` (1000) | LRU + `CACHE_TTL_SECONDS` TTL (300s) | no |
| 2 | **Per-caller source ledger** (`Server.history`) | identity + session | 1000 callers × `MCP_HISTORY_ENTRIES` (50) sources | LRU per caller, ring per source | no |
| 3 | **Rate-limit buckets** | identity, or source IP when unauthenticated | 10,000 | LRU | no |
| 4 | **Health probe result** | none — one global bool | 1 | 10-second TTL | no |
| 5 | **Session table** (stateful mode) | session ID | `maxSessions` (1000) | janitor at `MCP_SESSION_MAX_AGE` | no |
| 6 | **Metrics label maps** | domain / engine name | 512 domains, 256 engines | **none** — overflow rolls up | no |
| 7 | **ACME certificate cache** | domain | — | CA lifetime | **yes, if the path is mounted** |

Numbers 4–7 are small and uncontroversial. The first two are where the
behaviour worth understanding lives.

## The URL content cache

One entry per URL, holding the *extracted* text plus the curated metadata, the
post-redirect final URL, the fetch timestamp, and whether extraction hit the
`MAX_EXTRACTED_CHARS` cap. It is populated by `searxng_read_url` and
`searxng_url_metadata` and read by both.

Three consequences fall out of that shape:

**The two fetch tools share one upstream request.** Triaging a URL with
`searxng_url_metadata` and then reading it with `searxng_read_url` costs one
HTTP request, not two, in either order. This is why triage-then-read is the
recommended agent pattern rather than a tax.

**Pagination is free after the first page.** The whole extracted text is cached,
up to `MAX_EXTRACTED_CHARS`, while each response returns at most 100k
characters. Paging through a 350k-character PDF is one upstream fetch and three
cache hits, not four fetches.

**The key is the URL and nothing else.** There is no identity or session in it,
so the cache is shared by every caller of the relay. That is the right default —
the content is public web pages, and per-tenant caches would multiply upstream
load by the tenant count for no security gain, since the relay sends no
caller-specific credentials upstream and the origin therefore cannot
distinguish callers anyway. But two properties follow that are worth stating:

- A second caller fetching a URL a first caller already fetched is served from
  cache, so the origin never sees the second request. With
  `FETCH_ALLOWED_HOSTS` configured, that includes internal resources: a
  Confluence page whose permissions change, or which is deleted, stays readable
  through the relay for up to `CACHE_TTL_SECONDS`. Lower the TTL if your
  internal ACLs are expected to be enforced promptly through this path.
- Latency discloses whether a URL is in cache, which is a weak cross-caller
  signal about what other callers have read. `mcp_fetches_by_domain_total` on
  `/metrics` discloses the same thing far more directly and fleet-wide, which
  is exactly why `MCP_METRICS_TOKEN` must not be one of your MCP tokens.

Image responses bypass this cache entirely.

## The per-caller source ledger

Despite sitting behind an LRU, this is **not a performance cache**. Nothing is
faster because of it. It is the record that backs `searxng_session_sources`:
what this caller actually fetched, and how much of each source was really read.

It differs from cache #1 in every respect that matters:

- **Keyed per caller**, as a length-prefixed `identity|session` pair. Identity
  is server-validated in both session modes; the session half is
  client-asserted under `MCP_STATELESS=true`. Pairing them is what stops one
  caller reading another's fetched URLs when the session half is empty, shared,
  or forged.
- **Counted in sources, not fetches.** A six-window read of one long document
  occupies one slot. Repeat fetches fold into one row that keeps the *deepest*
  read ever reached, so a later metadata-only call cannot un-read a page
  already read in full.
- **A cache hit still writes to it.** Every fetch path records, including the
  ones served from cache — and `finalURL` and `fetchedAt` are carried *through*
  cache #1 for precisely this reason. A hit at 14:32 whose bytes were retrieved
  at 14:28 records 14:28. The ledger reports fetch truth, not cache-hit time.

Two counters tell you whether it is sized correctly.
`mcp_session_sources_elided_total` counts calls that returned an incomplete
list — an agent may have answered against a record that no longer held
everything it read, which is the failure this feature exists to prevent. That
is the one to tune on. `mcp_history_callers_evicted_total` counts whole ledgers
dropped from the 1000-caller LRU; rising against a stable caller count means
someone is minting keys, which in stateless mode a client rotating
`Mcp-Session-Id` can do freely.

## How they interact

Mostly they do not — different keys, different lifetimes, no shared storage.
The couplings that exist are these:

```
searxng_read_url / searxng_url_metadata
        │
        ├─ miss ─▶ SSRF-checked fetch ─▶ extract ─▶ ① content cache (by URL)
        │                                              │
        └─ hit ────────────────────────────────────────┘
                     │
                     └─▶ ② source ledger (by identity+session)
                          records on BOTH paths, carrying the
                          original fetchedAt and finalURL
```

- **① feeds ②, and ② is never satisfied by ①.** The ledger is written on every
  call regardless of cache outcome. This is the only real data dependency
  between caches.
- **① is what makes the two fetch tools one upstream request**, and what makes
  pagination cheap.
- **④ is the only thing shielding SearXNG from probe traffic.** `/health` runs
  an upstream probe at most once per 10 seconds however often it is polled.
- **⑥ never evicts.** Domains and engines beyond the cap are folded into
  `domain="__overflow__"` / `engine="__overflow__"` rather than growing the
  label set. A non-zero overflow is a signal, not a leak.
- **③ eviction is fail-open.** An evicted rate-limit bucket comes back full, so
  under an IP-rotation attack the limiter bounds memory rather than the
  attacker. That is the intended trade.
- **Nothing crosses a replica boundary.** Every cache above except ⑦ is
  in-process. Two replicas share no content cache and no ledger, so a caller
  round-robined between them sees a partial source list. Configure session
  affinity at the ingress for multi-replica deployments.

## What is deliberately not cached

- **Search results.** `searxng_web_search` has no cache at all. Every search is
  a live SearXNG query. Caching would make `time_range` and engine-health
  changes invisible, and would put stale results behind a tool whose value is
  recency.
- **DNS.** The Go resolver does not cache, and nothing here adds one. This is
  load-bearing for the SSRF policy: the address check happens at TCP-dial time
  and on every redirect hop, and a resolver cache between check and connect
  would reopen the DNS-rebinding window the design closes.
- **Fence signing keys**, across restarts, unless the operator supplies one.
  See [`fence-verification.md`](fence-verification.md#key-acquisition-and-rotation).
- **The source ledger**, across restarts or replicas. It only needs to outlive
  the conversation; shared storage would widen it to "everything this identity
  ever fetched", which makes the list worse for its purpose rather than better.

## Impact by component

| Component | Protected by | Exposed when it is cold or disabled |
|---|---|---|
| **SearXNG** | ④ only | Every `/health` poll becomes an upstream probe. Searches are never cached, so search load tracks agent behaviour directly. |
| **Fetched origins (the open web)** | ① | Every read, every metadata triage, and every pagination window becomes a separate outbound request. |
| **Internal hosts** (`FETCH_ALLOWED_HOSTS`) | ① | Same as above, plus the origin regains visibility of each access — which may be what you want for audit. |
| **Relay memory** | bounds on ①②③⑤⑥ | ① dominates: worst case `CACHE_MAX_ENTRIES × MAX_EXTRACTED_CHARS` ≈ 1 GB at defaults, though real pages rarely approach the cap. |
| **Model context** | ② | Not a memory question — the ledger is read into context on every `searxng_session_sources` call, at roughly 40–80 tokens per entry. |
| **Prometheus index** | ⑥ | Unbounded label cardinality from a fleet touching many domains. |
| **Let's Encrypt rate limits** | ⑦ | Restarts re-request certificates. Mount the cache directory. |

## Sizing and tuning

- **Raise `MCP_HISTORY_ENTRIES`** when `mcp_session_sources_elided_total` is
  persistently non-zero. The constraint is model context, not memory.
- **Lower `CACHE_TTL_SECONDS`** when the relay reaches internal resources whose
  permissions change and must be enforced promptly through this path.
- **Lower `CACHE_MAX_ENTRIES` or `MAX_EXTRACTED_CHARS`** on a tight memory
  budget; raise `MAX_EXTRACTED_CHARS` to page deeper into very large documents.
- **Leave the health probe TTL alone.** It is not configurable, and 10 seconds
  is below any sane load-balancer interval.
- **Watch `mcp_cache_hits_total` against `mcp_fetch_duration_seconds`.** The
  histogram is split by `cache`, so the two questions no longer contaminate
  each other: `cache="miss"` is origin latency and the thing to alert on,
  `cache="hit"` is how fast the cache answers. Summing them back together
  recreates the old problem, where a healthy cache looked like a latency
  improvement that was not there.
