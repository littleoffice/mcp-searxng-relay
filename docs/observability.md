# Logging and metrics

What the relay writes to its logs and what it exposes at `/metrics`. A ready-made Grafana dashboard is in [`deploy/grafana/`](../deploy/grafana/).

## Contents

- [Logging](#logging)
- [Metrics](#metrics)
  - [Per-domain cardinality](#per-domain-cardinality)
  - [What the per-domain metric is *not*](#what-the-per-domain-metric-is-not)

## Logging

All log output goes to **stderr**. Set `LOG_FORMAT=json` for structured logging compatible with log aggregators.

On startup the server prints a configuration banner to stderr regardless of log level. It lists every active setting with secrets redacted, so what the process is actually running can be read off the logs rather than reconstructed from the environment it was given. Below is an HTTP-mode relay with three tokens and everything else left at its default:

```
###########################################################################################

mcp-searxng-relay v1.0.0

###########################################################################################

mode             streamable-http
address          :3000
searxng          http://searxng:8080
password         [not set]
user-agent       mcp-searxng-relay/v1.0.0
cache ttl        5m0s
cache entries    1000 max
body limit       500000 bytes
pdf limit        50000000 bytes
office limit     50000000 bytes
image limit      7500000 bytes
extract limit    1000000 chars
source history   50 per caller
log level        info
log format       text
session mode     stateless
fetch policy     public only
auth tokens      3 configured (3 identities)
oauth            disabled (static tokens only)
health auth      disabled (/health open — set MCP_HEALTH_TOKEN to require a token)
metrics auth     CLOSED (/metrics returns 401 — set MCP_METRICS_TOKEN to enable scraping)
tls              disabled (plain HTTP)
rate limit       5 rps, burst 10
link extraction  enabled
invisible chars  stripped
hidden html      stripped
prune selector   [class*="related"], [id*="related"]
fence key        d550b6b9f221ccfa (ephemeral, rotates on restart)
fence preamble   fenced (format 1.1, preamble signed)

###########################################################################################
```

Rows are shown only where they mean something, so the banner never states a setting the running process would ignore:

- `address` — HTTP mode only; stdio serves no socket.
- `searxng tokens` and `username` — only when `SEARXNG_TOKENS` / `AUTH_USERNAME` are set. The token *count* is shown, never the values.
- `session max age` and `janitor interval` — stateful mode only; in stateless mode there are no sessions for the janitor to expire.
- `allowed hosts`, `allowed cidrs` — only once `FETCH_ALLOWED_HOSTS` / `FETCH_ALLOWED_CIDRS` have widened the SSRF policy, in which case `fetch policy` flips from `public only` to `widened` and lists exactly what you allowed, in the order you wrote it.
- `fetch proxy` — only when `FETCH_PROXY` is set, with any password in the URL redacted and the scope named.

The same relay with upstream tokens, an HTTP-auth username, a widened fetch policy and an egress proxy therefore adds (or changes) these rows:

```
searxng tokens   2 configured
username         relay
fetch policy     widened (internal targets allowed)
allowed hosts    wiki.internal:443, docs.internal:8080
allowed cidrs    10.42.0.0/16:443
fetch proxy      http://user:xxxxx@proxy.internal:3128 (allow-listed hosts only)
```

In stdio mode the four rows that describe network surface read `n/a` rather than `disabled` — `oauth`, `health auth`, `metrics auth` and `tls` all refer to endpoints or sockets that mode does not serve, and "disabled" would imply a setting that could be turned on:

```
oauth            n/a (stdio serves no network socket)
health auth      n/a (stdio has no /health endpoint)
metrics auth     n/a (stdio has no /metrics endpoint)
tls              n/a (stdio serves no network socket)
```

The `metrics auth`, `health auth`, `tls`, `fetch policy`, `fence key` and `fence preamble` rows are the ones worth reading on every deploy: each names a security boundary whose state is otherwise only discoverable by tripping over it — a blank dashboard, a rejected fence, an agent that can suddenly reach an internal host. Their individual meanings are covered under [Security notes](../README.md#security-notes), [Metrics](#metrics) and [Health endpoint](operations.md#health-endpoint).

Once the server is running, typical log lines look like this (stateful mode, `LOG_FORMAT=text`) — one session's worth of calls, from the handshake to a fetch that failed:

```
time=2026-09-19T23:54:48.813Z level=INFO msg="session initialized" session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT identity=zed
time=2026-09-19T23:54:52.104Z level=INFO msg="search completed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT query="searxng json api settings" page=1 duration_ms=131 outcome=ok results=3 categories="" engines=""
time=2026-09-19T23:55:14.596Z level=INFO msg="url fetched" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT url=https://raw.githubusercontent.com/searxng/searxng/master/docs/admin/settings/settings_server.rst content_type="text/plain; charset=utf-8" bytes_raw=2688 chars_extracted=2687 extraction_truncated=false
time=2026-09-19T23:55:14.596Z level=INFO msg="fetch completed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT url=https://raw.githubusercontent.com/searxng/searxng/master/docs/admin/settings/settings_server.rst domain=raw.githubusercontent.com tool=searxng_read_url kind=text duration_ms=105 from_cache=false outcome=ok start_index=0 end_index=2687 total_chars=2687 read=full
time=2026-09-19T23:55:14.603Z level=INFO msg="fetch completed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT url=https://raw.githubusercontent.com/searxng/searxng/master/docs/admin/settings/settings_server.rst domain=raw.githubusercontent.com tool=searxng_read_url kind=text duration_ms=0 from_cache=true outcome=ok start_index=1200 end_index=2687 total_chars=2687 read=full
time=2026-09-19T23:55:14.609Z level=INFO msg="metadata fetch completed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT url=https://raw.githubusercontent.com/searxng/searxng/master/docs/admin/settings/settings_server.rst domain=raw.githubusercontent.com tool=searxng_url_metadata duration_ms=0 from_cache=true outcome=ok has_title=false has_date=false
time=2026-09-19T23:55:14.616Z level=INFO msg="session sources listed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT duration_ms=0 outcome=ok returned=1 total_fetches=3 elided=0 since_seq=0
time=2026-09-19T23:55:19.021Z level=ERROR msg="fetch failed" identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT url=https://github.com/searxng/searxng domain=github.com tool=searxng_read_url duration_ms=252 outcome=error reason=http_status error="upstream returned a non-success status: URL returned HTTP 403"
```

Every tool-completion line carries the same spine, which is what makes the log queryable rather than merely readable:

| Field | On | Meaning |
|---|---|---|
| `identity`, `session_id` | every tool line | Who made the call, in which session. Both are always present — they degrade to `""` rather than being dropped, so a log processor can rely on the key set |
| `tool` | fetch/metadata lines | Which tool touched the URL: `searxng_read_url` or `searxng_url_metadata`. The same domain reached by a metadata triage and by a full read are different events |
| `domain` | fetch/metadata lines | Destination host, matching the `domain` label on `mcp_fetches_by_domain_total` |
| `duration_ms` | every completion line | Whole milliseconds, as an integer rather than a duration string, so it can be compared numerically in a log store without parsing |
| `outcome` | every completion line | `ok` or `error`; `reason` on a failure narrows it to the same closed set as `mcp_fetch_errors_by_reason_total` (`http_status` above) |
| `from_cache` | fetch/metadata lines | Whether the bytes came from the response cache. The second fetch above is a cache hit at `duration_ms=0`, so latency percentiles can exclude what never left the process |
| `start_index`, `end_index`, `total_chars`, `read` | `searxng_read_url` | Which window of the document was returned and how deep the read went — the same read-depth vocabulary `searxng_session_sources` reports to the model |

The `"fetch failed"` line records the same attribution and timing as a success, so a failing destination is as visible in the audit trail as a working one. The URL it logs is the redacted form: any credentials in the URL's userinfo are stripped before the line is written, the same way they are stripped from the ledger and from anything the model sees.

A search where some SearXNG backends failed is not an error — the upstream answers `200` with whatever the surviving engines produced — but it is a degraded answer, and it is logged as one (one line in reality, wrapped here to fit):

```
time=2026-09-19T23:55:31.402Z level=WARN msg="searxng search was degraded: some engines did not respond"
  identity=zed session_id=SCBNSDQJ2CXWV4SYOZXUMJL3NT
  unresponsive_engines=google,bing unresponsive_count=2
  detail="google: Suspended: Access denied; bing: timeout"
  query="degraded engines test" results=1
  hint="results are incomplete; check the named engines in your SearXNG instance
        before treating thin results as a relay or model problem"
```

Engines break — upstream markup changes, an API is deprecated, a captcha wall goes up — and SearXNG suspends them and carries on. Without this line the degradation is invisible all the way up the stack: fewer results reach the agent, its answers get worse, and nothing anywhere says why. Deployments with many engines configured will see intermittent entries as engines cycle through suspension; that is noise worth having, because the alternative is silence.

The same event increments `mcp_searches_degraded_total` and `mcp_searxng_engine_errors_total{engine="…"}` (see [Metrics](#metrics)): the log line is how you diagnose one incident, the counters are how you find out there is one — a WARN nobody greps is not monitoring.

The `session_id` field joins each tool call back to the `"session initialized"` line where the client's `identity` was first recorded; combined they form the audit trail. A failed bearer-token attempt is logged without the credential it presented — only the method, path and remote address:

```
time=2026-09-19T23:55:52.184Z level=WARN msg="unauthorized request" method=POST path=/ remote=127.0.0.1:48060
```

In `LOG_FORMAT=json` the same fields appear as a flat JSON object per line, which is what most log aggregators expect.

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
| `mcp_history_callers_evicted_total` | — | Callers whose entire history was dropped from the 1,000-entry cache. Rising against a stable caller count means someone is minting cache keys — in stateless mode the conversation half of the key is client-asserted, so a client rotating `Mcp-Session-Id` can evict everyone else |
| `mcp_history_evictions_total` | — | Sources dropped from a caller's history to make room. Says how far past the cap callers run; on its own it can be one busy caller that never reads its list back, so tune on the elided counter above |
| `mcp_fetches_total` | — | All calls to `searxng_read_url` |
| `mcp_fetch_errors_total` | — | Subset that returned an error |
| `mcp_fetches_by_type_total` | `type=html\|pdf\|office\|plain\|image` | Successful fetches by extractor used |
| `mcp_fetches_by_domain_total` | `domain=<host>`, `outcome=success\|error` | Per-domain success/failure counters |
| `mcp_cache_hits_total` | — | `searxng_read_url` requests served from cache |
| `mcp_cache_misses_total` | — | Requests that fell through to a network fetch |
| `mcp_cache_force_refresh_total` | — | Requests with `force_refresh=true` |
| `mcp_rate_limit_rejections_total` | — | HTTP requests rejected by the per-caller rate limiter (429 responses). Rejection details — identity, remote, retry — are in the structured WARN log; no per-identity label here by design |
| `mcp_ssrf_blocked_total` | `reason=loopback\|link_local\|private\|unspecified\|multicast\|non_global_unicast\|reserved` | Fetch/redirect dials refused because the target resolved to a non-public address, by class. This is the egress boundary made visible; a spike is an agent (or attacker) probing internal/cloud-metadata addresses. The matched reserved CIDR and the offending IP stay in the debug log, never in this label or in any caller response |
| `mcp_auth_failures_total` | `endpoint=mcp\|metrics\|health` | HTTP requests rejected with `401` at each gated surface. A spike is credential probing or a misconfigured scraper/prober (e.g. a scraper still getting `401` because `MCP_METRICS_TOKEN` is unset — the closed-endpoint case counts under `endpoint="metrics"`). The offending remote is in the WARN log; no per-remote label here |
| `mcp_invisible_chars_removed_total` | — | Invisible characters (Unicode tags, zero-width, bidi controls) removed from fetched text — page bodies, metadata fields, search titles and snippets — before fencing. Counted when the text is cleaned, so a cache hit does not count twice. A host that suddenly contributes thousands is hiding a payload; the `info` log line `invisible characters removed` names the URL |
| `mcp_hidden_elements_removed_total` | — | HTML elements a browser would not render, removed before extraction — one per hidden subtree, not per descendant. Counted at fetch, not per cache hit; the `info` log line `hidden elements removed from fetched page` names the URL. Hidden form inputs make low single digits normal on many pages |
| `mcp_searches_degraded_total` | — | `searxng_web_search` calls that returned HTTP 200 but named unresponsive engines. **Read as a ratio against `mcp_searches_total`** — the single number that says whether backend flakiness is background noise or the thing making your agents' answers worse. **Not** an error, so `mcp_search_errors_total` deliberately does not see them |
| `mcp_searxng_engine_errors_total` | `engine=<name>` | Failures per SearXNG backend, from the upstream `unresponsive_engines` field. Answers *which* engine once the ratio above says there is a problem. Bounded to 256 distinct names; the remainder aggregates under `engine="__overflow__"` |
| `mcp_active_sessions` | — | Gauge: current live MCP sessions (stateful mode only) |
| `mcp_search_duration_seconds` | `le` | Histogram: SearXNG search round-trip latency. Buckets from 50ms to 30s |
| `mcp_fetch_duration_seconds` | `cache=hit\|miss`, `le` | Histogram: URL fetch pipeline latency (dial through extraction), observed for both `searxng_read_url` and `searxng_url_metadata`. **Alert on `cache="miss"`** — that is origin latency. `cache="hit"` returns in microseconds and is a cache-health signal, not a latency one; summing the two back together reproduces the diluted number this split exists to remove. The top bucket matches the 30s fetch client timeout, so `+Inf` observations are timeout-adjacent requests |
| `mcp_fetch_errors_by_reason_total` | `reason=invalid_url\|scheme_rejected\|ssrf_blocked\|dns\|timeout\|refused\|http_status\|extract_failed\|other` | Failed fetches by cause, across both URL tools. `mcp_fetch_errors_total` says the failure rate moved; this says whether it was a slow origin, a bad URL, the SSRF guardrail firing, or a document that would not parse. The set is closed by design — a fetched page picks its own status code, so a per-status label would be unbounded cardinality driven by hostile input. A rising `other` means a failure mode nobody has classified yet |

### Per-domain cardinality

`mcp_fetches_by_domain_total` is bounded to 512 distinct domains. Once that cap is reached, additional unique destinations are aggregated under the synthetic label value `domain="__overflow__"` rather than expanding the label set further. The cap is a deliberate design choice: an agent fetching many unique hosts shouldn't be able to grow process memory or Prometheus's index without bound.

If the overflow counter is non-zero in your environment, either your agent fleet legitimately touches more than 512 domains (in which case raise `maxTrackedDomains` in `metrics.go` and rebuild) or something is wrong with the queries you're handing the tool (in which case the overflow is doing its job by signalling that). Operators who want a full audit of every URL fetched should rely on the structured fetch log lines (`url=…`) rather than the metrics counter; the metric is observability, not provenance.

### What the per-domain metric is *not*

It is not a blocklist input that the server reads back. The project does not auto-block domains based on failure rates — that decision belongs to the operator. The intended workflow is: operator reviews the per-domain failure counts in their Prometheus / Grafana setup, decides which (if any) hosts to drop, and updates their static configuration accordingly. Compared to a system that mutates its own behaviour, this keeps the server's behaviour at any given moment a function of its config alone, which is what makes it auditable.
