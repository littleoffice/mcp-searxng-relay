# Grafana dashboard

[`mcp-searxng-relay-dashboard.json`](mcp-searxng-relay-dashboard.json) is a
Grafana dashboard for a **single** `mcp-searxng-relay` instance. It visualises
every series exposed at `GET /metrics` (see the [Metrics](../../README.md#metrics)
section of the main README) and is organised so the panels an operator looks at
first — traffic, errors, latency, cache — are at the top.

## Prerequisites

- A Prometheus (or Prometheus-compatible) data source in Grafana that scrapes
  this relay's `/metrics` endpoint.
- `MCP_METRICS_TOKEN` set on the relay, and that same token given to the
  scraper. With the token unset, `/metrics` returns `401` to everyone and the
  dashboard stays blank — the startup banner's `metrics auth` row reports
  `CLOSED` when that is the case.

Example scrape config:

```yaml
scrape_configs:
  - job_name: mcp-searxng-relay
    metrics_path: /metrics
    scheme: https
    authorization:
      type: Bearer
      credentials: "<MCP_METRICS_TOKEN>"
    static_configs:
      - targets: ["relay.internal.example.com:8080"]
```

The dashboard's `job` and `instance` template variables are populated from the
scraped `job` / `instance` labels, so pick the ones matching this scrape config
at the top of the dashboard. It is scoped to one instance on purpose — the
relay's per-domain series names your egress hosts, and a per-instance view keeps
that readable rather than smearing several relays together.

## Import

- **UI:** Dashboards → New → Import → *Upload JSON file*, then select the
  Prometheus data source when prompted.
- **Provisioning:** drop the JSON into a
  [dashboard provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/#dashboards)
  path and Grafana loads it on start. The dashboard UID is
  `mcp-searxng-relay-instance`.

## Panels

| Row | What it answers |
|---|---|
| **Overview** | Rates, overall error ratio, cache hit ratio, fetch p99, active sessions, rate-limit rejections — the instance at a glance. |
| **Security & guardrails** | SSRF-blocked dials by reason (the egress boundary firing — an IMDS/internal-address probe spikes here), auth failures (401s) by endpoint, and degraded-search rate/ratio. These meter events the relay only logged before; a spike is the first thing to look at. |
| **Throughput & sessions** | Per-tool call rate; live session count over time. |
| **Errors** | Absolute error rate and error-as-fraction-of-calls, per tool. |
| **Latency** | p50/p90/p99 + mean for search and fetch, plus full-distribution heatmaps. The fetch top bucket matches the 30s client timeout, so `+Inf` is timeout-adjacent. |
| **Cache** | Hit ratio, hits vs. misses, force-refresh rate. |
| **Fetch breakdown** | Content-type mix (`html/pdf/office/plain/image`), top domains by fetch and by error rate, distinct-domain count, and the `__overflow__` bucket. |
| **Session sources & history** | Source-verification ratio, elided calls (raise `MCP_HISTORY_ENTRIES` if persistently non-zero), source/caller evictions. |
| **Rate limiting** | 429 rejection rate and range total. Per-identity detail lives in the structured WARN log, not the metric. |

Counter panels use `rate()` over `$__rate_interval`; ratio panels clamp the
denominator to ≥1 so low-traffic windows don't produce divide-by-zero spikes.
