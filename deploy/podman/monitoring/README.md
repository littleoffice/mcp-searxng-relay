# Logs pipeline (Loki + Promtail)

The Prometheus metrics answer *how much* and *how healthy* — call rates, error
ratios, latency, and destination **hostnames** (`mcp_fetches_by_domain_total`,
capped at 512). They deliberately do **not** carry full URLs or search-query
text: those are unbounded-cardinality and name each caller's activity, so the
relay keeps them out of the metrics (the same disclosure boundary that gives
`/metrics` its own token).

The per-event record — *which URL was fetched, what was searched, by which
session* — lives in the relay's **structured logs**. This overlay ships those
logs to [Loki](https://grafana.com/oss/loki/) so you can query and dashboard
them in the Grafana you already run.

> ⚠️ **These logs are more sensitive than `/metrics`.** They contain full fetch
> URLs, search-query strings, and caller identities. Whatever can read Loki can
> read every tenant's browsing and searching. Keep it on a trusted network and
> access-controlled at least as tightly as the metrics token.

## What's here

| File | Role |
|---|---|
| `docker-compose.monitoring.yaml` | Loki + Promtail services (separate from the app stack) |
| `loki-config.yaml` | Single-binary Loki, filesystem storage, 7-day retention |
| `promtail-config.yaml` | Tails the `mcp-searxng-relay` container and pushes to Loki |

## Prerequisites

1. **The relay must log JSON.** `LOG_FORMAT=json` is set in
   [`../envs/.mcp-searxng-relay.env`](../envs/.mcp-searxng-relay.env). Restart
   the relay if you changed it: `podman compose -f ../docker-compose.yaml up -d`.

2. **The Podman API socket must be running** — Promtail discovers and reads the
   relay's logs through it (Docker-compatible), which avoids depending on where
   Podman writes log files.

   ```bash
   # rootless (typical):
   systemctl --user enable --now podman.socket
   echo "$XDG_RUNTIME_DIR/podman/podman.sock"     # confirm the path
   ```

   If your socket is not at the rootless default `/run/user/1000/podman/podman.sock`
   (e.g. a different UID, or rootful `/run/podman/podman.sock`), export it:

   ```bash
   export PODMAN_SOCKET="$XDG_RUNTIME_DIR/podman/podman.sock"
   ```

## Bring it up

```bash
podman compose -f docker-compose.monitoring.yaml up -d
# or: podman-compose -f docker-compose.monitoring.yaml up -d
```

Check Promtail attached to the relay and is pushing:

```bash
podman logs promtail | tail
curl -s "http://127.0.0.1:3100/loki/api/v1/label/container/values"   # should list mcp-searxng-relay
```

## Add Loki to Grafana

In your existing Grafana: **Connections → Data sources → Add data source →
Loki**, URL `http://127.0.0.1:3100` (or the monitoring-network address if
Grafana runs in containers). The dashboard's **Activity (logs)** row uses a
`loki` datasource variable — pick this datasource there.

## Useful queries (LogQL)

The relay logs one line per tool call. Fields available after `| json`: `level`,
`msg`, `time`, `identity`, `session_id`, plus `query` (searches) and `url`
(fetches). Message strings:

| `msg` | Emitted by | Key fields |
|---|---|---|
| `search completed` | `searxng_web_search` | `query`, `page` |
| `fetch completed` | `searxng_read_url` | `url`, `kind` |
| `metadata fetch completed` | `searxng_url_metadata` | `url` |
| `search failed` / `fetch failed` | error paths | `query` / `url`, `error` |

```logql
# Recent searches, newest first
{container="mcp-searxng-relay"} | json | msg = `search completed`
  | line_format "{{.time}}  [{{.session_id}}]  {{.query}}"

# Recent URLs fetched (read_url + metadata)
{container="mcp-searxng-relay"} | json | msg =~ `fetch completed|metadata fetch completed`
  | line_format "{{.time}}  [{{.session_id}}]  {{.url}}"

# Failures only
{container="mcp-searxng-relay"} | json | msg =~ `fetch failed|search failed`

# Everything one session did (fetches + searches), correlated
{container="mcp-searxng-relay"} | json | session_id = `<paste-session-id>`
```

Because `url`/`query`/`session_id` are extracted at query time (not Loki labels),
you can filter and correlate on them freely without creating high-cardinality
label series.

## Tear down

```bash
podman compose -f docker-compose.monitoring.yaml down          # keep logs
podman compose -f docker-compose.monitoring.yaml down -v       # also drop stored logs
```
