# Operations

Notes for running the server in production. Most of this lives in the code and the comments, but it is the kind of detail an operator needs *before* the first incident, not after.

## Contents

- [Caches](#caches)
- [Health endpoint](#health-endpoint)
- [`--healthcheck` CLI flag](#--healthcheck-cli-flag)
- [Graceful shutdown](#graceful-shutdown)
- [HTTP server timeouts](#http-server-timeouts)
- [TLS](#tls)

## Caches

The relay holds seven pieces of cached or bounded state. The two that matter for tuning are the **URL content cache** (keyed by URL alone, so it is shared across callers; it is what makes `searxng_url_metadata` and `searxng_read_url` cost one upstream request between them, and what makes pagination free after the first page) and the **per-caller source ledger** behind `searxng_session_sources` (keyed by identity + session, written on cache hits as well as misses, and carrying the original fetch timestamp through the cache so it reports when the bytes were retrieved rather than when the hit occurred).

Search results are deliberately **not** cached, and neither is DNS — the latter is load-bearing for the SSRF policy, since a resolver cache between the dial-time address check and the connect would reopen the rebinding window that design closes.

Full inventory, interactions, per-component impact and sizing guidance: [`docs/caching.md`](caching.md).

## Health endpoint

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

The included [`deployment.yaml`](../deploy/kubernetes/deployment.yaml) uses `/health` only as the readiness probe; liveness is a plain TCP-socket probe. This is deliberate: a transient SearXNG outage should not cascade into kubelet killing the pod, only into traffic being routed away until SearXNG recovers. (A TCP-socket liveness probe needs no `Authorization` header even when `MCP_HEALTH_TOKEN` is set, since it never hits `/health`.)

## `--healthcheck` CLI flag

The container `HEALTHCHECK` directive in the [`Dockerfile`](../Dockerfile) invokes `mcp-searxng-relay --healthcheck`, which is a self-probe: the binary makes a single `GET` to `http://127.0.0.1:$MCP_PORT/health` with a 5-second timeout, exits `0` if the response is `200`, and exits `1` otherwise. The flag exists because the `scratch` runtime image has no shell, `curl`, or `wget` to write a conventional probe with — the binary has to be its own probe. When `MCP_HEALTH_TOKEN` is set, the self-probe reads that same env var and sends the `Authorization: Bearer` header automatically, so a single environment entry covers both the server and its own probe.

This is for plain `docker run` / Compose deployments. Kubernetes uses the HTTP probes in `deployment.yaml` and ignores the `HEALTHCHECK` directive.

## Graceful shutdown

On `SIGTERM` or `SIGINT` the server stops accepting new connections, then gives in-flight requests up to **30 seconds** to complete before exiting. The session janitor (stateful mode) is stopped at the same time. If the drain window expires with requests still in flight, the process exits non-zero.

Two deployment knobs interact with this:

- **Kubernetes `terminationGracePeriodSeconds`.** Defaults to 30s on most clusters, which exactly matches the drain timeout — leaving zero margin for kubelet to deliver SIGTERM, the server to receive it, and the response to flush. Set `terminationGracePeriodSeconds: 45` (or higher) on the Pod spec so the drain has a real chance to finish.
- **Compose `stop_grace_period`.** Defaults to 10s, which is shorter than the server's drain timeout. Set `stop_grace_period: 45s` on the service so SIGKILL does not arrive mid-drain.

For multi-replica deployments behind an Ingress or load balancer, the LB needs to deregister the Pod before SIGTERM arrives — otherwise traffic continues arriving during the drain window. Kubernetes handles this automatically once readiness probes start failing, which is one reason `/health` is the *readiness* probe and not the liveness one.

## HTTP server timeouts

The server's stdlib `http.Server` is configured with three deliberate values:

| Setting | Value | Reason |
|---|---|---|
| `ReadTimeout` | `30s` | Bounds how long a slow client can hold the request-line, headers, and body read. Long enough for typical JSON-RPC bodies; short enough to discourage slowloris-style attacks. |
| `WriteTimeout` | **disabled (`0`)** | The go-sdk manages per-stream deadlines for SSE responses. A server-level write deadline would prematurely close long-lived event streams during tool calls that take more than a few seconds. |
| `IdleTimeout` | `120s` | Keepalive idle window. Above typical client think-time between tool calls; below the point at which dead connections accumulate. |

When fronting the server with a reverse proxy (recommended for any non-local deployment — see [Security notes](../README.md#security-notes)), the proxy's own timeouts must accommodate streaming responses:

- **nginx.** Set `proxy_read_timeout` and `proxy_send_timeout` to at least the longest tool-call wall time you expect — a reasoning agent over a large PDF or Office document can take 30+ seconds. Disable `proxy_buffering` for the MCP route so SSE chunks reach the client immediately.
- **Caddy.** The bundled [`Caddyfile`](../deploy/podman/Caddyfile) sets `flush_interval -1` on the MCP reverse_proxy directive, which is what disables Caddy's response buffering for streaming.
- **Traefik.** Use the `forwardingTimeouts.responseHeaderTimeout` field and ensure the entrypoint is not configured with an aggressive idle timeout.

If you see tool calls failing with truncated SSE streams in a reverse-proxy deployment, the proxy's read/write timeout is almost always the cause, not the relay's.

## TLS

By default the relay speaks plain HTTP and TLS is terminated by whatever fronts it — the Caddy service in the [podman stack](../deploy/podman), an Ingress in [Kubernetes](../deploy/kubernetes). That remains the recommended shape wherever such a terminator already exists. For a deployment with no proxy — the relay running by itself — it can also serve HTTPS directly, in one of two modes (mutually exclusive; configuring both fails startup):

**Manual certificate.** Point `MCP_TLS_CERT` and `MCP_TLS_KEY` at a PEM certificate and key:

```bash
docker run -e MCP_PORT=8443 -e MCP_TLS_CERT=/tls/tls.crt -e MCP_TLS_KEY=/tls/tls.key ...
```

The pair is loaded once at startup (a bad path or a mismatched cert/key fails startup, not the first handshake) and re-read on the next handshake whenever the files change — so an in-place renewal (cert-manager rewriting a mounted Secret, a certbot deploy hook) is picked up **without a restart**.

**Automatic certificates (ACME).** There is no on/off flag — naming the hostname(s) to certify with `MCP_TLS_ACME_DOMAINS` turns ACME on:

```bash
docker run -e MCP_PORT=443 \
  -e MCP_TLS_ACME_DOMAINS=relay.example.com \
  -e MCP_TLS_ACME_EMAIL=admin@example.com \
  -v mcp-acme:/var/cache/mcp-acme ...
```

Setting any `MCP_TLS_ACME_*` variable selects ACME mode, and `MCP_TLS_ACME_DOMAINS` is then required — so a half-configured ACME setup (a stray or misspelled variable) fails startup loudly instead of silently falling back to plain HTTP. Certificates are cached under `MCP_TLS_ACME_CACHE_DIR` (default `/var/cache/mcp-acme`); **mount a volume, bind mount or PVC there** so they survive restarts — without persistence, restarts re-request and can hit CA rate limits, and startup fails if the path is not writable. Challenges are answered over **TLS-ALPN-01 on the same listener**, so only the one TLS port needs to be reachable — no `:80` responder.

- **Startup issuance and logging.** The relay contacts the CA **at startup**, requesting a certificate for each `MCP_TLS_ACME_DOMAINS` host as soon as the listener is up (rather than lazily on the first client handshake), so a misconfiguration surfaces immediately. Watch the log for it — at `info` you get `acme: enabled` (the directory, hosts, cache dir and how the CA is trusted), then `acme: requesting certificate` / `acme: certificate ready` (or `acme: certificate request failed` with the error) per host; at `LOG_LEVEL=debug` every handshake — including the CA's own TLS-ALPN-01 challenge — is logged. TLS handshake errors from real clients are logged too. If you see **no** `acme:` lines at all, ACME did not turn on — check that `MCP_TLS_ACME_DOMAINS` is set and spelled correctly, and that you are running a build that includes this (there is no longer an `MCP_TLS_ACME` on/off flag). The CA must be able to reach the relay's TLS port to complete the challenge; if your ACME server logs no incoming request, that reachability (DNS/firewall/routing to the listener) is the first thing to check.

- **Contact email.** `MCP_TLS_ACME_EMAIL` is optional. Leave it unset to register the ACME account without a contact; if you do set it, give a valid bare address — a public CA (Let's Encrypt) rejects a malformed contact at registration, and the relay checks the address shape at startup so that failure surfaces immediately rather than at first issuance.

- **Challenge reachability (`could not connect to validation target`).** The CA validates over **TLS-ALPN-01 by connecting to the host on tcp/443** — port 443 is fixed by RFC 8737, whatever port the relay itself listens on. So `<host>:443` (for every name in `MCP_TLS_ACME_DOMAINS`) must resolve, *from the CA's network*, to this relay and be reachable through any firewall/NAT. If the relay listens on a non-443 port, publish it so the domain's `:443` still routes in (e.g. `-p 443:8443`). An `acme:error:connection` / "could not connect to validation target" in the log means this path is broken, not the relay — verify it from the CA host with `openssl s_client -connect <host>:443 -alpn acme-tls/1 -servername <host>`.

- **Private CA (e.g. step-ca).** `MCP_TLS_ACME_DIRECTORY` selects the ACME directory (default: Let's Encrypt production). If that CA's own directory-endpoint certificate is not publicly trusted, the simplest path is to add its root to the container's trust store (bake it into the image, or set `SSL_CERT_FILE`) — then leave `MCP_TLS_ACME_CA_ROOTS` unset and ACME uses the system trust store. Set `MCP_TLS_ACME_CA_ROOTS=/path/to/ca-roots.pem` only when you want that trust **confined to the ACME client** so the private CA is not also trusted by the fetch tool and the SearXNG client. This is the in-process equivalent of the ACME setup the bundled [`Caddyfile`](../deploy/podman/Caddyfile) already uses.

- **Health check.** The `--healthcheck` self-probe (used by the Docker `HEALTHCHECK`) follows the server to HTTPS when TLS is on. In **ACME** mode it presents the first `MCP_TLS_ACME_DOMAINS` host as the TLS SNI while still dialing `127.0.0.1`, so the server can serve its real certificate (a loopback-IP SNI is refused by the ACME host policy) and the probe verifies against that hostname — no extra configuration needed once the certificate has been issued. In **manual** mode the probe dials `127.0.0.1` directly, so the serving certificate must be valid for the loopback address (add `127.0.0.1`/`localhost` as SANs) for verification to pass; `MCP_TLS_HEALTHCHECK_INSECURE=true` skips verification when it cannot. Either way this affects only the loopback self-probe, never the served endpoint.

In Kubernetes, prefer terminating TLS at an Ingress with cert-manager ([`ingress.example.yaml`](../deploy/kubernetes/ingress.example.yaml)); the in-pod `MCP_TLS_*` path is there for running the relay alone in a namespace with no Ingress (see the [Kubernetes README](../deploy/kubernetes/README.md#tls)).
