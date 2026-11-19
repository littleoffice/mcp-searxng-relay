# Upgrading

Changes that need action when you upgrade, newest first. Releases not listed here upgrade in place: pull the new image digest and restart. The full change list for each release is on the [releases page](https://github.com/littleoffice/mcp-searxng-relay/releases).

## v2.3.0: Podman deployment puts fence-gateway in front, web UI off

**Who is affected:** deployments built from [`deploy/podman`](../deploy/podman/README.md). The relay itself, its image, its settings and the Kubernetes manifests upgrade in place (the Kubernetes manifests gain a NetworkPolicy, see below).

**What changed:**

- `/mcp` now goes through [fence-gateway](https://github.com/littleoffice/fence-gateway), which checks every fence signature before a response reaches the client. Caddy has no route to the relay any more.
- The SearXNG web UI is no longer published. Up to v2.2.0 every path other than `/mcp` served SearXNG with no login, so anyone who found the hostname could search through your instance, bypassing the relay's auth, rate limits and audit log. It now answers `404`. To keep the web UI, add the [`webui/`](../deploy/podman/webui/README.md) overlay, which puts it behind single sign-on.
- Each hop has its own network; Caddy reaches neither the relay nor SearXNG.
- `settings.yml` no longer carries a committed SearXNG `secret_key`; set `SEARXNG_SECRET`.

**What you need to do:** your old env files will not start as they are. Follow [Upgrading from the v2.2 layout](../deploy/podman/README.md#upgrading-from-the-v22-layout). In short: add a gateway token and list it with your client token in the relay's `MCP_AUTH_TOKENS`; set `FENCE_SIGNING_KEY` and pin its fingerprint in the gateway; set `SEARXNG_SECRET`. Clients keep the same URL and token.

**To stay on the old layout,** use `deploy/podman` from the [`v2.2.0` tag](https://github.com/littleoffice/mcp-searxng-relay/tree/v2.2.0/deploy/podman). It is not maintained.

**Kubernetes:** `kubectl apply -k .` now also applies [`networkpolicy.yaml`](../deploy/kubernetes/networkpolicy.yaml). Edit its namespace and label selectors first, or it will block traffic you meant to allow; see [NetworkPolicy](../deploy/kubernetes/README.md#networkpolicy).
