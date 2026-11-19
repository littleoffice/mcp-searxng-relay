# Upgrading

Changes that need action when you upgrade, newest first. Releases not listed here upgrade in place: pull the new image digest and restart. The full change list for each release is on the [releases page](https://github.com/littleoffice/mcp-searxng-relay/releases).

## v2.3.0: stricter fetch defaults; Podman deployment puts fence-gateway in front

**Who is affected:**

- **Everyone:** two relay defaults are stricter (images off, and a check on where fetched URLs came from). No setting was removed and no existing setting changed meaning, but agents can see refusals they did not get on v2.2.0. See [Relay defaults](#relay-defaults) below.
- **Deployments built from [`deploy/podman`](../deploy/podman/README.md):** the stack layout changed, and old env files will not start as they are. See [Podman deployment](#podman-deployment).
- **Kubernetes:** the manifests gain a NetworkPolicy. See [Kubernetes](#kubernetes).

### Relay defaults

**Images are refused.** `searxng_read_url` returned images as image blocks up to v2.2.0. It now refuses them with `image content is disabled on this relay`, because an image reaches a vision model outside any fence. To keep the old behaviour, set `FETCH_ALLOW_IMAGES=true`. See [Images](security-model.md#images).

**Unseen URLs that carry data need the user's confirmation.** The relay now remembers every address it showed a caller (search results, links in pages it returned, redirect targets). A read or metadata request for an address it never showed, which also carries data (a query string, credentials, or a token-like path or host part), needs a "yes" from the user first. On a client that supports MCP elicitation the user is asked; on one that does not, the fetch is refused. Plain unseen addresses, such as a docs page the model knows from memory, are still fetched and logged. `FETCH_URL_PROVENANCE` (default `enforce`) selects the behaviour. See [Where a URL came from](security-model.md#where-a-url-came-from).

What you may notice and what to do:

- **Agents that call an API or internal tool by URL with a query string** start getting refusals or prompts. Add those hosts to `FETCH_PROVENANCE_TRUSTED_HOSTS` (for example `api.example.com,*.wiki.corp`). See [Trusted hosts](security-model.md#trusted-hosts).
- **Users who paste a URL with a query string into the chat** are asked to confirm it, or refused on clients without elicitation. Expected; trusted hosts cover the sites this happens with routinely.
- **To measure before enforcing,** run with `FETCH_URL_PROVENANCE=log` for a while and watch `mcp_url_provenance_total{outcome="would_block"}` and the matching WARN log lines, then add trusted hosts and switch back to `enforce`.
- **To restore v2.2.0 behaviour,** set `FETCH_URL_PROVENANCE=off`. Not recommended: the check is what stops a prompt-injected page from sending data out through a fetch.

New metrics: `mcp_url_provenance_total{outcome}`, `mcp_search_queries_flagged_total`, and `image_disabled` as a new `reason` on `mcp_fetch_errors_by_reason_total`. See [Metrics](observability.md#metrics).

### Podman deployment

**What changed:**

- `/mcp` now goes through [fence-gateway](https://github.com/littleoffice/fence-gateway), which checks every fence signature before a response reaches the client. Caddy has no route to the relay any more.
- The SearXNG web UI is no longer published. Up to v2.2.0 every path other than `/mcp` served SearXNG with no login, so anyone who found the hostname could search through your instance, bypassing the relay's auth, rate limits and audit log. It now answers `404`. To keep the web UI, add the [`webui/`](../deploy/podman/webui/README.md) overlay, which puts it behind single sign-on.
- Each hop has its own network; Caddy reaches neither the relay nor SearXNG.
- `settings.yml` no longer carries a committed SearXNG `secret_key`; set `SEARXNG_SECRET`.

**What you need to do:** your old env files will not start as they are. Follow [Upgrading from the v2.2 layout](../deploy/podman/README.md#upgrading-from-the-v22-layout). In short: add a gateway token and list it with your client token in the relay's `MCP_AUTH_TOKENS`; set `FENCE_SIGNING_KEY` and pin its fingerprint in the gateway; set `SEARXNG_SECRET`. Clients keep the same URL and token.

**To stay on the old layout,** use `deploy/podman` from the [`v2.2.0` tag](https://github.com/littleoffice/mcp-searxng-relay/tree/v2.2.0/deploy/podman). It is not maintained.

### Kubernetes

`kubectl apply -k .` now also applies [`networkpolicy.yaml`](../deploy/kubernetes/networkpolicy.yaml). Edit its namespace and label selectors first, or it will block traffic you meant to allow; see [NetworkPolicy](../deploy/kubernetes/README.md#networkpolicy).
