# Kubernetes deployment

Manifests for running `mcp-searxng-relay` in a Kubernetes cluster.

## Quick start

1. Generate strong tokens — one per identity:

   ```bash
   openssl rand -hex 32
   ```

2. Copy `secret.example.yaml` to `secret.yaml`, fill in real tokens, and apply it once:

   ```bash
   cp secret.example.yaml secret.yaml
   # edit secret.yaml — replace each REPLACE_ME with a generated token
   kubectl apply -f secret.yaml
   ```

   `secret.yaml` is intentionally **not** in `kustomization.yaml` so that future `apply -k .` runs cannot accidentally roll back to the placeholder values.

3. Apply the Deployment and Service:

   ```bash
   kubectl apply -k .
   ```

4. Verify and port-forward to test:

   ```bash
   kubectl rollout status deployment/mcp-searxng
   kubectl port-forward svc/mcp-searxng 8080:8080
   curl http://localhost:8080/health
   ```

> **Using OAuth instead of static tokens?** If callers authenticate through an
> OIDC provider, you can skip the token Secret entirely: set `MCP_OAUTH_ISSUER`
> and `MCP_OAUTH_AUDIENCE` on the Deployment (from a ConfigMap or a Secret) and
> the HTTP-mode auth requirement is met without `MCP_AUTH_TOKEN_FILE`. For a
> private in-cluster issuer whose CA is not publicly trusted, mount its roots
> and point `MCP_OAUTH_CA_ROOTS` at them. See
> [OAuth 2.0 / OIDC](../../README.md#oauth-20--oidc) in the main README.

## What's in here

| File | Purpose |
|---|---|
| `deployment.yaml` | Deployment with `securityContext`, split TCP/HTTP probes, resource requests/limits |
| `service.yaml` | ClusterIP service on port 8080 |
| `secret.example.yaml` | Template for the auth-token Secret. Not in `kustomization.yaml`; create your own |
| `kustomization.yaml` | Entry point for `kubectl apply -k .` |

## Deployment shapes

The main repo README discusses stateful vs stateless modes at length. The K8s-specific implications:

### Single replica, stateful — *the default in these manifests*

Audit correlation works as designed: each agent gets one session ID for its lifetime, every tool-call log line carries `session_id` and `identity`, joining them post-hoc is trivial. The trade-off is that any rollout — image bump, env change, secret rotation — drops all sessions briefly. Agents have to re-`initialize`, and many MCP clients handle that badly (the main README documents which ones).

If audit correlation is the reason you're running this in K8s at all, this is the right starting point.

### Multiple replicas, stateless

Set `MCP_STATELESS=true` and bump `replicas:` to 2+. Every request is treated as a fresh ephemeral session, so the Service can round-robin between pods with no sticky-session config. Rolling restarts (including token rotation via Secret update) happen with zero connection downtime — old pods drain in-flight requests while new pods come up.

You lose the cross-request `session_id` join key. Audit correlation now relies on `identity` + timestamp + source IP — usable, but less precise than per-session attribution.

One thing to watch if anything downstream verifies fence signatures: each pod generates its own fence signing key at startup, so a verifier behind the Service sees a different key depending on which pod answered, and a fresh set after every rollout. Pin a shared key via `FENCE_SIGNING_KEY_FILE` (commented entries in `deployment.yaml` and `secret.example.yaml` show the shape) so every replica signs identically. Irrelevant if nothing verifies the signatures.

This is the right shape if "agents survive every redeploy" matters more than per-session audit precision.

### Multiple replicas, stateful

Possible, but only with sticky-session routing at the Ingress or Service layer so each agent always hits the pod where it initialized. The exact configuration depends on your Ingress controller — `nginx.ingress.kubernetes.io/affinity: cookie` for nginx-ingress, `service.spec.sessionAffinity: ClientIP` at the Service layer if your Ingress doesn't help, similar features in Traefik / Gateway API.

Not provided in these manifests because the right answer is controller-specific. If you need HA *and* audit correlation, this is your path; pick one of these patterns and apply it as a kustomize overlay.

## Token rotation

The server reads `MCP_AUTH_TOKEN_FILE` **once at startup**. Updating the Secret does not affect running pods — the kubelet rewrites the mount file but the process has already loaded its token table.

To rotate:

1. Update the Secret with new tokens.

   For zero-downtime rotation, list the *old* and *new* tokens for each identity in the file — both are accepted until you remove the old one. Standard pattern, same as you'd use with a local token file:

   ```
   alice:OLD_TOKEN_64_HEX_CHARS_x_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   alice:NEW_TOKEN_64_HEX_CHARS_x_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

2. Roll the Deployment to pick up the change:

   ```bash
   kubectl rollout restart deployment/mcp-searxng
   ```

3. Once you've confirmed clients have migrated to the new token, remove the old line and roll again.

If you can't tolerate the in-flight session loss of a rolling restart, switch to the multi-replica-stateless shape above; that combination handles secret rotation with no client-visible blip.

## Things deliberately omitted

- **Ingress.** Different clusters use different controllers; pick yours and add an Ingress pointing at `mcp-searxng:8080`. **Terminate TLS at the Ingress** — the MCP server itself speaks plain HTTP and the README's security notes are explicit about this.
- **NetworkPolicy.** Strongly recommended in production: egress should be restricted to DNS + your SearXNG Service + the public internet (the URL-fetch tool needs that). The exact syntax depends on your CNI plugin, so providing a one-size policy would be wrong.
- **HorizontalPodAutoscaler.** Only useful in stateless mode (HPA on a stateful service breaks session affinity). If you've adopted stateless multi-replica and have load to justify it, add one targeting CPU at ~70%.
- **PodDisruptionBudget.** Worth adding (`minAvailable: 1`) once you have 2+ replicas and use voluntary disruption controls (cluster autoscaler, node drains).
- **Secret rotation automation.** External Secrets Operator, Vault Agent Injector, CSI Secrets Store all work with `MCP_AUTH_TOKEN_FILE` unchanged because they all end at "a file exists at this path". Pick the one your platform already uses; no code changes here.

## Rate limiting and multi-replica deployments

The server ships with per-caller rate limiting enabled by default (5 rps sustained, burst 10, see the main README for `MCP_RATE_LIMIT_*` variables). Two K8s-specific notes worth being aware of:

- **Buckets are in-process, not shared across pods.** Each replica maintains its own token-bucket store. In a multi-replica deployment a caller's effective rate is `(replicas × MCP_RATE_LIMIT_RPS)` if traffic is round-robined, with the floor being `MCP_RATE_LIMIT_RPS` when sticky-session routing pins them to one pod. This is usually what you want — the limit scales with the cluster — but if you need a globally-enforced budget, terminate the limit at the Ingress layer instead and set `MCP_RATE_LIMIT_RPS=0` on the pods.
- **Exempt your monitoring scraper.** Prometheus's `/metrics` polling itself is not rate-limited (see the main README's "Rate limiting" section), but any other identity you use for monitoring or CI that hits `/` should be added to `MCP_RATE_LIMIT_EXEMPT`. Example: set `MCP_RATE_LIMIT_EXEMPT=ci,uptime-monitor` in the Deployment's env so those identities skip the limiter entirely.

## External secret stores

Because the server only cares about a readable file at `MCP_AUTH_TOKEN_FILE`, anything that materialises a file inside the container works without modification:

- **[External Secrets Operator](https://external-secrets.io/)** — syncs from Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, et al. into a native `Secret` resource. Apply your `ExternalSecret`, then the rest of these manifests work unchanged.
- **[Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)** — commit encrypted secrets to git; the controller decrypts to a regular `Secret` in-cluster. Replaces step 2 of the quick start.
- **[Secrets Store CSI Driver](https://secrets-store-csi-driver.sigs.k8s.io/)** — mounts from the upstream secret manager directly, no `Secret` resource. Point `MCP_AUTH_TOKEN_FILE` at the CSI mount path.

In all three cases the Deployment manifest above is unchanged; only the secret-creation step (#2 in the quick start) is replaced.
