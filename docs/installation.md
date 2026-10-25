# Installation

Requirements, the other ways to run the relay, and connecting a client. The one-command `docker run` is in the [Quick start](../README.md#quick-start).

## Contents

- [Requirements](#requirements)
  - [Enabling JSON format in SearXNG](#enabling-json-format-in-searxng)
- [Docker Compose](#docker-compose)
- [Building the container image](#building-the-container-image)
- [Kubernetes](#kubernetes)
- [Using with Claude Desktop (stdio mode)](#using-with-claude-desktop-stdio-mode)
- [Using with Claude Desktop (HTTP mode)](#using-with-claude-desktop-http-mode)

## Requirements

- A running SearXNG instance with the JSON output format enabled
- Docker or Podman, to run the published image or build your own. Building the binary outside a container takes the Go version named by the `go` directive in [`go.mod`](../go.mod) plus the two native extraction libraries; see [The pdf_oxide build step](supply-chain.md#the-pdf_oxide-build-step)

### Enabling JSON format in SearXNG

Add the following to your SearXNG `settings.yml`:

```yaml
search:
  formats:
    - html
    - json
```

## Docker Compose

```yaml
services:
  mcp-searxng:
    image: ghcr.io/littleoffice/mcp-searxng-relay:latest
    restart: unless-stopped
    environment:
      SEARXNG_URL: https://your-searxng-instance.example.com
      MCP_PORT: "8080"
      MCP_AUTH_TOKEN: your-strong-random-token
    ports:
      - "8080:8080"
```

## Building the container image

For a quick local build, `docker build -t mcp-searxng-relay .` is enough. For an image you can reproduce bit for bit, compute the two reproducibility inputs once, then choose your build tool:

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

The multi-stage build compiles the binary on the digest-pinned `golang` builder named in the [`Dockerfile`](../Dockerfile) and copies only the static binary and CA certificates into a `scratch` runtime image.

**Reproducibility.** Given the same source commit and `SOURCE_DATE_EPOCH` (canonically the commit's own timestamp), either invocation produces a byte-identical image — verifiable via `docker save <image> | sha256sum` or `podman save <image> | sha256sum`. The toolchain is pinned by content digest, the module graph is frozen by `go.sum`, and the build sets `-trimpath`, `-buildvcs=false`, `-buildid=`, and `-Wl,--build-id=none` so neither paths, VCS state, nor link-time build IDs leak into the binary. BuildKit's `rewrite-timestamp` and Podman's `--timestamp` both pin all layer file timestamps to the same value so the image envelope is reproducible, not just the binary inside. See [`supply-chain.md`](supply-chain.md) for the full provenance statement and verification steps.

Note that Docker and Podman use slightly different on-disk manifest encodings, so images built with one and saved through the other will not have matching SHA-256s even when functionally identical. Pick a build tool and stick with it for cross-machine reproducibility checks.

## Kubernetes

**For production, use [searxng-helm](https://github.com/littleoffice/searxng-helm).** The chart deploys SearXNG and this relay together with a locked-down security context, deny-by-default NetworkPolicies, Secret-managed credentials, and cosign-signed releases. It is the reference deployment for the threat model this relay is built for. See its README for the full infrastructure security story, the `mcpRelay` values block, and the GitOps / external-secret-store integration notes.

**Minimal standalone manifests** are included in [`deploy/kubernetes/`](../deploy/kubernetes/) for quick cluster testing without a Helm release: [`deployment.yaml`](../deploy/kubernetes/deployment.yaml) with a locked-down `securityContext`, [`service.yaml`](../deploy/kubernetes/service.yaml), [`kustomization.yaml`](../deploy/kubernetes/kustomization.yaml), and [`secret.example.yaml`](../deploy/kubernetes/secret.example.yaml) as a template for `MCP_AUTH_TOKEN_FILE`. These are intentionally minimal — single replica, no Ingress, no NetworkPolicy — and are a starting point, not a hardened deployment. Apply with `kubectl apply -k deploy/kubernetes/` after creating a real Secret out-of-band from `secret.example.yaml` (copy to `secret.yaml`, fill in tokens, apply once; it is deliberately not listed in `kustomization.yaml` so a re-apply cannot roll a real Secret back to the placeholder values). The full deployment-shape, token-rotation, and external-secret-store guidance is in [`deploy/kubernetes/README.md`](../deploy/kubernetes/README.md).

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

> **Note:** In any non-local deployment the MCP endpoint must be reached over TLS — its bearer tokens travel in whatever wraps it. Either front it with a TLS-terminating reverse proxy (nginx, Caddy, Traefik) or an Ingress, or have the relay serve HTTPS itself with `MCP_TLS_CERT`/`MCP_TLS_KEY` or `MCP_TLS_ACME_DOMAINS` (see [TLS](operations.md#tls)). With none of these, the relay serves plain HTTP and logs a warning at startup.
