# ---------------------------------------------------------------------------
# Reproducible-build inputs.
#
# The build is reproducible relative to:
#   * the base-image digest pinned below,
#   * the committed go.mod / go.sum,
#   * the SERVER_VERSION value passed in,
#   * SOURCE_DATE_EPOCH passed in.
#
# Canonical invocation (podman):
#   SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
#   SERVER_VERSION="$(git describe --tags --always)"
#   podman build \
#     --build-arg SERVER_VERSION="${SERVER_VERSION}" \
#     --build-arg SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
#     --timestamp "${SOURCE_DATE_EPOCH}" \
#     -t mcp-searxng-relay:"${SERVER_VERSION}" .
#
# --timestamp is the podman/buildah equivalent of BuildKit's rewrite-timestamp:
# it forces all files in all layers to the given epoch, so the image envelope
# itself is reproducible, not just the binary inside.
# ---------------------------------------------------------------------------
ARG SOURCE_DATE_EPOCH=0
ARG SERVER_VERSION=dev

# Pin the builder image by content digest, not by tag. Tags are mutable;
# digests are immutable. Resolve a digest with, e.g.:
#   podman manifest inspect docker.io/golang:1.26.3-bookworm | jq -r .digest
# and copy it below. Bump deliberately as Go patch releases land.
#
# 1.26.3 (2026-05-07) fixes CVE-2026-33814: an HTTP/2 client infinite-loop on
# malicious SETTINGS_MAX_FRAME_SIZE=0, reachable via the searxng_read_url tool
# when fetching an attacker-controlled HTTPS endpoint.
FROM docker.io/golang:1.26.3-trixie@sha256:6b3de2e6b4ccfc5fae404042cb1a025b1de13c73458e50455e3143bf12e98eae as builder

# ARGs do not cross FROM boundaries — re-declare to bring them into scope.
ARG SOURCE_DATE_EPOCH
ARG SERVER_VERSION

WORKDIR /app

# Pin ca-certificates by exact version so the bundle copied into the final
# image is itself reproducible. Resolve the current version inside the chosen
# base image with:
#   apt-cache policy ca-certificates
# and pin it here. Bump deliberately.
#
# git is intentionally NOT installed: SERVER_VERSION is now passed in as an
# ARG, so the builder does not need .git in the context to stamp the binary.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419\
    && rm -rf /var/lib/apt/lists/*

# Fetch dependencies as a separate step from the source copy so this layer
# caches cleanly. go.sum is treated as a frozen input: -mod=readonly forbids
# `go mod download` from rewriting it, replacing the old `go mod tidy` step
# which could in principle mutate go.sum at build time.
COPY go.mod go.sum ./
ENV GOFLAGS="-mod=readonly"
RUN go mod download

# Install the pdf_oxide static library. The installer module is pinned by
# version and verified through the Go module proxy and checksum database;
# the precompiled libpdf_oxide.a it deposits in /pdf_oxide_lib is an upstream
# artifact whose source-to-binary provenance is documented in supply-chain.md.
RUN go run github.com/yfedoseev/pdf_oxide/go/cmd/install@v0.3.43 -dir /pdf_oxide_lib

COPY . .

# Build a fully static, reproducible binary.
#
# Reproducibility flags:
#   -trimpath                strip absolute filesystem paths from the binary
#   -buildvcs=false          do not embed VCS state (version is stamped via -X)
#   -buildid=                zero out Go's internal build id
#   -Wl,--build-id=none      zero out the C linker's build id; without this,
#                            ld embeds a random per-link build id and the
#                            output binary differs on every build
#
# Static-linking flags (unchanged from the previous build):
#   -tags netgo              Go's pure-Go DNS resolver (avoids glibc NSS)
#   -linkmode=external       hand off final linking to gcc so extldflags apply
#   -extldflags='-static'    final binary has no shared-library dependency
#
# CGO_LDFLAGS replaces -lgcc_s (shared-only) with -lgcc_eh -lgcc, which have
# static counterparts in the Debian gcc package.
RUN GOARCH="$(go env GOARCH)" && \
    CGO_ENABLED=1 \
    CGO_CFLAGS="-I/pdf_oxide_lib/include" \
    CGO_LDFLAGS="/pdf_oxide_lib/lib/linux_${GOARCH}/libpdf_oxide.a -lm -lpthread -ldl -lrt -lgcc_eh -lgcc -lutil -lc" \
    go build \
        -trimpath \
        -buildvcs=false \
        -tags netgo \
        -ldflags "-linkmode=external -extldflags '-static -Wl,--build-id=none' -buildid= -X main.ServerVersion=${SERVER_VERSION}" \

        -o mcp-searxng-relay .

# ---------------------------------------------------------------------------
# Runtime image.
# ---------------------------------------------------------------------------
FROM scratch
ARG SOURCE_DATE_EPOCH

COPY --from=builder /app/mcp-searxng-relay /mcp-searxng-relay
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

USER 1001:1001
ENV SEARXNG_URL=""
ENV MCP_PORT=""
ENV MCP_AUTH_TOKEN=""
ENV AUTH_USERNAME=""
ENV AUTH_PASSWORD=""
ENV USER_AGENT=""
ENV CACHE_TTL_SECONDS="300"
ENV CACHE_MAX_ENTRIES="1000"
ENV MAX_BODY_BYTES="500000"
ENV MAX_PDF_BYTES="50000000"
ENV MAX_IMAGE_BYTES="7500000"
ENV LOG_LEVEL="info"
ENV LOG_FORMAT="text"

# HEALTHCHECK that hits our own /health endpoint via the binary's
# --healthcheck mode. Required because the scratch base image has no shell
# or wget — the binary is the only executable in the runtime image.
# Note: container orchestrators (Kubernetes etc.) use their own probes and
# ignore this directive; it primarily benefits plain podman run / Compose.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["/mcp-searxng-relay", "--healthcheck"]

ENTRYPOINT ["/mcp-searxng-relay"]
