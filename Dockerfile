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
FROM docker.io/golang:1.27.0-trixie@sha256:df98008ecd2b0ecc9f0a94d1b07e3564a9c92b555369b33d9b5f60d0765b2db7 AS builder

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
# curl is required for the office_oxide library install step further down:
# upstream's `go run .../cmd/install` is broken at the time of writing (asset
# URL mismatch — installer fetches `${name}-${ver}.tar.gz`, GitHub serves
# `${name}.tar.gz`; tracking issue filed upstream), so this Dockerfile
# downloads the release archive directly. Once upstream ships a fixed
# installer this `curl` line and the manual download below can be replaced
# with a `go run` similar to the pdf_oxide step. Resolve the version with:
#   apt-cache policy curl
# and pin here.
#
# git is intentionally NOT installed: SERVER_VERSION is now passed in as an
# ARG, so the builder does not need .git in the context to stamp the binary.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419 \
        curl \
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
RUN PDF_OXIDE_VERSION="$(go list -m -f '{{.Version}}' github.com/yfedoseev/pdf_oxide/go)" && \
    go run "github.com/yfedoseev/pdf_oxide/go/cmd/install@${PDF_OXIDE_VERSION}" -dir /pdf_oxide_lib

# Install the office_oxide static library.
#
# Unlike pdf_oxide we cannot use the upstream `go run .../cmd/install`
# because that installer constructs `${name}-${ver}.tar.gz` while the
# release artifact is published as `${name}.tar.gz` (no version suffix)
# — issue filed upstream, this block reverts to a `go run` once a fixed
# installer ships. Until then we fetch the same archive the installer
# would and lay it out at the same prefix layout.
#
# Version is sourced from go.mod (single source of truth) and the archive
# is staged under /office_oxide_lib with the conventional layout:
#   /office_oxide_lib/lib/linux_<arch>/liboffice_oxide.a
#   /office_oxide_lib/include/office_oxide_c/office_oxide.h
#
# Upstream's archive layout (./lib/lib*.{a,so} + ./include/office_oxide_c/)
# bundles BOTH the shared library and the static archive. We only need
# the static archive for this build — the final binary is statically
# linked into a scratch image — and discard the .so during repack.
RUN OFFICE_OXIDE_VERSION="$(go list -m -f '{{.Version}}' github.com/yfedoseev/office_oxide/go)" && \
    GOARCH="$(go env GOARCH)" && \
    case "${GOARCH}" in \
        amd64) OFFICE_ARCH=x86_64 ;; \
        arm64) OFFICE_ARCH=aarch64 ;; \
        *) echo "office_oxide: unsupported arch ${GOARCH}" >&2; exit 1 ;; \
    esac && \
    mkdir -p "/office_oxide_lib/lib/linux_${GOARCH}" /office_oxide_lib/include /tmp/office_oxide_unpack && \
    curl --proto =https --tlsv1.2 -fsSL \
        "https://github.com/yfedoseev/office_oxide/releases/download/${OFFICE_OXIDE_VERSION}/native-linux-${OFFICE_ARCH}.tar.gz" \
        -o /tmp/office_oxide.tar.gz && \
    tar -xzf /tmp/office_oxide.tar.gz -C /tmp/office_oxide_unpack && \
    cp /tmp/office_oxide_unpack/lib/liboffice_oxide.a "/office_oxide_lib/lib/linux_${GOARCH}/liboffice_oxide.a" && \
    cp -r /tmp/office_oxide_unpack/include/office_oxide_c /office_oxide_lib/include/ && \
    rm -rf /tmp/office_oxide.tar.gz /tmp/office_oxide_unpack

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
    CGO_CFLAGS="-I/pdf_oxide_lib/include -I/office_oxide_lib/include/office_oxide_c" \
    CGO_LDFLAGS="/pdf_oxide_lib/lib/linux_${GOARCH}/libpdf_oxide.a /office_oxide_lib/lib/linux_${GOARCH}/liboffice_oxide.a -lm -lpthread -ldl -lrt -lgcc_eh -lgcc -lutil -lc" \
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
# Auth credentials (MCP_AUTH_TOKEN, AUTH_USERNAME, AUTH_PASSWORD) are read from
# the runtime environment via os.Getenv and are deliberately NOT declared here.
# Baking secret-named ENV keys into the image is flagged by BuildKit's
# SecretsUsedInArgOrEnv check and would persist them in image metadata/history;
# an unset var and one set to "" are equivalent to this code, so declaring them
# gains nothing. Provide them at run time, e.g. `-e MCP_AUTH_TOKEN=...` or via
# your orchestrator's secret mechanism.
ENV USER_AGENT=""
ENV CACHE_TTL_SECONDS="300"
ENV CACHE_MAX_ENTRIES="1000"
ENV MAX_BODY_BYTES="500000"
ENV MAX_PDF_BYTES="50000000"
ENV MAX_OFFICE_BYTES="50000000"
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
