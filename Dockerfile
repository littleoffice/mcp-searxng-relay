# ---------------------------------------------------------------------------
# Reproducible-build inputs.
#
# The build is reproducible relative to:
#   * the base-image digests pinned below (Go builder AND Rust builder),
#   * the committed go.mod / go.sum,
#   * the pinned pdf_oxide / office_oxide source commits (see the source stage),
#   * the SERVER_VERSION value passed in,
#   * SOURCE_DATE_EPOCH passed in.
#
# The pdf_oxide / office_oxide native static libraries are BUILT FROM SOURCE in
# the rust-builder stage below rather than downloaded as precompiled upstream
# blobs. That closes the source-to-binary provenance gap for the two native
# dependencies (see docs/supply-chain.md): every byte in the image now traces to
# either Go source pinned in go.sum or Rust source pinned by commit + Cargo.lock.
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

# Pin the builder images by content digest, not by tag. Tags are mutable;
# digests are immutable. Resolve a digest with, e.g.:
#   podman manifest inspect docker.io/golang:1.27.0-trixie | jq -r .digest
# and copy it below. Bump deliberately as Go patch releases land.
#
# 1.26.3 (2026-05-07) fixes CVE-2026-33814: an HTTP/2 client infinite-loop on
# malicious SETTINGS_MAX_FRAME_SIZE=0, reachable via the searxng_read_url tool
# when fetching an attacker-controlled HTTPS endpoint.

# ---------------------------------------------------------------------------
# Stage 1: resolve the pinned native-dependency versions from go.mod and fetch
# their Rust source. Kept in the Go image because go.mod is the single source of
# truth for the versions, and `go list -m` is how we read it; git ships in the
# official golang image, so no extra tooling is needed here.
# ---------------------------------------------------------------------------
FROM docker.io/golang:1.27.0-trixie@sha256:df98008ecd2b0ecc9f0a94d1b07e3564a9c92b555369b33d9b5f60d0765b2db7 AS source

WORKDIR /app

# Integrity pin ON TOP OF the go.mod version: the source stage clones the tag
# named by go.mod, then asserts the resulting commit matches the SHA below.
# A re-pointed tag (the one thing a version string cannot defend against) fails
# the build loudly. Bump these in lockstep with the module versions in go.mod.
#
# These are the COMMIT the tag points to, which is what `git rev-parse HEAD`
# yields after `git clone --branch <tag>`. Both upstream tags are ANNOTATED, so
# resolve the peeled commit — note the `^{}` — not the tag-object SHA:
#   git ls-remote https://github.com/yfedoseev/pdf_oxide.git 'refs/tags/vX.Y.Z^{}'
ARG PDF_OXIDE_COMMIT=10b87f153200cd5c4d4a4defee471757091e6559
ARG OFFICE_OXIDE_COMMIT=744b25be7f79ad333ffe68a11b2a39856846cdf3

# go.sum is a frozen input: -mod=readonly forbids any step from rewriting it.
COPY go.mod go.sum ./
ENV GOFLAGS="-mod=readonly"
RUN go mod download

# Clone each core at the tag named by go.mod, shallow, then verify HEAD against
# the pinned commit. `.git` is removed so the copied tree is source-only.
RUN set -eux; \
    PDF_VER="$(go list -m -f '{{.Version}}' github.com/yfedoseev/pdf_oxide/go)"; \
    OFF_VER="$(go list -m -f '{{.Version}}' github.com/yfedoseev/office_oxide/go)"; \
    git clone --depth 1 --branch "${PDF_VER}" https://github.com/yfedoseev/pdf_oxide.git /src/pdf_oxide; \
    git clone --depth 1 --branch "${OFF_VER}" https://github.com/yfedoseev/office_oxide.git /src/office_oxide; \
    got_pdf="$(git -C /src/pdf_oxide rev-parse HEAD)"; \
    got_off="$(git -C /src/office_oxide rev-parse HEAD)"; \
    [ "${got_pdf}" = "${PDF_OXIDE_COMMIT}" ] || { echo "pdf_oxide ${PDF_VER} HEAD ${got_pdf} != pinned ${PDF_OXIDE_COMMIT}" >&2; exit 1; }; \
    [ "${got_off}" = "${OFFICE_OXIDE_COMMIT}" ] || { echo "office_oxide ${OFF_VER} HEAD ${got_off} != pinned ${OFFICE_OXIDE_COMMIT}" >&2; exit 1; }; \
    rm -rf /src/pdf_oxide/.git /src/office_oxide/.git

# ---------------------------------------------------------------------------
# Stage 2: build the native static libraries from Rust source.
#
# rust:1.90-trixie satisfies both crates' MSRV (1.88) and office_oxide's
# edition 2024 (>= 1.85). Pinned by digest for the same reason the Go image is.
#   podman manifest inspect docker.io/rust:1.90-trixie | jq -r .digest
# ---------------------------------------------------------------------------
FROM docker.io/rust:1.90-trixie@sha256:e227f20ec42af3ea9a3c9c1dd1b2012aa15f12279b5e9d5fb890ca1c2bb5726c AS rust-builder

ARG SOURCE_DATE_EPOCH

# Build-time system deps for pdf_oxide's feature set only: aws-lc-rs (signatures)
# needs cmake/nasm/perl, system-fonts needs fontconfig dev headers, and clang is
# the C toolchain those crates' build scripts invoke. office_oxide is pure Rust
# and needs none of these. Left unpinned like the original build's `curl` line;
# the build-twice reproducibility job hits a single apt snapshot per run.
#
# NOTE (provenance caveat, tracked in docs/supply-chain.md): pdf_oxide's `ocr`
# feature pulls the `ort` ONNX Runtime crate. Depending on ort's build strategy
# it may fetch a prebuilt onnxruntime at build time — i.e. the feature set that
# forces the widest FFI surface is also the one that can reintroduce a
# precompiled sub-dependency. Verify in CI whether the produced .a is fully
# from-source; if not, that residual is the next provenance item to close.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake \
        nasm \
        perl \
        pkg-config \
        libfontconfig1-dev \
        clang \
    && rm -rf /var/lib/apt/lists/*

COPY --from=source /src /src

# Reproducibility for the Rust artifacts:
#   - CARGO_HOME is a fixed path so dependency source paths are stable.
#   - --remap-path-prefix strips the crate's own build path.
#   - --locked builds strictly from the committed Cargo.lock (its per-crate
#     checksums are the Rust equivalent of go.sum), so the crate graph cannot
#     drift at build time.
#   - codegen-units=1 + strip are already set in each crate's release profile.
ENV CARGO_HOME=/cargo
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
ENV RUSTFLAGS="--remap-path-prefix=/src=/build"

# office_oxide — pure Rust, default features. Emits liboffice_oxide.a; the C
# header is committed in the source tree (no cbindgen run needed).
RUN set -eux; cd /src/office_oxide; \
    cargo build --release --locked --lib; \
    mkdir -p /staging/office; \
    cp target/release/liboffice_oxide.a /staging/office/; \
    cp include/office_oxide_c/office_oxide.h /staging/office/

# pdf_oxide — the exact feature set the Go binding's ABI requires. Dropping any
# feature removes exported FFI symbols and the Go cgo link step then fails on the
# missing symbols. After building, shrink the archive with upstream's own script
# (strips the per-object .llvmbc / DWARF sections that CGo's linker never uses —
# ~35 MB+). The header is committed in the source tree.
RUN set -eux; cd /src/pdf_oxide; \
    cargo build --release --locked --lib \
        --features ocr,rendering,signatures,barcodes,tsa-client,system-fonts; \
    bash scripts/shrink-staticlib.sh target/release/libpdf_oxide.a; \
    mkdir -p /staging/pdf; \
    cp target/release/libpdf_oxide.a /staging/pdf/; \
    cp include/pdf_oxide_c/pdf_oxide.h /staging/pdf/

# ---------------------------------------------------------------------------
# Stage 3: build the fully static Go binary, linking the from-source archives.
# ---------------------------------------------------------------------------
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
# git is intentionally NOT installed: SERVER_VERSION is passed in as an ARG, so
# the builder does not need .git in the context to stamp the binary. The source
# fetch that DID need git happens in the `source` stage above.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20250419 \
    && rm -rf /var/lib/apt/lists/*

# Fetch dependencies as a separate step from the source copy so this layer
# caches cleanly. go.sum is treated as a frozen input: -mod=readonly forbids
# `go mod download` from rewriting it.
COPY go.mod go.sum ./
ENV GOFLAGS="-mod=readonly"
RUN go mod download

# Place the from-source libraries and headers at the exact paths the CGO flags
# below expect — the same layout the upstream installers used to produce, so the
# link step is unchanged from the download-based build it replaces.
COPY --from=rust-builder /staging /staging
RUN set -eux; GOARCH="$(go env GOARCH)"; \
    mkdir -p "/pdf_oxide_lib/lib/linux_${GOARCH}" /pdf_oxide_lib/include \
             "/office_oxide_lib/lib/linux_${GOARCH}" /office_oxide_lib/include/office_oxide_c; \
    cp /staging/pdf/libpdf_oxide.a "/pdf_oxide_lib/lib/linux_${GOARCH}/"; \
    cp /staging/pdf/pdf_oxide.h /pdf_oxide_lib/include/; \
    cp /staging/office/liboffice_oxide.a "/office_oxide_lib/lib/linux_${GOARCH}/"; \
    cp /staging/office/office_oxide.h /office_oxide_lib/include/office_oxide_c/

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
# Static-linking flags:
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
