#!/usr/bin/env bash
# Reproducible build + push. Usage: ./build.sh 1.2.3
#
# The build is reproducible relative to:
#   - the base-image digest pinned in the Dockerfile,
#   - the committed go.mod / go.sum,
#   - SERVER_VERSION (passed in as --build-arg),
#   - SOURCE_DATE_EPOCH (passed in as --build-arg AND --timestamp).
#
# Two people running this script on the same tagged commit, with the same
# podman/buildah version, should produce byte-identical image manifests.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 <version-without-v-prefix>" >&2
    exit 64
fi

# quick and dirty
#podman run --rm \
#    -v "$PWD:/app:Z" \
#    -w /app \
#    docker.io/golang:1.26.3-trixie@sha256:6b3de2e6b4ccfc5fae404042cb1a025b1de13c73458e50455e3143bf12e98eae \
#    go mod tidy

version="v$1"
registry="registry.domain.tld/project/mcp-searxng-relay"
local_image="localhost/mcp-searxng-relay"

git pull --ff-only
git tag "$version"
git push origin "$version"

# Reproducibility inputs derived from the tagged commit. Using the commit's
# own timestamp (not `date +%s`) means rebuilds at any later wall-clock time
# still produce the same image.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
SERVER_VERSION="$(git describe --tags --always)"

podman build \
    --no-cache \
    --pull=newer \
    --build-arg "SERVER_VERSION=${SERVER_VERSION}" \
    --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
    --timestamp "${SOURCE_DATE_EPOCH}" \
    -t "${local_image}:${version}" \
    .

podman push "${local_image}:${version}" "${registry}:${version}"
