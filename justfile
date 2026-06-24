# osquery-nftables-ext task runner
# Run `just` or `just --list` to see available recipes.
#
# All GoReleaser work (build / snapshot / release) runs inside the official
# GoReleaser Docker image, so Go is never required on the host.

# Pin to a major; bump deliberately. See https://hub.docker.com/r/goreleaser/goreleaser/tags
goreleaser_image := "goreleaser/goreleaser:latest"

# Run GoReleaser in a container against the repo, as the current user so the
# generated ./dist is host-owned and removable by `just clean`.
#   -e GITHUB_TOKEN          : forwarded from the host environment (release only)
#   HOME=/tmp                : writable home for the Go build cache
#   GIT_CONFIG_* safe.dir    : avoids git "dubious ownership" on the mounted repo
_gr *args:
    docker run --rm \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -e GITHUB_TOKEN \
        -e GIT_CONFIG_COUNT=1 \
        -e GIT_CONFIG_KEY_0=safe.directory \
        -e GIT_CONFIG_VALUE_0='*' \
        -v "{{justfile_directory()}}":/src \
        -w /src \
        {{goreleaser_image}} {{args}}

_default:
    @just --list

# Build the static extension binary in a container (output under ./dist).
build:
    @just _gr build --single-target --snapshot --clean

# Validate the GoReleaser config.
check:
    @just _gr check

# Build a local snapshot release (no publish, no tag required) into ./dist.
snapshot:
    @just _gr release --snapshot --clean

# Run unit tests.
test:
    go test ./...

# Run go vet static checks.
vet:
    go vet ./...

# Resolve modules and populate go.sum.
deps:
    go mod tidy

# Remove build artifacts.
clean:
    rm -f nftables.ext
    rm -rf dist

# Cut a release: bump the latest semver tag, push it, then build and publish a
# GitHub Release. Requires GITHUB_TOKEN in your environment.
# Usage: just release patch | just release minor | just release major
release BUMP:
    #!/usr/bin/env bash
    set -euo pipefail
    test -n "${GITHUB_TOKEN:-}" || { echo "GITHUB_TOKEN is not set" >&2; exit 1; }
    test -z "$(git status --porcelain)" || { echo "working tree is dirty; commit, stash, or ignore changes first (GoReleaser refuses a dirty tree)" >&2; exit 1; }
    case "{{BUMP}}" in
      patch|minor|major) ;;
      *) echo "usage: just release [patch|minor|major]" >&2; exit 1 ;;
    esac
    latest="$(git tag --list 'v*' --sort=-v:refname | head -n1)"
    latest="${latest:-v0.0.0}"
    IFS=. read -r major minor patch <<< "${latest#v}"
    case "{{BUMP}}" in
      major) major=$((major + 1)); minor=0; patch=0 ;;
      minor) minor=$((minor + 1)); patch=0 ;;
      patch) patch=$((patch + 1)) ;;
    esac
    next="v${major}.${minor}.${patch}"
    echo "Bumping ${latest} -> ${next}"
    git tag -a "${next}" -m "Release ${next}"
    git push origin "${next}"
    just _gr release --clean

# Publish a GitHub Release for the latest existing tag, without bumping.
# Use to retry after a `just release` whose tag was pushed but publish failed.
publish:
    @test -n "${GITHUB_TOKEN:-}" || { echo "GITHUB_TOKEN is not set" >&2; exit 1; }
    @just _gr release --clean
