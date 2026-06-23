# syntax=docker/dockerfile:1
#
# Multi-stage build: compile the static extension, then run it inside an image
# that ships osqueryd + nft. To query the *host's* nftables ruleset the
# container must share the host network namespace and hold CAP_NET_ADMIN — see
# docker-compose.yml.

# ---- build stage ---------------------------------------------------------
FROM golang:1.26.4-trixie AS build

WORKDIR /src

# Copy module files first for layer caching. `go.*` matches go.mod (always
# present) and go.sum (present once `go mod tidy` has run); it never fails.
COPY go.* ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 => a fully static, dependency-free binary.
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/nftables.ext .

# ---- runtime stage -------------------------------------------------------
FROM debian:bookworm-slim

# osquery release to install. Override with `--build-arg OSQUERY_VERSION=...`.
# NOTE: the .deb below is amd64; adjust the filename for arm64 hosts.
ARG OSQUERY_VERSION=5.23.0

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl nftables \
 && curl -fsSL -o /tmp/osquery.deb \
      "https://pkg.osquery.io/deb/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb" \
 && dpkg -i /tmp/osquery.deb \
 && rm -f /tmp/osquery.deb \
 && apt-get purge -y --auto-remove curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

# Install the extension root:root 0755 — osquery refuses to load an extension
# that is group/world-writable.
COPY --from=build /out/nftables.ext /usr/local/bin/nftables.ext
RUN chown root:root /usr/local/bin/nftables.ext \
 && chmod 0755 /usr/local/bin/nftables.ext

RUN mkdir -p /etc/osquery /var/osquery \
 && printf '%s\n' '/usr/local/bin/nftables.ext' > /etc/osquery/extensions.load \
 && chmod 0644 /etc/osquery/extensions.load

COPY docker/osquery.flags /etc/osquery/osquery.flags
COPY docker/osquery.conf  /etc/osquery/osquery.conf

ENTRYPOINT ["/usr/bin/osqueryd"]
CMD ["--flagfile=/etc/osquery/osquery.flags", "--config_path=/etc/osquery/osquery.conf"]
