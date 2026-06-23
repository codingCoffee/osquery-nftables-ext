# osquery-nftables-ext Makefile
#
# `make build` produces a fully static, dependency-free binary named
# nftables.ext (osquery convention: extensions end in .ext).

BINARY      := nftables.ext
PKG         := github.com/zerodha/osquery-nftables-ext
GO          ?= go

# CGO_ENABLED=0 => no libc linkage => a single static binary.
# -s -w strips the symbol table and DWARF info to keep it small.
GOFLAGS     := -trimpath
LDFLAGS     := -s -w

.PHONY: all build deps test vet clean

all: build

## build: compile the static extension binary
build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BINARY) .

## deps: resolve modules and populate go.sum (run once, needs network)
deps:
	$(GO) mod tidy

## test: run unit tests (does NOT shell out to a real nft binary)
test:
	$(GO) test ./...

## vet: run go vet static checks
vet:
	$(GO) vet ./...

## clean: remove build artifacts
clean:
	rm -f $(BINARY)
