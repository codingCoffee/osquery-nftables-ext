module github.com/zerodha/osquery-nftables-ext

go 1.26

// The only direct third-party dependency is the official osquery Go SDK; it is
// added (with the correct version) by `go get github.com/osquery/osquery-go`.
// Its transitive dependencies (Apache Thrift, etc.) are pulled in by `go mod
// tidy`, which also populates go.sum. See `make deps`.

require github.com/osquery/osquery-go v0.0.0-20260508130258-3e773449a5d4

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/apache/thrift v0.23.0 // indirect
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/pkg/errors v0.8.0 // indirect
	go.opentelemetry.io/otel v1.16.0 // indirect
	go.opentelemetry.io/otel/metric v1.16.0 // indirect
	go.opentelemetry.io/otel/trace v1.16.0 // indirect
	golang.org/x/sys v0.25.0 // indirect
)
