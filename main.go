// SPDX-License-Identifier: Apache-2.0
//
// osquery-nftables-ext: an osquery extension that exposes the live Linux
// nftables ruleset as a queryable osquery table named `nftables`.
//
// Why this exists
// ---------------
// Core osquery's built-in `iptables` table reads /proc/net/ip_tables_names,
// which the modern nf_tables kernel backend does not populate. On nftables
// systems that table therefore returns nothing. This extension fills the gap
// by shelling out to `nft -j list ruleset` (read-only, structured JSON) and
// flattening the result into rows.
//
// The extension speaks the osquery Thrift extensions protocol over the socket
// passed via --socket and registers a single TablePlugin. See nftables.go for
// the table implementation and the row model.
//
// This program NEVER modifies firewall state. The only external command it ever
// runs is `nft -j list ruleset`, invoked with a fixed argument slice and no
// shell.
package main

import (
	"flag"
	"log"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// version is reported to osquery during extension registration. Override at
// build time with -ldflags "-X main.version=<v>".
var version = "0.1.0"

func main() {
	// osqueryd passes these flags to autoloaded extensions. We must accept all
	// of them or flag parsing fails and the extension will not start.
	socket := flag.String("socket", "", "path to the osqueryd extensions UNIX socket")
	timeout := flag.Int("timeout", 0, "seconds to wait for the osqueryd extensions manager")
	interval := flag.Int("interval", 0, "seconds between extension manager health pings")
	flag.Bool("verbose", false, "enable verbose logging (accepted for compatibility)")
	flag.Parse()

	if *socket == "" {
		log.Fatalln("nftables.ext: --socket is required (osqueryd supplies it automatically)")
	}

	opts := []osquery.ServerOption{osquery.ExtensionVersion(version)}
	if *timeout > 0 {
		opts = append(opts, osquery.ServerTimeout(time.Duration(*timeout)*time.Second))
	}
	if *interval > 0 {
		opts = append(opts, osquery.ServerPingInterval(time.Duration(*interval)*time.Second))
	}

	server, err := osquery.NewExtensionManagerServer("nftables", *socket, opts...)
	if err != nil {
		log.Fatalf("nftables.ext: failed to create extension manager server: %v", err)
	}

	server.RegisterPlugin(table.NewPlugin("nftables", nftablesColumns(), generateNftables))

	if err := server.Run(); err != nil {
		log.Fatalf("nftables.ext: extension server exited: %v", err)
	}
}
