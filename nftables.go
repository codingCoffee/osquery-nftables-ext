// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"os"
	"os/exec"

	"github.com/osquery/osquery-go/plugin/table"
)

// Row model
// ---------
// `nft -j list ruleset` emits a single JSON object with one key, "nftables",
// whose value is an array of single-key objects. Each object is one of:
// metainfo, table, chain, rule, set, map, element, ... We flatten this array
// into one osquery row per object (skipping "metainfo"), so a row may describe
// a table, a chain, a rule, a set or a map. The `kind` column says which.
//
//	kind=table  -> one row per nftables table.   chain/type/hook/priority/policy empty.
//	kind=chain  -> one row per chain. For base chains, type/hook/priority/policy
//	               are populated; regular chains leave them empty.
//	kind=rule   -> one row per rule. `chain` is the owning chain; the full rule
//	               (including its expression list) is preserved in rule_json.
//	kind=set    -> one row per named set.  `chain` is empty.
//	kind=map    -> one row per named map.  `chain` is empty.
//	kind=<other>-> any future top-level object type is still surfaced as a row
//	               with whatever common fields parse, plus its raw JSON.
//
// rule_json always holds the raw JSON object for that row, so no information is
// ever lost to the flattening — a caller can re-parse it for details the
// dedicated columns don't expose (e.g. a rule's match/verdict expressions).
//
// All columns are TEXT (osquery table columns here are all strings). Integer
// values such as handle and priority are rendered as their text form; priority
// may also be a name/offset object in newer nft, in which case the compact JSON
// is stored verbatim.

// nftBinary resolves the nft executable to run. NFT_BIN overrides PATH lookup.
func nftBinary() (string, error) {
	if override := os.Getenv("NFT_BIN"); override != "" {
		return override, nil
	}
	return exec.LookPath("nft")
}

// nftablesColumns defines the table schema. Every column is TEXT.
func nftablesColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("kind"),       // table | chain | rule | set | map | ...
		table.TextColumn("family"),     // ip, ip6, inet, arp, bridge, netdev
		table.TextColumn("table_name"), // nftables table name
		table.TextColumn("chain"),      // chain name (empty for table/set/map rows)
		table.TextColumn("handle"),     // rule/chain/table handle
		table.TextColumn("type"),       // base-chain type: filter/nat/route
		table.TextColumn("hook"),       // input/output/forward/prerouting/postrouting
		table.TextColumn("priority"),   // base-chain priority
		table.TextColumn("policy"),     // accept/drop, for base chains
		table.TextColumn("rule_json"),  // raw JSON object for this row
	}
}

// generateNftables is the osquery TablePlugin Generate function. It runs nft,
// parses the JSON, and returns flattened rows. Any operational failure (nft
// missing, non-zero exit, permission denied, malformed JSON) is logged and
// surfaced as an EMPTY result set rather than an error, so a transient or
// environmental problem never crashes the extension.
func generateNftables(ctx context.Context, _ table.QueryContext) ([]map[string]string, error) {
	bin, err := nftBinary()
	if err != nil {
		log.Printf("nftables.ext: nft binary not found on PATH (set NFT_BIN to override): %v", err)
		return []map[string]string{}, nil
	}

	// FIXED argument slice. Never a shell, never a built string -> no injection
	// surface. CommandContext so the query can be cancelled / time out cleanly.
	cmd := exec.CommandContext(ctx, bin, "-j", "list", "ruleset")
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// Most common cause is lack of privilege: reading the full ruleset
			// requires root (CAP_NET_ADMIN).
			log.Printf("nftables.ext: %q exited non-zero (need root to read the ruleset?): %v; stderr: %s",
				bin, err, string(exitErr.Stderr))
		} else {
			log.Printf("nftables.ext: failed to run %q: %v", bin, err)
		}
		return []map[string]string{}, nil
	}

	rows, err := flattenRuleset(out)
	if err != nil {
		log.Printf("nftables.ext: could not parse nft JSON output: %v", err)
		return []map[string]string{}, nil
	}
	return rows, nil
}

// ruleset mirrors the top-level shape of `nft -j list ruleset`.
type ruleset struct {
	Nftables []json.RawMessage `json:"nftables"`
}

// nftObject captures the fields we care about across the various object kinds.
// Not every field is present on every kind; absent fields decode to zero values.
//
//	table: family, name, handle
//	chain: family, table, name, handle, type, hook, prio, policy
//	rule:  family, table, chain, handle
//	set:   family, table, name, handle
//	map:   family, table, name, handle
type nftObject struct {
	Family string          `json:"family"`
	Table  string          `json:"table"` // owning table name (chain/rule/set/map)
	Name   string          `json:"name"`  // own name (table/chain/set/map)
	Chain  string          `json:"chain"` // owning chain (rule)
	Handle json.RawMessage `json:"handle"`
	Type   string          `json:"type"`
	Hook   string          `json:"hook"`
	Prio   json.RawMessage `json:"prio"`
	Policy string          `json:"policy"`
}

// flattenRuleset parses raw `nft -j list ruleset` JSON and returns one row per
// top-level object (excluding metainfo). It is deliberately exec-free so it can
// be unit-tested against captured fixtures.
func flattenRuleset(data []byte) ([]map[string]string, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	var rs ruleset
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	if rs.Nftables == nil {
		return nil, errors.New(`missing "nftables" key in nft output`)
	}

	rows := make([]map[string]string, 0, len(rs.Nftables))
	for _, raw := range rs.Nftables {
		// Each element is a single-key object: {"<kind>": {...}}.
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, err
		}
		for kind, body := range wrapper {
			if kind == "metainfo" {
				continue
			}

			var obj nftObject
			// A parse failure on one object should not lose the rest; skip it.
			if err := json.Unmarshal(body, &obj); err != nil {
				log.Printf("nftables.ext: skipping malformed %q object: %v", kind, err)
				continue
			}

			rows = append(rows, rowFromObject(kind, obj, body))
		}
	}
	return rows, nil
}

// rowFromObject maps a decoded object to a fully-populated column map. `body` is
// the raw JSON of the object (without the kind wrapper), stored in rule_json.
func rowFromObject(kind string, obj nftObject, body json.RawMessage) map[string]string {
	row := map[string]string{
		"kind":       kind,
		"family":     obj.Family,
		"table_name": tableNameFor(kind, obj),
		"chain":      chainNameFor(kind, obj),
		"handle":     rawToText(obj.Handle),
		"type":       "",
		"hook":       "",
		"priority":   "",
		"policy":     "",
		"rule_json":  string(body),
	}
	// type/hook/priority/policy are only meaningful for base chains.
	if kind == "chain" {
		row["type"] = obj.Type
		row["hook"] = obj.Hook
		row["priority"] = rawToText(obj.Prio)
		row["policy"] = obj.Policy
	}
	return row
}

// tableNameFor returns the table this object belongs to. For a "table" object
// that is its own Name; for everything else it is the Table field.
func tableNameFor(kind string, obj nftObject) string {
	if kind == "table" {
		return obj.Name
	}
	return obj.Table
}

// chainNameFor returns the chain associated with the object: a chain's own name,
// or the owning chain of a rule. Empty for tables/sets/maps.
func chainNameFor(kind string, obj nftObject) string {
	switch kind {
	case "chain":
		return obj.Name
	case "rule":
		return obj.Chain
	default:
		return ""
	}
}

// rawToText renders a json.RawMessage as a plain TEXT value: a JSON string is
// unquoted, a number is kept as-is, and anything else (e.g. a priority given as
// {"name":"filter","offset":0}) is stored as its compact JSON. Absent/null
// fields become "".
func rawToText(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return string(raw)
}
