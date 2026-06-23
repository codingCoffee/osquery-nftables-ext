// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"testing"
)

// loadFixture returns the captured `nft -j list ruleset` sample. The tests
// never shell out to a real nft binary.
func loadFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/ruleset.json")
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func TestFlattenRuleset_RowCountSkipsMetainfo(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}
	// 2 tables + 3 chains + 3 rules + 1 set + 1 map = 10 rows; metainfo skipped.
	if got, want := len(rows), 10; got != want {
		t.Fatalf("row count = %d, want %d", got, want)
	}
}

func TestFlattenRuleset_BaseChain(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}

	row := findRow(t, rows, func(r map[string]string) bool {
		return r["kind"] == "chain" && r["chain"] == "input"
	})

	assertField(t, row, "family", "inet")
	assertField(t, row, "table_name", "filter")
	assertField(t, row, "handle", "4")
	assertField(t, row, "type", "filter")
	assertField(t, row, "hook", "input")
	assertField(t, row, "priority", "0")
	assertField(t, row, "policy", "drop")
}

func TestFlattenRuleset_RegularChainHasNoBaseFields(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}

	row := findRow(t, rows, func(r map[string]string) bool {
		return r["kind"] == "chain" && r["chain"] == "log_and_drop"
	})

	for _, col := range []string{"type", "hook", "priority", "policy"} {
		assertField(t, row, col, "")
	}
}

func TestFlattenRuleset_Rule(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}

	row := findRow(t, rows, func(r map[string]string) bool {
		return r["kind"] == "rule" && r["handle"] == "6"
	})

	assertField(t, row, "family", "inet")
	assertField(t, row, "table_name", "filter")
	assertField(t, row, "chain", "input")
	// Base-chain-only columns must stay empty for rules.
	assertField(t, row, "type", "")
	assertField(t, row, "hook", "")
	assertField(t, row, "policy", "")

	// rule_json must be the raw object and must round-trip as valid JSON that
	// still contains the rule's expression list.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(row["rule_json"]), &parsed); err != nil {
		t.Fatalf("rule_json is not valid JSON: %v", err)
	}
	if _, ok := parsed["expr"]; !ok {
		t.Errorf("rule_json missing expr key: %s", row["rule_json"])
	}
}

func TestFlattenRuleset_Table(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}

	row := findRow(t, rows, func(r map[string]string) bool {
		return r["kind"] == "table" && r["family"] == "ip"
	})

	assertField(t, row, "table_name", "nat")
	assertField(t, row, "handle", "9")
	assertField(t, row, "chain", "")
}

func TestFlattenRuleset_SetAndMap(t *testing.T) {
	rows, err := flattenRuleset(loadFixture(t))
	if err != nil {
		t.Fatalf("flattenRuleset: %v", err)
	}

	set := findRow(t, rows, func(r map[string]string) bool { return r["kind"] == "set" })
	assertField(t, set, "table_name", "filter")
	assertField(t, set, "chain", "")
	assertField(t, set, "handle", "2")

	m := findRow(t, rows, func(r map[string]string) bool { return r["kind"] == "map" })
	assertField(t, m, "table_name", "filter")
	assertField(t, m, "chain", "")
	assertField(t, m, "handle", "3")
}

func TestFlattenRuleset_Errors(t *testing.T) {
	cases := map[string]struct {
		input   []byte
		wantErr bool
	}{
		"empty":            {input: []byte{}, wantErr: true},
		"not json":         {input: []byte("not json at all"), wantErr: true},
		"missing key":      {input: []byte(`{"something":[]}`), wantErr: true},
		"empty ruleset ok": {input: []byte(`{"nftables":[]}`), wantErr: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rows, err := flattenRuleset(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error, got rows=%v", rows)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRawToText(t *testing.T) {
	cases := map[string]struct {
		in   string
		want string
	}{
		"number":      {in: `100`, want: "100"},
		"string":      {in: `"accept"`, want: "accept"},
		"null":        {in: `null`, want: ""},
		"empty":       {in: ``, want: ""},
		"prio object": {in: `{"name":"filter","offset":0}`, want: `{"name":"filter","offset":0}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := rawToText(json.RawMessage(tc.in)); got != tc.want {
				t.Errorf("rawToText(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// --- helpers ---

func findRow(t *testing.T, rows []map[string]string, pred func(map[string]string) bool) map[string]string {
	t.Helper()
	for _, r := range rows {
		if pred(r) {
			return r
		}
	}
	t.Fatalf("no matching row found among %d rows", len(rows))
	return nil
}

func assertField(t *testing.T, row map[string]string, col, want string) {
	t.Helper()
	if got := row[col]; got != want {
		t.Errorf("column %q = %q, want %q", col, got, want)
	}
}
