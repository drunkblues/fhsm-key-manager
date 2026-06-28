package cmd

import "testing"

func TestSM2CLIGenGet(t *testing.T) {
	dir := t.TempDir()
	m, err := runCmd(t, dir, "00000000000000000000000000000000", "sm2", "gen", "--index", "3")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if m["priv"] == nil || m["pubX"] == nil || m["pubY"] == nil {
		t.Fatalf("missing fields: %v", m)
	}
	if _, err := runCmd(t, dir, "00000000000000000000000000000000", "sm2", "get", "--index", "3"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
