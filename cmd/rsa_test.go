package cmd

import "testing"

func TestRSACLIGenGet(t *testing.T) {
	dir := t.TempDir()
	m, err := runCmd(t, dir, "00000000000000000000000000000000", "rsa", "gen", "--index", "1", "--modlen", "1024")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if m["privDer"] == nil {
		t.Fatal("missing privDer")
	}
	if _, err := runCmd(t, dir, "00000000000000000000000000000000", "rsa", "get", "--index", "1"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
