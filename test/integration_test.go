package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// moduleRoot resolves the repository root from this test file's location
// (test/integration_test.go -> parent dir). The build must run there because
// `go build .` targets the main package at the module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, this, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(filepath.Dir(this))
}

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fhsm-key-manager")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = moduleRoot(t)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestEndToEndPBOC1(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	put := `{"block":1,"type":1,"version":0,"index":1,"alg":0,"div":1,"exp":0,"length":16,"key":"01020304050607080102030405060708"}`
	c := exec.Command(bin, "--path", dir, "--lsk", "11111111111111111111111111111111", "pboc1", "put")
	c.Stdin = strings.NewReader(put)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("put: %v\n%s", err, out)
	}
	g := exec.Command(bin, "--path", dir, "--lsk", "11111111111111111111111111111111", "pboc1", "get", "--block", "1", "--type", "1", "--version", "0", "--index", "1")
	out, err := g.Output()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &m); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if m["key"] != "01020304050607080102030405060708" {
		t.Errorf("key mismatch: %v", m["key"])
	}
	if _, err := os.Stat(filepath.Join(dir, "pboc1.key")); err != nil {
		t.Fatalf("file missing: %v", err)
	}
}

func TestEndToEndRSA(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	gen := exec.Command(bin, "--path", dir, "rsa", "gen", "--index", "1", "--modlen", "1024")
	out, err := gen.Output()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &m); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if m["privDer"] == nil {
		t.Fatal("gen missing privDer")
	}
}
