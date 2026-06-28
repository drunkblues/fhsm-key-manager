package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestECCCLIPutGet(t *testing.T) {
	dir := t.TempDir()
	// pri/pub1/pub2 = 48 bytes each (0x0A / 0x0B / 0x0C), base64-encoded.
	// eccFileSz = 144 = pri(48) + pub1(48) + pub2(48); GetECC size-check requires this.
	in := `{"index":2,"pri":"CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoK","pub1":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsL","pub2":"DAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM"}`
	tmp := filepath.Join(dir, "in.json")
	os.WriteFile(tmp, []byte(in), 0644)
	orig := os.Stdin
	f, _ := os.Open(tmp)
	os.Stdin = f
	_, err := runCmd(t, dir, "00000000000000000000000000000000", "ecc", "put")
	os.Stdin = orig
	f.Close()
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	m, err := runCmd(t, dir, "00000000000000000000000000000000", "ecc", "get", "--index", "2")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if m["pri"] == nil {
		t.Fatal("get missing pri")
	}
}
