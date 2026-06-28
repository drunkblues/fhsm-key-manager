package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestECCRoundTrip(t *testing.T) {
	dir := t.TempDir()
	in := keymodel.ECCKey{Index: 3, Pri: bytes.Repeat([]byte{0x0A}, 48), Pub1: bytes.Repeat([]byte{0x0B}, 48), Pub2: bytes.Repeat([]byte{0x0C}, 48)}
	if err := PutECC(dir, in); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := GetECC(dir, 3)
	if err != nil || !bytes.Equal(got.Pri, in.Pri) || !bytes.Equal(got.Pub1, in.Pub1) {
		t.Fatalf("get: %v", err)
	}
	metas, _ := ListECC(dir)
	if len(metas) != 1 || metas[0].Index != 3 {
		t.Fatalf("list: %+v", metas)
	}
	if err := DeleteECC(dir, 3); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestECCSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	// write a malformed (wrong-size) file directly to simulate corruption
	if err := os.MkdirAll(filepath.Join(dir, eccDir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eccPath(dir, 1), []byte("short"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := GetECC(dir, 1); err == nil {
		t.Fatal("expected SIZE_MISMATCH")
	}
}
