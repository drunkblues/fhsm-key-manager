package storage

import (
	"os"
	"path/filepath"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestSM2GenGetDelete(t *testing.T) {
	dir := t.TempDir()
	out, err := GenSM2(dir, 7)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	fi, err := os.Stat(dir + "/sm2/0007.SM2")
	if err != nil || fi.Size() != 96 {
		t.Fatalf("file size=%d err=%v want 96", fi.Size(), err)
	}
	got, err := GetSM2(dir, 7)
	if err != nil || string(got.Priv) != string(out.Priv) {
		t.Fatalf("get: %v", err)
	}
	if err := PutSM2(dir, keymodel.SM2Key{Index: 8, Priv: out.Priv, PubX: out.PubX, PubY: out.PubY}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if metas, _ := ListSM2(dir); len(metas) != 2 {
		t.Fatalf("metas=%d", len(metas))
	}
	if err := DeleteSM2(dir, 7); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestSM2SizeMismatch(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, sm2Dir), 0755); err != nil {
		t.Fatal(err)
	}
	// write a malformed (wrong-size) file directly to simulate corruption
	if err := os.WriteFile(sm2Path(dir, 1), []byte("short"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := GetSM2(dir, 1); err == nil {
		t.Fatal("expected SIZE_MISMATCH")
	}
}
