package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestPBOC2RoundTrip(t *testing.T) {
	dir := t.TempDir()
	lsk := bytes.Repeat([]byte{0x22}, 16)
	in := keymodel.PBOC2Key{Type: 0xF0, Index: 0, Subtype: 0, Length: 24, Key: bytes.Repeat([]byte{0xCD}, 24)}

	if err := PutPBOC2(dir, lsk, in); err != nil {
		t.Fatalf("put: %v", err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "pboc2.key"))
	if fi.Size() != int64(pboc2FileSize) {
		t.Fatalf("size=%d want %d", fi.Size(), pboc2FileSize)
	}
	got, err := GetPBOC2(dir, lsk, in.Type, in.Index, in.Subtype)
	if err != nil || !bytes.Equal(got.Key, in.Key) {
		t.Fatalf("get: %+v %v", got, err)
	}

	// reserved [4..6] must be zero (binary compat requirement)
	data, _ := os.ReadFile(filepath.Join(dir, "pboc2.key"))
	if data[4] != 0 || data[5] != 0 || data[6] != 0 {
		t.Fatalf("reserved not zero: %x %x %x", data[4], data[5], data[6])
	}

	metas, _ := ListPBOC2(dir)
	if len(metas) != 1 || metas[0].Type != 0xF0 {
		t.Fatalf("list: %+v", metas)
	}
	if err := DeletePBOC2(dir, lsk, in.Type, in.Index, in.Subtype); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestPBOC2PutOverwritesInPlace(t *testing.T) {
	dir := t.TempDir()
	lsk := bytes.Repeat([]byte{0x22}, 16)
	first := keymodel.PBOC2Key{Type: 0xF0, Index: 1, Subtype: 0, Length: 16, Key: bytes.Repeat([]byte{0xAA}, 16)}
	PutPBOC2(dir, lsk, first)
	second := first
	second.Key = bytes.Repeat([]byte{0xBB}, 16)
	if err := PutPBOC2(dir, lsk, second); err != nil {
		t.Fatal(err)
	}
	all, _ := ReadAllPBOC2(dir, lsk)
	if len(all) != 1 {
		t.Fatalf("overwrite should keep 1 slot, got %d", len(all))
	}
}
