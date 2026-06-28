package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestPBOC1RoundTrip(t *testing.T) {
	dir := t.TempDir()
	lsk := bytes.Repeat([]byte{0x11}, 16)
	in := keymodel.PBOC1Key{Block: 1, Type: 2, Version: 0, Index: 1, Alg: 0, Div: 1, Exp: 0,
		Length: 16, Key: bytes.Repeat([]byte{0xAB}, 16)}

	if err := PutPBOC1(dir, lsk, in); err != nil {
		t.Fatalf("put: %v", err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "pboc1.key"))
	if fi.Size() != int64(pboc1FileSize) {
		t.Fatalf("size=%d want %d", fi.Size(), pboc1FileSize)
	}

	got, err := GetPBOC1(dir, lsk, in.Block, in.Type, in.Version, in.Index)
	if err != nil || !bytes.Equal(got.Key, in.Key) || got.Alg != in.Alg {
		t.Fatalf("get mismatch: %+v %v", got, err)
	}

	metas, err := ListPBOC1(dir)
	if err != nil || len(metas) != 1 || metas[0].Index != 1 {
		t.Fatalf("list: %+v %v", metas, err)
	}

	all, err := ReadAllPBOC1(dir, lsk)
	if err != nil || len(all) != 1 {
		t.Fatalf("get-all: %d %v", len(all), err)
	}

	if err := DeletePBOC1(dir, lsk, in.Block, in.Type, in.Version, in.Index); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := GetPBOC1(dir, lsk, in.Block, in.Type, in.Version, in.Index); err == nil {
		t.Fatal("expected KEY_NOT_FOUND after delete")
	}
}

func TestPBOC1BadLength(t *testing.T) {
	dir := t.TempDir()
	bad := keymodel.PBOC1Key{Block: 1, Type: 1, Length: 7, Key: []byte{1, 2, 3, 4, 5, 6, 7}}
	if err := PutPBOC1(dir, bytes.Repeat([]byte{0}, 16), bad); err == nil {
		t.Fatal("expected KEYLEN_INVALID")
	}
}
