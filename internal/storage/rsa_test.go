package storage

import (
	"crypto/x509"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestRSAGenGetDelete(t *testing.T) {
	dir := t.TempDir()
	out, err := GenRSA(dir, 1, 1024, 65537) // small modulus for fast test
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// priv der parses as PKCS#1
	if _, err := x509.ParsePKCS1PrivateKey(out.PrivDer); err != nil {
		t.Fatalf("parse pkcs1: %v", err)
	}
	if out.ModulusLen != 1024 {
		t.Fatalf("modulusLen=%d", out.ModulusLen)
	}
	got, err := GetRSA(dir, 1)
	if err != nil || string(got.PrivDer) != string(out.PrivDer) {
		t.Fatalf("get: %v", err)
	}
	metas, _ := ListRSA(dir)
	if len(metas) != 1 || metas[0].ModulusLen != 1024 {
		t.Fatalf("list: %+v", metas)
	}
	if err := PutRSA(dir, keymodel.RSAKey{Index: 2, PrivDer: out.PrivDer}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := DeleteRSA(dir, 1); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestRSAPutRejectsInvalidDER(t *testing.T) {
	dir := t.TempDir()
	if err := PutRSA(dir, keymodel.RSAKey{Index: 1, PrivDer: []byte("not-a-valid-der")}); err == nil {
		t.Fatal("expected DER_INVALID for garbage DER")
	}
	if err := PutRSA(dir, keymodel.RSAKey{Index: 1, PrivDer: []byte{}}); err == nil {
		t.Fatal("expected DER_INVALID for empty DER")
	}
}
