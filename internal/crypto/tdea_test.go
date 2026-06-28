package crypto

import (
	"bytes"
	"crypto/des"
	"testing"
)

func Test2TDEARoundTrip(t *testing.T) {
	lsk := []byte("0123456789ABCDEF")
	plain := []byte("12345678abcdefgh")
	enc, err := Encrypt2TDEA(plain, lsk)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(enc, plain) {
		t.Fatal("ciphertext equals plaintext")
	}
	dec, err := Decrypt2TDEA(enc, lsk)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("round-trip mismatch: got %x want %x", dec, plain)
	}
}

// K1==K2 => 2TDEA degenerates to single-DES E_K1.
func Test2TDEADegeneratesToSingleDES(t *testing.T) {
	k1 := []byte("ABCDEFGH")
	lsk := append(append([]byte{}, k1...), k1...)
	plain := []byte("12345678")
	enc, err := Encrypt2TDEA(plain, lsk)
	if err != nil {
		t.Fatal(err)
	}
	c, err := des.NewCipher(k1)
	if err != nil {
		t.Fatalf("new single-des cipher: %v", err)
	}
	want := make([]byte, 8)
	c.Encrypt(want, plain)
	if !bytes.Equal(enc, want) {
		t.Fatalf("K1==K2 should equal single DES: got %x want %x", enc, want)
	}
}

func Test2TDEARejectsBadLSK(t *testing.T) {
	if _, err := Encrypt2TDEA([]byte("12345678"), []byte("short")); err == nil {
		t.Fatal("expected error for short lsk")
	}
}

func Test2TDEARejectsNonBlockAligned(t *testing.T) {
	lsk := []byte("0123456789ABCDEF")
	if _, err := Encrypt2TDEA([]byte("1234567"), lsk); err == nil { // 7 bytes
		t.Fatal("expected error for non-block-aligned plaintext")
	}
	if _, err := Encrypt2TDEA([]byte("123456789"), lsk); err == nil { // 9 bytes
		t.Fatal("expected error for non-block-aligned plaintext")
	}
	if _, err := Decrypt2TDEA([]byte("123456789"), lsk); err == nil { // 9 bytes
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
}
