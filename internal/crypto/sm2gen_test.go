package crypto

import (
	"math/big"
	"testing"
)

func TestSM2GenerateKeyPair(t *testing.T) {
	priv, x, y, err := GenerateSM2KeyPair()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if len(priv) != 32 || len(x) != 32 || len(y) != 32 {
		t.Fatalf("len priv=%d x=%d y=%d", len(priv), len(x), len(y))
	}
	d := new(big.Int).SetBytes(priv)
	if d.Sign() < 1 || d.Cmp(sm2N) >= 0 {
		t.Fatalf("priv out of range [1,n-1]: %x", priv)
	}
	if !onCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
		t.Fatal("public point not on sm2p256v1")
	}
}

func TestSM2Deterministic(t *testing.T) {
	d := make([]byte, 32)
	d[31] = 0x09
	x1, y1 := publicFromD(d)
	x2, y2 := publicFromD(d)
	if string(x1) != string(x2) || string(y1) != string(y2) {
		t.Fatal("non-deterministic from fixed d")
	}
	// P=d*G must be on curve
	if !onCurve(new(big.Int).SetBytes(x1), new(big.Int).SetBytes(y1)) {
		t.Fatal("deterministic point not on curve")
	}
}
