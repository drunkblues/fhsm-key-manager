package keymodel

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHexBytesRoundTrip(t *testing.T) {
	k := PBOC1Key{Block: 1, Type: 2, Length: 16, Key: HexBytes{0x01, 0x02, 0xab, 0xcd, 0x01, 0x02, 0xab, 0xcd, 0x01, 0x02, 0xab, 0xcd, 0x01, 0x02, 0xab, 0xcd}}
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"key":"0102abcd`) {
		t.Errorf("hex not in json: %s", data)
	}
	var got PBOC1Key
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Key) != 16 || got.Key[2] != 0xab {
		t.Errorf("unmarshal mismatch: %v", got.Key)
	}
}

func TestB64BytesRoundTrip(t *testing.T) {
	k := RSAKey{Index: 5, PrivDer: B64Bytes{0x01, 0x02, 0x03}}
	data, _ := json.Marshal(k)
	if !strings.Contains(string(data), `"privDer":"AQID"`) {
		t.Errorf("b64 not in json: %s", data)
	}
}

func TestErrorFormat(t *testing.T) {
	e := NewError("KEY_NOT_FOUND", "missing %d", 7)
	if e.Error() != "missing 7" || e.Code != "KEY_NOT_FOUND" {
		t.Errorf("bad error: %+v", e)
	}
}

func TestB64BytesUnmarshalRoundTrip(t *testing.T) {
	orig := B64Bytes{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
	k := RSAKey{Index: 1, PrivDer: orig}
	data, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	var got RSAKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.PrivDer) != len(orig) {
		t.Fatalf("len %d != %d", len(got.PrivDer), len(orig))
	}
	for i := range orig {
		if got.PrivDer[i] != orig[i] {
			t.Fatalf("byte %d: %x != %x", i, got.PrivDer[i], orig[i])
		}
	}
}

func TestHexBytesInvalidHex(t *testing.T) {
	var k PBOC1Key
	bad := `{"block":0,"type":0,"version":0,"index":0,"alg":0,"div":0,"exp":0,"length":1,"key":"zz"}`
	if err := json.Unmarshal([]byte(bad), &k); err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestB64BytesInvalidBase64(t *testing.T) {
	var k RSAKey
	bad := `{"index":1,"privDer":"!!!not-base64!!!"}`
	if err := json.Unmarshal([]byte(bad), &k); err == nil {
		t.Fatal("expected error for invalid base64")
	}
}
