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
