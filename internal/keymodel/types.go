package keymodel

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) { return json.Marshal(hex.EncodeToString(h)) }
func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	*h = b
	return nil
}

type B64Bytes []byte

func (b B64Bytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}
func (b *B64Bytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dec, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	*b = dec
	return nil
}

type PBOC1Key struct {
	Block   byte     `json:"block"`
	Type    byte     `json:"type"`
	Version byte     `json:"version"`
	Index   byte     `json:"index"`
	Alg     byte     `json:"alg"`
	Div     byte     `json:"div"`
	Exp     byte     `json:"exp"`
	Length  byte     `json:"length"`
	Key     HexBytes `json:"key"`
}

type PBOC1Meta struct {
	Block   byte `json:"block"`
	Type    byte `json:"type"`
	Version byte `json:"version"`
	Index   byte `json:"index"`
	Alg     byte `json:"alg"`
	Div     byte `json:"div"`
	Exp     byte `json:"exp"`
	Length  byte `json:"length"`
}

type PBOC2Key struct {
	Type    byte     `json:"type"`
	Index   byte     `json:"index"`
	Subtype byte     `json:"subtype"`
	Length  byte     `json:"length"`
	Key     HexBytes `json:"key"`
}

type PBOC2Meta struct {
	Type    byte `json:"type"`
	Index   byte `json:"index"`
	Subtype byte `json:"subtype"`
	Length  byte `json:"length"`
}

type RSAKey struct {
	Index      int      `json:"index"`
	ModulusLen int      `json:"modulusLen,omitempty"`
	Exponent   int      `json:"exponent,omitempty"`
	PrivDer    B64Bytes `json:"privDer"`
	PubDer     B64Bytes `json:"pubDer,omitempty"`
}

type RSAMeta struct {
	Index      int `json:"index"`
	ModulusLen int `json:"modulusLen"`
}

type SM2Key struct {
	Index int      `json:"index"`
	Priv  HexBytes `json:"priv"`
	PubX  HexBytes `json:"pubX"`
	PubY  HexBytes `json:"pubY"`
}

type SM2Meta struct {
	Index int `json:"index"`
}

type ECCKey struct {
	Index int      `json:"index"`
	Pri   B64Bytes `json:"pri"`
	Pub1  B64Bytes `json:"pub1"`
	Pub2  B64Bytes `json:"pub2"`
}

type ECCMeta struct {
	Index int `json:"index"`
}
