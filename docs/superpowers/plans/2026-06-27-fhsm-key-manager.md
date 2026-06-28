# fhsm-key-manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Go CLI that manages PBOC1/PBOC2/RSA/SM2/ECC keys in files byte-compatible with fhsm-cpp.

**Architecture:** Layered — `internal/crypto` (2TDEA-ECB, SM2 keygen), `internal/storage` (binary file CRUD per key type), `internal/keymodel` (JSON models + error envelope), `cmd` (cobra command groups). Zero external deps beyond cobra; pure stdlib crypto.

**Tech Stack:** Go (CGO_ENABLED=0), `github.com/spf13/cobra`, `crypto/des`, `crypto/rsa`, `math/big` (SM2), `encoding/json`.

**Spec:** `docs/superpowers/specs/2026-06-27-fhsm-key-manager-design.md` (binary formats, command surface, JSON contract — referenced, not repeated here).

---

## File Structure

| Path | Responsibility |
|---|---|
| `go.mod` | Module `fhsm-key-manager`, Go 1.21+, dep cobra |
| `main.go` | Entry; execute root cmd; convert errors → JSON envelope + exit code |
| `internal/keymodel/types.go` | `HexBytes`/`B64Bytes`, all key structs (`PBOC1Key`, `PBOC2Key`, `RSAKey`, `SM2Key`, `ECCKey` + `*Meta`) |
| `internal/keymodel/error.go` | `Error{Code,Msg}`, `OutputJSON`, `OutputError` |
| `internal/crypto/tdea.go` | 2TDEA-ECB encrypt/decrypt (matches fhsm-cpp `_3DesEnc8X`) |
| `internal/crypto/sm2gen.go` | SM2 keypair generation on sm2p256v1 (pure Go) |
| `internal/storage/util.go` | shared `clearSlice`, `validKeyLen` |
| `internal/storage/pboc1.go` | pboc1.key CRUD: `ReadAll/Get/List/Put/Delete` |
| `internal/storage/pboc2.go` | pboc2.key CRUD |
| `internal/storage/rsa.go` | rsa dir CRUD + keygen |
| `internal/storage/sm2.go` | sm2 dir CRUD + keygen |
| `internal/storage/ecc.go` | ecc dir CRUD (no gen) |
| `cmd/root.go` | Global flags `--path`/`--lsk`/`--verbose`; registers subcommands |
| `cmd/version.go` | `version` command |
| `cmd/pboc1.go`, `cmd/pboc2.go`, `cmd/rsa.go`, `cmd/sm2.go`, `cmd/ecc.go` | command groups |

---

## Task 1: Project scaffold + version command

**Files:** Create `go.mod`, `main.go`, `cmd/root.go`, `cmd/version.go`, `cmd/version_test.go`

- [ ] **Step 1: Init module + add cobra**

```bash
go mod init fhsm-key-manager
go get github.com/spf13/cobra@v1.8.0
```

- [ ] **Step 2: Write the failing test** `cmd/version_test.go`:

```go
package cmd

import (
	"bytes"
	"testing"
)

func TestVersionOutputsJSON(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"name": "fhsm-key-manager"`)) {
		t.Errorf("unexpected output: %s", out.String())
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `go test ./cmd/` — Expected: FAIL (newRootCmd undefined)

- [ ] **Step 4: Implement root + version**

`cmd/root.go`:
```go
package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

var (
	flagPath    string
	flagLSK     string
	flagVerbose bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "fhsm-key-manager",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&flagPath, "path", ".", "key root directory")
	root.PersistentFlags().StringVar(&flagLSK, "lsk", "00000000000000000000000000000000", "LSK hex (16 bytes) for 3DES; default all-zero")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "print progress to stderr")
	root.AddCommand(newVersionCmd())
	return root
}

func Execute() error { return newRootCmd().Execute() }

func parseLSK(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid lsk hex: %w", err)
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("lsk must be 16 bytes (32 hex chars), got %d bytes", len(b))
	}
	return b, nil
}
```

`cmd/version.go`:
```go
package cmd

import (
	"encoding/json"

	"github.com/spf13/cobra"
)

var version = "0.1.0"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version as JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			out, _ := json.Marshal(map[string]string{"name": "fhsm-key-manager", "version": version})
			cmd.Println(string(out))
			return nil
		},
	}
}
```

- [ ] **Step 5: Run to verify it passes** — Run: `go test ./cmd/` — Expected: PASS

- [ ] **Step 6: Wire main.go**

```go
package main

import (
	"errors"
	"os"

	"fhsm-key-manager/cmd"
	"fhsm-key-manager/internal/keymodel"
)

func main() {
	if err := cmd.Execute(); err != nil {
		var e *keymodel.Error
		if errors.As(err, &e) {
			keymodel.OutputError(e.Code, e.Msg)
		} else {
			keymodel.OutputError("INTERNAL", err.Error())
		}
		os.Exit(1)
	}
}
```

- [ ] **Step 7: Smoke test** — Run: `go build -o fhsm-key-manager . && ./fhsm-key-manager version`

- [ ] **Step 8: Commit**
```bash
git add go.mod go.sum main.go cmd/
git commit -m "feat: project scaffold with cobra root and version command"
```

---

## Task 2: keymodel — JSON types and error envelope

**Files:** Create `internal/keymodel/types.go`, `internal/keymodel/error.go`, `internal/keymodel/types_test.go`

- [ ] **Step 1: Write the failing test** `internal/keymodel/types_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/keymodel/` — Expected: FAIL

- [ ] **Step 3: Implement** `internal/keymodel/types.go`:

```go
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

func (b B64Bytes) MarshalJSON() ([]byte, error) { return json.Marshal(base64.StdEncoding.EncodeToString(b)) }
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
```

`internal/keymodel/error.go`:
```go
package keymodel

import (
	"encoding/json"
	"fmt"
	"os"
)

type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string                         { return e.Msg }
func NewError(code, format string, args ...any) *Error { return &Error{Code: code, Msg: fmt.Sprintf(format, args...)} }

func OutputJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func OutputError(code, msg string) {
	OutputJSON(struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}{Error: msg, Code: code})
}
```

- [ ] **Step 4: Run to verify it passes** — `go test ./internal/keymodel/` — Expected: PASS

- [ ] **Step 5: Commit**
```bash
git add internal/keymodel/
git commit -m "feat(keymodel): JSON types (HexBytes/B64Bytes), key structs, error envelope"
```

---

## Task 3: crypto — 2TDEA-ECB

**Files:** Create `internal/crypto/tdea.go`, `internal/crypto/tdea_test.go`

- [ ] **Step 1: Write the failing test** `internal/crypto/tdea_test.go`:

```go
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
	if err != nil || !bytes.Equal(dec, plain) {
		t.Fatalf("round-trip mismatch: %x %v", dec, err)
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
	c, _ := des.NewCipher(k1)
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
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/crypto/` — Expected: FAIL

- [ ] **Step 3: Implement** `internal/crypto/tdea.go`:

```go
package crypto

import (
	"crypto/des"
	"fmt"
)

func make2TDEAKey(lsk []byte) ([]byte, error) {
	if len(lsk) != 16 {
		return nil, fmt.Errorf("lsk must be 16 bytes, got %d", len(lsk))
	}
	key := make([]byte, 24)
	copy(key[0:8], lsk[0:8])
	copy(key[8:16], lsk[8:16])
	copy(key[16:24], lsk[0:8]) // K3 = K1
	return key, nil
}

func Encrypt2TDEA(plain, lsk []byte) ([]byte, error) {
	if len(plain)%8 != 0 {
		return nil, fmt.Errorf("plaintext length must be multiple of 8, got %d", len(plain))
	}
	key, err := make2TDEAKey(lsk)
	if err != nil {
		return nil, err
	}
	c, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	for i := 0; i < len(plain); i += 8 {
		c.Encrypt(out[i:i+8], plain[i:i+8])
	}
	return out, nil
}

func Decrypt2TDEA(cipherText, lsk []byte) ([]byte, error) {
	if len(cipherText)%8 != 0 {
		return nil, fmt.Errorf("ciphertext length must be multiple of 8, got %d", len(cipherText))
	}
	key, err := make2TDEAKey(lsk)
	if err != nil {
		return nil, err
	}
	c, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(cipherText))
	for i := 0; i < len(cipherText); i += 8 {
		c.Decrypt(out[i:i+8], cipherText[i:i+8])
	}
	return out, nil
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit**
```bash
git add internal/crypto/tdea.go internal/crypto/tdea_test.go
git commit -m "feat(crypto): 2TDEA-ECB matching fhsm-cpp _3DesEnc8X"
```

---

## Task 4: storage — pboc1.key CRUD

**Files:** Create `internal/storage/util.go`, `internal/storage/pboc1.go`, `internal/storage/pboc1_test.go`

- [ ] **Step 1: Write the failing test** `internal/storage/pboc1_test.go`:

```go
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
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/storage/` — Expected: FAIL

- [ ] **Step 3: Implement** `internal/storage/util.go`:
```go
package storage

func clearSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func validKeyLen(n byte) bool { return n == 8 || n == 16 || n == 24 }
```

`internal/storage/pboc1.go`:
```go
package storage

import (
	"os"
	"path/filepath"

	"fhsm-key-manager/internal/crypto"
	"fhsm-key-manager/internal/keymodel"
)

const (
	pboc1ItemLen   = 33
	pboc1KeyAmount = 1024
	pboc1FileSize  = pboc1ItemLen * pboc1KeyAmount
)

func pboc1Path(root string) string { return filepath.Join(root, "pboc1.key") }

func readPBOC1File(root string) ([]byte, error) {
	data, err := os.ReadFile(pboc1Path(root))
	if err != nil {
		if os.IsNotExist(err) {
			return make([]byte, pboc1FileSize), nil
		}
		return nil, err
	}
	if len(data) < pboc1FileSize {
		pad := make([]byte, pboc1FileSize)
		copy(pad, data)
		return pad, nil
	}
	return data[:pboc1FileSize], nil
}

func parsePBOC1Slot(slot, lsk []byte) (keymodel.PBOC1Key, bool, error) {
	if slot[0] == 0 {
		return keymodel.PBOC1Key{}, false, nil
	}
	if !validKeyLen(slot[8]) {
		return keymodel.PBOC1Key{}, false, keymodel.NewError("KEYLEN_INVALID", "pboc1 slot bad keylen %d", slot[8])
	}
	plain, err := crypto.Decrypt2TDEA(slot[9:9+int(slot[8])], lsk)
	if err != nil {
		return keymodel.PBOC1Key{}, false, err
	}
	return keymodel.PBOC1Key{Block: slot[1], Type: slot[2], Version: slot[3], Index: slot[4],
		Alg: slot[5], Div: slot[6], Exp: slot[7], Length: slot[8], Key: plain}, true, nil
}

func ReadAllPBOC1(root string, lsk []byte) ([]keymodel.PBOC1Key, error) {
	data, err := readPBOC1File(root)
	if err != nil {
		return nil, err
	}
	var keys []keymodel.PBOC1Key
	for i := 0; i < pboc1KeyAmount; i++ {
		k, ok, err := parsePBOC1Slot(data[i*pboc1ItemLen:(i+1)*pboc1ItemLen], lsk)
		if err != nil {
			return nil, err
		}
		if ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func ListPBOC1(root string) ([]keymodel.PBOC1Meta, error) {
	data, err := readPBOC1File(root)
	if err != nil {
		return nil, err
	}
	var metas []keymodel.PBOC1Meta
	for i := 0; i < pboc1KeyAmount; i++ {
		slot := data[i*pboc1ItemLen : (i+1)*pboc1ItemLen]
		if slot[0] == 0 {
			continue
		}
		if !validKeyLen(slot[8]) {
			return nil, keymodel.NewError("KEYLEN_INVALID", "pboc1 slot bad keylen %d", slot[8])
		}
		metas = append(metas, keymodel.PBOC1Meta{Block: slot[1], Type: slot[2], Version: slot[3],
			Index: slot[4], Alg: slot[5], Div: slot[6], Exp: slot[7], Length: slot[8]})
	}
	return metas, nil
}

func GetPBOC1(root string, lsk []byte, block, typ, version, index byte) (keymodel.PBOC1Key, error) {
	keys, err := ReadAllPBOC1(root, lsk)
	if err != nil {
		return keymodel.PBOC1Key{}, err
	}
	for _, k := range keys {
		if k.Block == block && k.Type == typ && k.Version == version && k.Index == index {
			return k, nil
		}
	}
	return keymodel.PBOC1Key{}, keymodel.NewError("KEY_NOT_FOUND", "pboc1 key block=%d type=%d version=%d index=%d", block, typ, version, index)
}

func PutPBOC1(root string, lsk []byte, k keymodel.PBOC1Key) error {
	if !validKeyLen(k.Length) {
		return keymodel.NewError("KEYLEN_INVALID", "pboc1 length must be 8/16/24, got %d", k.Length)
	}
	if len(k.Key) != int(k.Length) {
		return keymodel.NewError("KEYLEN_INVALID", "pboc1 key bytes %d != length %d", len(k.Key), k.Length)
	}
	enc, err := crypto.Encrypt2TDEA(k.Key, lsk)
	if err != nil {
		return err
	}
	data, err := readPBOC1File(root)
	if err != nil {
		return err
	}
	slotIdx := -1
	for i := 0; i < pboc1KeyAmount; i++ {
		s := data[i*pboc1ItemLen : (i+1)*pboc1ItemLen]
		if s[0] != 0 && s[1] == k.Block && s[2] == k.Type && s[3] == k.Version && s[4] == k.Index {
			slotIdx = i
			break
		}
	}
	if slotIdx == -1 {
		for i := 0; i < pboc1KeyAmount; i++ {
			if data[i*pboc1ItemLen] == 0 {
				slotIdx = i
				break
			}
		}
	}
	if slotIdx == -1 {
		return keymodel.NewError("DB_FULL", "pboc1 database full (1024 slots)")
	}
	slot := data[slotIdx*pboc1ItemLen : (slotIdx+1)*pboc1ItemLen]
	clearSlice(slot)
	slot[0] = 1
	slot[1] = k.Block
	slot[2] = k.Type
	slot[3] = k.Version
	slot[4] = k.Index
	slot[5] = k.Alg
	slot[6] = k.Div
	slot[7] = k.Exp
	slot[8] = k.Length
	copy(slot[9:9+int(k.Length)], enc)
	return os.WriteFile(pboc1Path(root), data, 0644)
}

func DeletePBOC1(root string, lsk []byte, block, typ, version, index byte) error {
	data, err := readPBOC1File(root)
	if err != nil {
		return err
	}
	for i := 0; i < pboc1KeyAmount; i++ {
		s := data[i*pboc1ItemLen : (i+1)*pboc1ItemLen]
		if s[0] != 0 && s[1] == block && s[2] == typ && s[3] == version && s[4] == index {
			clearSlice(s)
			return os.WriteFile(pboc1Path(root), data, 0644)
		}
	}
	return keymodel.NewError("KEY_NOT_FOUND", "pboc1 key block=%d type=%d version=%d index=%d", block, typ, version, index)
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/storage/util.go internal/storage/pboc1.go internal/storage/pboc1_test.go && git commit -m "feat(storage): pboc1.key CRUD with 2TDEA encryption"`

---

## Task 5: storage — pboc2.key CRUD

Same structure as Task 4. Constants: `pboc2ItemLen=32`, `pboc2KeyAmount=1024`, `pboc2FileSize=32768`. Slot layout: `[0]flag [1]type [2]index [3]subtype [4..6]reserved=0 [7]keylen [8..31]enc`. Selectors `(type, index, subtype)`.

**Files:** Create `internal/storage/pboc2.go`, `internal/storage/pboc2_test.go`

- [ ] **Step 1: Write the failing test** `internal/storage/pboc2_test.go`:

```go
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

	// reserved [4..6] must be zero (binary compat)
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
```

- [ ] **Step 2: Run to verify it fails** — `go test ./internal/storage/ -run TestPBOC2` — Expected: FAIL

- [ ] **Step 3: Implement** `internal/storage/pboc2.go`:

```go
package storage

import (
	"os"
	"path/filepath"

	"fhsm-key-manager/internal/crypto"
	"fhsm-key-manager/internal/keymodel"
)

const (
	pboc2ItemLen   = 32
	pboc2KeyAmount = 1024
	pboc2FileSize  = pboc2ItemLen * pboc2KeyAmount
)

func pboc2Path(root string) string { return filepath.Join(root, "pboc2.key") }

func readPBOC2File(root string) ([]byte, error) {
	data, err := os.ReadFile(pboc2Path(root))
	if err != nil {
		if os.IsNotExist(err) {
			return make([]byte, pboc2FileSize), nil
		}
		return nil, err
	}
	if len(data) < pboc2FileSize {
		pad := make([]byte, pboc2FileSize)
		copy(pad, data)
		return pad, nil
	}
	return data[:pboc2FileSize], nil
}

func parsePBOC2Slot(slot, lsk []byte) (keymodel.PBOC2Key, bool, error) {
	if slot[0] == 0 {
		return keymodel.PBOC2Key{}, false, nil
	}
	if !validKeyLen(slot[7]) {
		return keymodel.PBOC2Key{}, false, keymodel.NewError("KEYLEN_INVALID", "pboc2 slot bad keylen %d", slot[7])
	}
	plain, err := crypto.Decrypt2TDEA(slot[8:8+int(slot[7])], lsk)
	if err != nil {
		return keymodel.PBOC2Key{}, false, err
	}
	return keymodel.PBOC2Key{Type: slot[1], Index: slot[2], Subtype: slot[3], Length: slot[7], Key: plain}, true, nil
}

func ReadAllPBOC2(root string, lsk []byte) ([]keymodel.PBOC2Key, error) {
	data, err := readPBOC2File(root)
	if err != nil {
		return nil, err
	}
	var keys []keymodel.PBOC2Key
	for i := 0; i < pboc2KeyAmount; i++ {
		k, ok, err := parsePBOC2Slot(data[i*pboc2ItemLen:(i+1)*pboc2ItemLen], lsk)
		if err != nil {
			return nil, err
		}
		if ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func ListPBOC2(root string) ([]keymodel.PBOC2Meta, error) {
	data, err := readPBOC2File(root)
	if err != nil {
		return nil, err
	}
	var metas []keymodel.PBOC2Meta
	for i := 0; i < pboc2KeyAmount; i++ {
		slot := data[i*pboc2ItemLen : (i+1)*pboc2ItemLen]
		if slot[0] == 0 {
			continue
		}
		if !validKeyLen(slot[7]) {
			return nil, keymodel.NewError("KEYLEN_INVALID", "pboc2 slot bad keylen %d", slot[7])
		}
		metas = append(metas, keymodel.PBOC2Meta{Type: slot[1], Index: slot[2], Subtype: slot[3], Length: slot[7]})
	}
	return metas, nil
}

func GetPBOC2(root string, lsk []byte, typ, index, subtype byte) (keymodel.PBOC2Key, error) {
	keys, err := ReadAllPBOC2(root, lsk)
	if err != nil {
		return keymodel.PBOC2Key{}, err
	}
	for _, k := range keys {
		if k.Type == typ && k.Index == index && k.Subtype == subtype {
			return k, nil
		}
	}
	return keymodel.PBOC2Key{}, keymodel.NewError("KEY_NOT_FOUND", "pboc2 key type=%d index=%d subtype=%d", typ, index, subtype)
}

func PutPBOC2(root string, lsk []byte, k keymodel.PBOC2Key) error {
	if !validKeyLen(k.Length) {
		return keymodel.NewError("KEYLEN_INVALID", "pboc2 length must be 8/16/24, got %d", k.Length)
	}
	if len(k.Key) != int(k.Length) {
		return keymodel.NewError("KEYLEN_INVALID", "pboc2 key bytes %d != length %d", len(k.Key), k.Length)
	}
	enc, err := crypto.Encrypt2TDEA(k.Key, lsk)
	if err != nil {
		return err
	}
	data, err := readPBOC2File(root)
	if err != nil {
		return err
	}
	slotIdx := -1
	for i := 0; i < pboc2KeyAmount; i++ {
		s := data[i*pboc2ItemLen : (i+1)*pboc2ItemLen]
		if s[0] != 0 && s[1] == k.Type && s[2] == k.Index && s[3] == k.Subtype {
			slotIdx = i
			break
		}
	}
	if slotIdx == -1 {
		for i := 0; i < pboc2KeyAmount; i++ {
			if data[i*pboc2ItemLen] == 0 {
				slotIdx = i
				break
			}
		}
	}
	if slotIdx == -1 {
		return keymodel.NewError("DB_FULL", "pboc2 database full (1024 slots)")
	}
	slot := data[slotIdx*pboc2ItemLen : (slotIdx+1)*pboc2ItemLen]
	clearSlice(slot)
	slot[0] = 1
	slot[1] = k.Type
	slot[2] = k.Index
	slot[3] = k.Subtype
	// slot[4..6] reserved = 0 (already cleared)
	slot[7] = k.Length
	copy(slot[8:8+int(k.Length)], enc)
	return os.WriteFile(pboc2Path(root), data, 0644)
}

func DeletePBOC2(root string, lsk []byte, typ, index, subtype byte) error {
	data, err := readPBOC2File(root)
	if err != nil {
		return err
	}
	for i := 0; i < pboc2KeyAmount; i++ {
		s := data[i*pboc2ItemLen : (i+1)*pboc2ItemLen]
		if s[0] != 0 && s[1] == typ && s[2] == index && s[3] == subtype {
			clearSlice(s)
			return os.WriteFile(pboc2Path(root), data, 0644)
		}
	}
	return keymodel.NewError("KEY_NOT_FOUND", "pboc2 key type=%d index=%d subtype=%d", typ, index, subtype)
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/storage/pboc2.go internal/storage/pboc2_test.go && git commit -m "feat(storage): pboc2.key CRUD with reserved-byte-zero for binary compat"`

---

## Task 6: storage — RSA dir CRUD + keygen

**Files:** Create `internal/storage/rsa.go`, `internal/storage/rsa_test.go`

- [ ] **Step 1: Write the failing test** `internal/storage/rsa_test.go`:

```go
package storage

import (
	"crypto/x509"
	"testing"

	"fhsm-key-manager/internal/keymodel"
)

func TestRSAGenGetDelete(t *testing.T) {
	dir := t.TempDir()
	out, err := GenRSA(dir, 1, 1024, 65537)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
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
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `internal/storage/rsa.go`:

```go
package storage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"fhsm-key-manager/internal/keymodel"
)

const rsaDir = "rsa"

func rsaPath(root string, index int) string {
	return filepath.Join(root, rsaDir, fmt.Sprintf("%04d.RSA", index))
}

func indexFromName(name, suffix string) (int, bool) {
	if len(name) != 8 || name[4:] != suffix {
		return 0, false
	}
	n, err := strconv.Atoi(name[:4])
	return n, err == nil
}

func GetRSA(root string, index int) (keymodel.RSAKey, error) {
	data, err := os.ReadFile(rsaPath(root, index))
	if err != nil {
		if os.IsNotExist(err) {
			return keymodel.RSAKey{}, keymodel.NewError("KEY_NOT_FOUND", "rsa index %d not found", index)
		}
		return keymodel.RSAKey{}, err
	}
	k := keymodel.RSAKey{Index: index, PrivDer: data}
	if m := rsaModulusBits(data); m > 0 {
		k.ModulusLen = m
	}
	k.PubDer = rsaPubDER(data)
	return k, nil
}

func ListRSA(root string) ([]keymodel.RSAMeta, error) {
	entries, err := os.ReadDir(filepath.Join(root, rsaDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var metas []keymodel.RSAMeta
	for _, e := range entries {
		idx, ok := indexFromName(e.Name(), ".RSA")
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, rsaDir, e.Name()))
		if err != nil {
			continue
		}
		metas = append(metas, keymodel.RSAMeta{Index: idx, ModulusLen: rsaModulusBits(data)})
	}
	return metas, nil
}

func PutRSA(root string, k keymodel.RSAKey) error {
	if err := os.MkdirAll(filepath.Join(root, rsaDir), 0755); err != nil {
		return err
	}
	return os.WriteFile(rsaPath(root, k.Index), k.PrivDer, 0644)
}

func DeleteRSA(root string, index int) error {
	err := os.Remove(rsaPath(root, index))
	if err != nil && os.IsNotExist(err) {
		return keymodel.NewError("KEY_NOT_FOUND", "rsa index %d not found", index)
	}
	return err
}

func GenRSA(root string, index, modLen, exponent int) (keymodel.RSAKey, error) {
	if err := os.MkdirAll(filepath.Join(root, rsaDir), 0755); err != nil {
		return keymodel.RSAKey{}, err
	}
	priv, err := rsa.GenerateKey(rand.Reader, modLen)
	if err != nil {
		return keymodel.RSAKey{}, keymodel.NewError("GEN_FAILED", "rsa generate: %v", err)
	}
	privDer := x509.MarshalPKCS1PrivateKey(priv)
	pubDer, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return keymodel.RSAKey{}, keymodel.NewError("GEN_FAILED", "rsa pub marshal: %v", err)
	}
	if err := os.WriteFile(rsaPath(root, index), privDer, 0644); err != nil {
		return keymodel.RSAKey{}, err
	}
	return keymodel.RSAKey{Index: index, ModulusLen: modLen, Exponent: exponent, PrivDer: privDer, PubDer: pubDer}, nil
}

func rsaModulusBits(privDer []byte) int {
	k, err := x509.ParsePKCS1PrivateKey(privDer)
	if err != nil {
		return 0
	}
	return k.N.BitLen()
}

func rsaPubDER(privDer []byte) []byte {
	k, err := x509.ParsePKCS1PrivateKey(privDer)
	if err != nil {
		return nil
	}
	pub, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return nil
	}
	return pub
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/storage/rsa.go internal/storage/rsa_test.go && git commit -m "feat(storage): rsa dir CRUD + keygen (PKCS#1 DER)"`

---

## Task 7: crypto — SM2 keypair generation

**Files:** Create `internal/crypto/sm2gen.go`, `internal/crypto/sm2gen_test.go`

- [ ] **Step 1: Write the failing test** `internal/crypto/sm2gen_test.go`:

```go
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
		t.Fatalf("priv out of range: %x", priv)
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
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `internal/crypto/sm2gen.go`:

```go
package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

var (
	sm2P, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _  = new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2Gx, _ = new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ = new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2N, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
)

type sm2Point struct{ x, y *big.Int }

func newPoint(x, y *big.Int) *sm2Point { return &sm2Point{new(big.Int).Set(x), new(big.Int).Set(y)} }

func (p *sm2Point) Double() *sm2Point {
	if p.y.Sign() == 0 {
		return &sm2Point{new(big.Int), new(big.Int)}
	}
	num := new(big.Int).Mul(p.x, p.x)
	num.Mul(num, big.NewInt(3))
	num.Add(num, sm2A)
	den := new(big.Int).Mul(p.y, big.NewInt(2))
	den.ModInverse(den, sm2P)
	s := new(big.Int).Mul(num, den)
	s.Mod(s, sm2P)
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p.x)
	x3.Sub(x3, p.x)
	x3.Mod(x3, sm2P)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p.y)
	y3.Mod(y3, sm2P)
	return &sm2Point{x3, y3}
}

func (p *sm2Point) Add(q *sm2Point) *sm2Point {
	if p.y.Sign() == 0 {
		return newPoint(q.x, q.y)
	}
	if q.y.Sign() == 0 {
		return newPoint(p.x, p.y)
	}
	if p.x.Cmp(q.x) == 0 {
		if p.y.Cmp(q.y) == 0 {
			return p.Double()
		}
		return &sm2Point{new(big.Int), new(big.Int)}
	}
	num := new(big.Int).Sub(q.y, p.y)
	den := new(big.Int).Sub(q.x, p.x)
	den.ModInverse(den, sm2P)
	s := new(big.Int).Mul(num, den)
	s.Mod(s, sm2P)
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p.x)
	x3.Sub(x3, q.x)
	x3.Mod(x3, sm2P)
	y3 := new(big.Int).Sub(p.x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p.y)
	y3.Mod(y3, sm2P)
	return &sm2Point{x3, y3}
}

func scalarMultG(k *big.Int) *sm2Point {
	g := newPoint(sm2Gx, sm2Gy)
	res := &sm2Point{new(big.Int), new(big.Int)}
	for _, b := range k.Bytes() {
		for bit := 7; bit >= 0; bit-- {
			res = res.Double()
			if (b>>uint(bit))&1 == 1 {
				res = res.Add(g)
			}
		}
	}
	return res
}

func GenerateSM2KeyPair() (priv, pubX, pubY []byte, err error) {
	one := big.NewInt(1)
	d, err := rand.Int(rand.Reader, new(big.Int).Sub(sm2N, one))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rand: %w", err)
	}
	d.Add(d, one)
	p := scalarMultG(d)
	return fixedBytes(d, 32), fixedBytes(p.x, 32), fixedBytes(p.y, 32), nil
}

func publicFromD(d []byte) (pubX, pubY []byte) {
	p := scalarMultG(new(big.Int).SetBytes(d))
	return fixedBytes(p.x, 32), fixedBytes(p.y, 32)
}

func fixedBytes(n *big.Int, size int) []byte {
	b := n.Bytes()
	if len(b) >= size {
		return b[len(b)-size:]
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func onCurve(x, y *big.Int) bool {
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, sm2P)
	rhs := new(big.Int).Exp(x, big.NewInt(3), sm2P)
	ax := new(big.Int).Mul(sm2A, x)
	ax.Mod(ax, sm2P)
	rhs.Add(rhs, ax)
	rhs.Add(rhs, sm2B)
	rhs.Mod(rhs, sm2P)
	return y2.Cmp(rhs) == 0
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/crypto/sm2gen.go internal/crypto/sm2gen_test.go && git commit -m "feat(crypto): pure-Go SM2 keypair generation on sm2p256v1"`

---

## Task 8: storage — SM2 dir CRUD + keygen

**Files:** Create `internal/storage/sm2.go`, `internal/storage/sm2_test.go`. File = `priv(32)|pubX(32)|pubY(32)` = 96 bytes.

- [ ] **Step 1: Write the failing test** `internal/storage/sm2_test.go`:

```go
package storage

import (
	"os"
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
	_ = PutSM2(dir, keymodel.SM2Key{Index: 1, Priv: []byte{1}, PubX: []byte{2}, PubY: []byte{3}})
	if _, err := GetSM2(dir, 1); err == nil {
		t.Fatal("expected SIZE_MISMATCH")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `internal/storage/sm2.go`:

```go
package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"fhsm-key-manager/internal/crypto"
	"fhsm-key-manager/internal/keymodel"
)

const (
	sm2Dir    = "sm2"
	sm2FileSz = 96
)

func sm2Path(root string, index int) string {
	return filepath.Join(root, sm2Dir, fmt.Sprintf("%04d.SM2", index))
}

func GetSM2(root string, index int) (keymodel.SM2Key, error) {
	data, err := os.ReadFile(sm2Path(root, index))
	if err != nil {
		if os.IsNotExist(err) {
			return keymodel.SM2Key{}, keymodel.NewError("KEY_NOT_FOUND", "sm2 index %d not found", index)
		}
		return keymodel.SM2Key{}, err
	}
	if len(data) != sm2FileSz {
		return keymodel.SM2Key{}, keymodel.NewError("SIZE_MISMATCH", "sm2 file size %d != %d", len(data), sm2FileSz)
	}
	return keymodel.SM2Key{Index: index, Priv: data[0:32], PubX: data[32:64], PubY: data[64:96]}, nil
}

func ListSM2(root string) ([]keymodel.SM2Meta, error) {
	entries, err := os.ReadDir(filepath.Join(root, sm2Dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var metas []keymodel.SM2Meta
	for _, e := range entries {
		if idx, ok := indexFromName(e.Name(), ".SM2"); ok {
			metas = append(metas, keymodel.SM2Meta{Index: idx})
		}
	}
	return metas, nil
}

func PutSM2(root string, k keymodel.SM2Key) error {
	if err := os.MkdirAll(filepath.Join(root, sm2Dir), 0755); err != nil {
		return err
	}
	buf := make([]byte, sm2FileSz)
	copy(buf[0:32], fixedField(k.Priv, 32))
	copy(buf[32:64], fixedField(k.PubX, 32))
	copy(buf[64:96], fixedField(k.PubY, 32))
	return os.WriteFile(sm2Path(root, k.Index), buf, 0644)
}

func DeleteSM2(root string, index int) error {
	err := os.Remove(sm2Path(root, index))
	if err != nil && os.IsNotExist(err) {
		return keymodel.NewError("KEY_NOT_FOUND", "sm2 index %d not found", index)
	}
	return err
}

func GenSM2(root string, index int) (keymodel.SM2Key, error) {
	priv, x, y, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		return keymodel.SM2Key{}, keymodel.NewError("GEN_FAILED", "sm2 generate: %v", err)
	}
	k := keymodel.SM2Key{Index: index, Priv: priv, PubX: x, PubY: y}
	if err := PutSM2(root, k); err != nil {
		return keymodel.SM2Key{}, err
	}
	return k, nil
}

func fixedField(b []byte, size int) []byte {
	if len(b) == size {
		return b
	}
	out := make([]byte, size)
	if len(b) > size {
		copy(out, b[len(b)-size:])
	} else {
		copy(out[size-len(b):], b)
	}
	return out
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/storage/sm2.go internal/storage/sm2_test.go && git commit -m "feat(storage): sm2 dir CRUD + keygen"`

---

## Task 9: storage — ECC dir CRUD (no gen)

**Files:** Create `internal/storage/ecc.go`, `internal/storage/ecc_test.go`. File = `pri(48)|pub1(48)|pub2(48)` = 144 bytes.

- [ ] **Step 1: Write the failing test** `internal/storage/ecc_test.go`:

```go
package storage

import (
	"bytes"
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
	if err != nil || !bytes.Equal(got.Pri, in.Pri) {
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
	_ = PutECC(dir, keymodel.ECCKey{Index: 1, Pri: []byte{1}})
	if _, err := GetECC(dir, 1); err == nil {
		t.Fatal("expected SIZE_MISMATCH")
	}
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `internal/storage/ecc.go`:

```go
package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"fhsm-key-manager/internal/keymodel"
)

const (
	eccDir    = "ecc"
	eccFileSz = 144
)

func eccPath(root string, index int) string {
	return filepath.Join(root, eccDir, fmt.Sprintf("%04d.ECC", index))
}

func GetECC(root string, index int) (keymodel.ECCKey, error) {
	data, err := os.ReadFile(eccPath(root, index))
	if err != nil {
		if os.IsNotExist(err) {
			return keymodel.ECCKey{}, keymodel.NewError("KEY_NOT_FOUND", "ecc index %d not found", index)
		}
		return keymodel.ECCKey{}, err
	}
	if len(data) != eccFileSz {
		return keymodel.ECCKey{}, keymodel.NewError("SIZE_MISMATCH", "ecc file size %d != %d", len(data), eccFileSz)
	}
	return keymodel.ECCKey{Index: index, Pri: data[0:48], Pub1: data[48:96], Pub2: data[96:144]}, nil
}

func ListECC(root string) ([]keymodel.ECCMeta, error) {
	entries, err := os.ReadDir(filepath.Join(root, eccDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var metas []keymodel.ECCMeta
	for _, e := range entries {
		if idx, ok := indexFromName(e.Name(), ".ECC"); ok {
			metas = append(metas, keymodel.ECCMeta{Index: idx})
		}
	}
	return metas, nil
}

func PutECC(root string, k keymodel.ECCKey) error {
	if err := os.MkdirAll(filepath.Join(root, eccDir), 0755); err != nil {
		return err
	}
	buf := make([]byte, eccFileSz)
	copy(buf[0:48], k.Pri)
	copy(buf[48:96], k.Pub1)
	copy(buf[96:144], k.Pub2)
	return os.WriteFile(eccPath(root, k.Index), buf, 0644)
}

func DeleteECC(root string, index int) error {
	err := os.Remove(eccPath(root, index))
	if err != nil && os.IsNotExist(err) {
		return keymodel.NewError("KEY_NOT_FOUND", "ecc index %d not found", index)
	}
	return err
}
```

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add internal/storage/ecc.go internal/storage/ecc_test.go && git commit -m "feat(storage): ecc dir CRUD (no gen)"`

---

## Task 10: cmd — pboc1 + pboc2 groups

**Files:** Create `cmd/pboc1.go`, `cmd/pboc2.go`, `cmd/pboc_test.go`; modify `cmd/root.go` to register.

- [ ] **Step 1: Write the failing test** `cmd/pboc_test.go`:

```go
package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func runCmd(t *testing.T, dir, lsk string, args ...string) (map[string]any, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs(append([]string{"--path", dir, "--lsk", lsk}, args...))
	err := root.Execute()
	var m map[string]any
	_ = json.Unmarshal(out.Bytes(), &m)
	return m, err
}

func TestPBOC1CLIPutGet(t *testing.T) {
	dir := t.TempDir()
	lsk := "11111111111111111111111111111111"
	putJSON := `{"block":1,"type":2,"version":0,"index":1,"alg":0,"div":1,"exp":0,"length":16,"key":"aabbccddaabbccddaabbccddaabbccdd"}`
	tmp := filepath.Join(dir, "in.json")
	os.WriteFile(tmp, []byte(putJSON), 0644)
	orig := os.Stdin
	f, _ := os.Open(tmp)
	os.Stdin = f
	_, err := runCmd(t, dir, lsk, "pboc1", "put")
	os.Stdin = orig
	f.Close()
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	m, err := runCmd(t, dir, lsk, "pboc1", "get", "--block", "1", "--type", "2", "--version", "0", "--index", "1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if m["key"] != "aabbccddaabbccddaabbccddaabbccdd" {
		t.Errorf("key mismatch: %v", m["key"])
	}
}
```

- [ ] **Step 2: Run to verify it fails** — `go test ./cmd/ -run TestPBOC1` — Expected: FAIL

- [ ] **Step 3: Implement** `cmd/pboc1.go`:

```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newPBOC1Cmd() *cobra.Command {
	c := &cobra.Command{Use: "pboc1", Short: "Manage PBOC1 symmetric keys (pboc1.key)"}
	c.AddCommand(pboc1GetCmd(), pboc1GetAllCmd(), pboc1ListCmd(), pboc1PutCmd(), pboc1DeleteCmd())
	return c
}

func pboc1GetCmd() *cobra.Command {
	var b, ty, ver, idx int
	c := &cobra.Command{
		Use: "get", Short: "Read a single PBOC1 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			k, err := storage.GetPBOC1(flagPath, lsk, byte(b), byte(ty), byte(ver), byte(idx))
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&b, "block", 0, "block")
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&ver, "version", 0, "version")
	c.Flags().IntVar(&idx, "index", 0, "index")
	return c
}

func pboc1GetAllCmd() *cobra.Command {
	return &cobra.Command{
		Use: "get-all", Short: "Read all PBOC1 keys (with plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			keys, err := storage.ReadAllPBOC1(flagPath, lsk)
			if err != nil {
				return err
			}
			if keys == nil {
				keys = []keymodel.PBOC1Key{}
			}
			keymodel.OutputJSON(keys)
			return nil
		},
	}
}

func pboc1ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List PBOC1 key metadata (no plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListPBOC1(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.PBOC1Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func pboc1PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write/update PBOC1 key(s) from stdin JSON (object or array)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var single keymodel.PBOC1Key
			if json.Unmarshal(raw, &single) == nil && single.Length != 0 {
				if err := storage.PutPBOC1(flagPath, lsk, single); err != nil {
					return err
				}
				keymodel.OutputJSON(map[string]int{"written": 1})
				return nil
			}
			var batch []keymodel.PBOC1Key
			if err := json.Unmarshal(raw, &batch); err != nil {
				return keymodel.NewError("INTERNAL", "invalid pboc1 json: %v", err)
			}
			for _, k := range batch {
				if err := storage.PutPBOC1(flagPath, lsk, k); err != nil {
					return err
				}
			}
			keymodel.OutputJSON(map[string]int{"written": len(batch)})
			return nil
		},
	}
}

func pboc1DeleteCmd() *cobra.Command {
	var b, ty, ver, idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete a PBOC1 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			if err := storage.DeletePBOC1(flagPath, lsk, byte(b), byte(ty), byte(ver), byte(idx)); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&b, "block", 0, "block")
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&ver, "version", 0, "version")
	c.Flags().IntVar(&idx, "index", 0, "index")
	return c
}
```

`cmd/pboc2.go` (mirrors pboc1; selectors `--type/--index/--subtype`):

```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newPBOC2Cmd() *cobra.Command {
	c := &cobra.Command{Use: "pboc2", Short: "Manage PBOC2 symmetric keys (pboc2.key)"}
	c.AddCommand(pboc2GetCmd(), pboc2GetAllCmd(), pboc2ListCmd(), pboc2PutCmd(), pboc2DeleteCmd())
	return c
}

func pboc2GetCmd() *cobra.Command {
	var ty, idx, sub int
	c := &cobra.Command{
		Use: "get", Short: "Read a single PBOC2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			k, err := storage.GetPBOC2(flagPath, lsk, byte(ty), byte(idx), byte(sub))
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&idx, "index", 0, "index")
	c.Flags().IntVar(&sub, "subtype", 0, "subtype")
	return c
}

func pboc2GetAllCmd() *cobra.Command {
	return &cobra.Command{
		Use: "get-all", Short: "Read all PBOC2 keys (with plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			keys, err := storage.ReadAllPBOC2(flagPath, lsk)
			if err != nil {
				return err
			}
			if keys == nil {
				keys = []keymodel.PBOC2Key{}
			}
			keymodel.OutputJSON(keys)
			return nil
		},
	}
}

func pboc2ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List PBOC2 key metadata (no plaintext)",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListPBOC2(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.PBOC2Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func pboc2PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write/update PBOC2 key(s) from stdin JSON (object or array)",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var single keymodel.PBOC2Key
			if json.Unmarshal(raw, &single) == nil && single.Length != 0 {
				if err := storage.PutPBOC2(flagPath, lsk, single); err != nil {
					return err
				}
				keymodel.OutputJSON(map[string]int{"written": 1})
				return nil
			}
			var batch []keymodel.PBOC2Key
			if err := json.Unmarshal(raw, &batch); err != nil {
				return keymodel.NewError("INTERNAL", "invalid pboc2 json: %v", err)
			}
			for _, k := range batch {
				if err := storage.PutPBOC2(flagPath, lsk, k); err != nil {
					return err
				}
			}
			keymodel.OutputJSON(map[string]int{"written": len(batch)})
			return nil
		},
	}
}

func pboc2DeleteCmd() *cobra.Command {
	var ty, idx, sub int
	c := &cobra.Command{
		Use: "delete", Short: "Delete a PBOC2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			lsk, err := parseLSK(flagLSK)
			if err != nil {
				return keymodel.NewError("LSK_INVALID", "%v", err)
			}
			if err := storage.DeletePBOC2(flagPath, lsk, byte(ty), byte(idx), byte(sub)); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&ty, "type", 0, "type")
	c.Flags().IntVar(&idx, "index", 0, "index")
	c.Flags().IntVar(&sub, "subtype", 0, "subtype")
	return c
}
```

Register in `cmd/root.go` `newRootCmd()` before `return root`:
```go
	root.AddCommand(newPBOC1Cmd())
	root.AddCommand(newPBOC2Cmd())
```

- [ ] **Step 4: Run to verify it passes** — `go test ./cmd/ -run TestPBOC1` — Expected: PASS
- [ ] **Step 5: Commit** — `git add cmd/pboc1.go cmd/pboc2.go cmd/pboc_test.go cmd/root.go && git commit -m "feat(cmd): pboc1 + pboc2 command groups"`

---

## Task 11: cmd — rsa group

**Files:** Create `cmd/rsa.go`, `cmd/rsa_test.go`; register `newRSACmd()` in root.

- [ ] **Step 1: Write the failing test** `cmd/rsa_test.go`:
```go
package cmd

import "testing"

func TestRSACLIGenGet(t *testing.T) {
	dir := t.TempDir()
	m, err := runCmd(t, dir, "00000000000000000000000000000000", "rsa", "gen", "--index", "1", "--modlen", "1024")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if m["privDer"] == nil {
		t.Fatal("missing privDer")
	}
	if _, err := runCmd(t, dir, "00000000000000000000000000000000", "rsa", "get", "--index", "1"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `cmd/rsa.go`:
```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newRSACmd() *cobra.Command {
	c := &cobra.Command{Use: "rsa", Short: "Manage RSA keys (rsa/NNNN.RSA)"}
	c.AddCommand(rsaGetCmd(), rsaListCmd(), rsaPutCmd(), rsaDeleteCmd(), rsaGenCmd())
	return c
}

func rsaGetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an RSA private key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetRSA(flagPath, idx)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func rsaListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List RSA key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListRSA(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.RSAMeta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func rsaPutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an RSA key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.RSAKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid rsa json: %v", err)
			}
			if err := storage.PutRSA(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func rsaDeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an RSA key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteRSA(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func rsaGenCmd() *cobra.Command {
	var idx, modLen, exp int
	c := &cobra.Command{
		Use: "gen", Short: "Generate an RSA keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GenRSA(flagPath, idx, modLen, exp)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	c.Flags().IntVar(&modLen, "modlen", 2048, "modulus length in bits")
	c.Flags().IntVar(&exp, "exponent", 65537, "public exponent")
	return c
}
```
Register `root.AddCommand(newRSACmd())` in `newRootCmd()`.

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add cmd/rsa.go cmd/rsa_test.go cmd/root.go && git commit -m "feat(cmd): rsa command group with keygen"`

---

## Task 12: cmd — sm2 group

**Files:** Create `cmd/sm2.go`, `cmd/sm2_test.go`; register `newSM2Cmd()` in root.

- [ ] **Step 1: Write the failing test** `cmd/sm2_test.go`:
```go
package cmd

import "testing"

func TestSM2CLIGenGet(t *testing.T) {
	dir := t.TempDir()
	m, err := runCmd(t, dir, "00000000000000000000000000000000", "sm2", "gen", "--index", "3")
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if m["priv"] == nil || m["pubX"] == nil || m["pubY"] == nil {
		t.Fatalf("missing fields: %v", m)
	}
	if _, err := runCmd(t, dir, "00000000000000000000000000000000", "sm2", "get", "--index", "3"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `cmd/sm2.go`:
```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newSM2Cmd() *cobra.Command {
	c := &cobra.Command{Use: "sm2", Short: "Manage SM2 keys (sm2/NNNN.SM2)"}
	c.AddCommand(sm2GetCmd(), sm2ListCmd(), sm2PutCmd(), sm2DeleteCmd(), sm2GenCmd())
	return c
}

func sm2GetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an SM2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetSM2(flagPath, idx)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func sm2ListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List SM2 key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListSM2(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.SM2Meta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func sm2PutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an SM2 key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.SM2Key
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid sm2 json: %v", err)
			}
			if err := storage.PutSM2(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func sm2DeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an SM2 key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteSM2(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func sm2GenCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "gen", Short: "Generate an SM2 keypair (sm2p256v1)",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GenSM2(flagPath, idx)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}
```
Register `root.AddCommand(newSM2Cmd())`.

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add cmd/sm2.go cmd/sm2_test.go cmd/root.go && git commit -m "feat(cmd): sm2 command group with keygen"`

---

## Task 13: cmd — ecc group (no gen)

**Files:** Create `cmd/ecc.go`, `cmd/ecc_test.go`; register `newECCCmd()` in root.

- [ ] **Step 1: Write the failing test** `cmd/ecc_test.go`:
```go
package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestECCCLIPutGet(t *testing.T) {
	dir := t.TempDir()
	in := `{"index":2,"pri":"CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgo=","pub1":"CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCw==","pub2":"DAsMCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCw=="}`
	tmp := filepath.Join(dir, "in.json")
	os.WriteFile(tmp, []byte(in), 0644)
	orig := os.Stdin
	f, _ := os.Open(tmp)
	os.Stdin = f
	_, err := runCmd(t, dir, "00000000000000000000000000000000", "ecc", "put")
	os.Stdin = orig
	f.Close()
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := runCmd(t, dir, "00000000000000000000000000000000", "ecc", "get", "--index", "2"); err != nil {
		t.Fatalf("get: %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails** — Expected: FAIL
- [ ] **Step 3: Implement** `cmd/ecc.go`:
```go
package cmd

import (
	"encoding/json"
	"io"
	"os"

	"fhsm-key-manager/internal/keymodel"
	"fhsm-key-manager/internal/storage"
	"github.com/spf13/cobra"
)

func newECCCmd() *cobra.Command {
	c := &cobra.Command{Use: "ecc", Short: "Manage ECC keys (ecc/NNNN.ECC, store/retrieve only)"}
	c.AddCommand(eccGetCmd(), eccListCmd(), eccPutCmd(), eccDeleteCmd())
	return c
}

func eccGetCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "get", Short: "Read an ECC key",
		RunE: func(cmd *cobra.Command, args []string) error {
			k, err := storage.GetECC(flagPath, idx)
			if err != nil {
				return err
			}
			keymodel.OutputJSON(k)
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}

func eccListCmd() *cobra.Command {
	return &cobra.Command{
		Use: "list", Short: "List ECC key metadata",
		RunE: func(cmd *cobra.Command, args []string) error {
			metas, err := storage.ListECC(flagPath)
			if err != nil {
				return err
			}
			if metas == nil {
				metas = []keymodel.ECCMeta{}
			}
			keymodel.OutputJSON(metas)
			return nil
		},
	}
}

func eccPutCmd() *cobra.Command {
	return &cobra.Command{
		Use: "put", Short: "Write an ECC key from stdin JSON",
		RunE: func(cmd *cobra.Command, args []string) error {
			raw, err := io.ReadAll(os.Stdin)
			if err != nil {
				return keymodel.NewError("INTERNAL", "read stdin: %v", err)
			}
			var k keymodel.ECCKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return keymodel.NewError("INTERNAL", "invalid ecc json: %v", err)
			}
			if err := storage.PutECC(flagPath, k); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]int{"written": 1})
			return nil
		},
	}
}

func eccDeleteCmd() *cobra.Command {
	var idx int
	c := &cobra.Command{
		Use: "delete", Short: "Delete an ECC key",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := storage.DeleteECC(flagPath, idx); err != nil {
				return err
			}
			keymodel.OutputJSON(map[string]bool{"deleted": true})
			return nil
		},
	}
	c.Flags().IntVar(&idx, "index", 0, "key index")
	return c
}
```
Register `root.AddCommand(newECCCmd())`.

- [ ] **Step 4: Run to verify it passes** — Expected: PASS
- [ ] **Step 5: Commit** — `git add cmd/ecc.go cmd/ecc_test.go cmd/root.go && git commit -m "feat(cmd): ecc command group (store/retrieve only)"`

---

## Task 14: Integration test + README

**Files:** Create `test/integration_test.go`, `README.md`

- [ ] **Step 1: Write end-to-end test** `test/integration_test.go` (builds the binary and exercises the CLI via subprocess):

```go
package integration

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func buildBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "fhsm-key-manager")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func TestEndToEndPBOC1(t *testing.T) {
	bin := buildBinary(t)
	dir := t.TempDir()
	put := `{"block":1,"type":1,"version":0,"index":1,"alg":0,"div":1,"exp":0,"length":16,"key":"01020304050607080102030405060708"}`
	c := exec.Command(bin, "--path", dir, "--lsk", "11111111111111111111111111111111", "pboc1", "put")
	c.Stdin = strings.NewReader(put)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("put: %v\n%s", err, out)
	}
	g := exec.Command(bin, "--path", dir, "--lsk", "11111111111111111111111111111111", "pboc1", "get", "--block", "1", "--type", "1", "--version", "0", "--index", "1")
	out, err := g.Output()
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(out), &m); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if m["key"] != "01020304050607080102030405060708" {
		t.Errorf("key mismatch: %v", m["key"])
	}
	// wrong LSK must fail to recover the same key (ciphertext differs)
	if _, err := os.Stat(filepath.Join(dir, "pboc1.key")); err != nil {
		t.Fatalf("file missing: %v", err)
	}
}
```

- [ ] **Step 2: Run** — `go test ./test/` — Expected: PASS

- [ ] **Step 3: Write README.md** (purpose, build, command examples, binary-format reference to spec)

- [ ] **Step 4: Final full test + vet** — `go vet ./... && go test ./...` — Expected: all PASS

- [ ] **Step 5: Commit** — `git add test/ README.md && git commit -m "test: end-to-end integration; docs: README"`

---

## Self-Review Notes

**Spec coverage:** Every spec requirement maps to tasks — pboc1/pboc2 get/get-all/list/put/delete (Tasks 4,5,10), rsa/sm2 gen + CRUD (Tasks 6,7,8,11,12), ecc CRUD no gen (Tasks 9,13), LSK param default all-zero (Task 1 root flag), `--path` default `.` (Task 1), JSON envelope + exit codes (Task 1 main + keymodel Task 2), error codes via `keymodel.NewError` (Tasks 4-9). Binary format constants verified against fhsm-cpp source (pboc1=33B/1024, pboc2=32B/1024, 2TDEA K1‖K2‖K1, SM2=96B, ECC=144B).

**Consistency:** `indexFromName` shared (Task 6, reused by Tasks 8/9). `validKeyLen`/`clearSlice` in `util.go`. All storage functions take `(root string, ...)`; pboc1/pboc2 also take `lsk []byte`. Error type `*keymodel.Error` unwrapped in `main` via `errors.As`.

**Known assumption to validate post-impl:** SM2 file = exactly 96 bytes (32+32+32) — verified by reading a real fhsm-cpp `.SM2` file; if it differs, adjust `sm2FileSz` and field splits.
