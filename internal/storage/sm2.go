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
	sm2FileSz = 96 // priv(32) + pubX(32) + pubY(32)
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

// fixedField left-pads b to exactly size bytes (right-aligned); truncates long b.
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
