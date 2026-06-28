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
