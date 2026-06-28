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
	// slot[4..6] reserved = 0 (already cleared by clearSlice — CRITICAL for binary compat)
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
