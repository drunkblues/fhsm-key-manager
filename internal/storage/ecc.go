package storage

import (
	"fmt"
	"os"
	"path/filepath"

	"fhsm-key-manager/internal/keymodel"
)

const (
	eccDir    = "ecc"
	eccFileSz = 144 // pri(48) + pub1(48) + pub2(48)
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
