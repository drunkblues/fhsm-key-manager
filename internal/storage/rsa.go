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

// indexFromName parses "NNNN.SUFFIX" -> index; returns ok=false if not 4-digit.
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
