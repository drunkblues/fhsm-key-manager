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
