package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// AES256Encrypt 進行 AES256 加密，使用 GCM 模式。
// key 長度必須為 32 bytes，iv 長度必須為 12 bytes。
func AES256Encrypt(key, iv, plaintext []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext = gcm.Seal(nil, iv, plaintext, nil)
	return ciphertext, nil
}

// AES256Decrypt 進行 AES256 解密，使用 GCM 模式。
// key 長度必須為 32 bytes，iv 長度必須為 12 bytes。
func AES256Decrypt(key, iv, ciphertext []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err = gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// RandomBytes 產生指定長度的隨機 bytes。
func RandomBytes(length uint) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
