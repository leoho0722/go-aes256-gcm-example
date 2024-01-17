package main

import (
	"leoho.io/go-aes256-gcm-example/crypto"
	"log"
)

func main() {
	plain := []byte("Hello, World!")
	key, _ := crypto.RandomBytes(32)
	iv, _ := crypto.RandomBytes(12)
	log.Printf("plaintext: %v\n", plain)
	log.Printf("iv: %v\n", len(iv))
	ciphertext, err := crypto.AES256Encrypt(key, iv, plain)
	if err != nil {
		log.Fatalf("AES256Encrypt error: %v", err)
	}
	log.Printf("ciphertext: %vtoString: %s\n", ciphertext, string(ciphertext))

	plaintext, err := crypto.AES256Decrypt(key, iv, ciphertext)
	if err != nil {
		log.Fatalf("AES256Decrypt error: %v", err)
	}
	log.Printf("plaintext: %v toString: %s\n", plaintext, string(plaintext))
}
