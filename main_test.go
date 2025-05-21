package main

import (
	"fmt"
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name  string
		algo  string
		key   []byte
		input string
	}{
		{
			name:  "AES-256-GCM",
			algo:  "aes",
			key:   []byte("0123456789abcdef0123456789abcdef"), // 32 bytes
			input: "Test data for AES encryption",
		},
		{
			name:  "ChaCha20-Poly1305",
			algo:  "chacha20",
			key:   []byte("abcdefghijklmnopqrstuvwxyz012345"), // 32 bytes
			input: "Test data for ChaCha20 encryption",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var ed EncrypterDecrypter
			var err error

			switch tc.algo {
			case "aes":
				ed, err = NewAESGCMEncrypterDecrypter(tc.key)
			case "chacha20":
				ed, err = NewChaCha20EncrypterDecrypter(tc.key)
			default:
				t.Fatalf("Unsupported algorithm: %s", tc.algo)
			}
			if err != nil {
				t.Fatalf("Failed to create encrypter/decrypter: %v", err)
			}

			inputFile := fmt.Sprintf("test_input_%s.txt", tc.name)
			encryptedFile := fmt.Sprintf("test_encrypted_%s.bin", tc.name)
			decryptedFile := fmt.Sprintf("test_decrypted_%s.txt", tc.name)

			// Cleanup files
			defer os.Remove(inputFile)
			defer os.Remove(encryptedFile)
			defer os.Remove(decryptedFile)

			// Write input to file
			err = os.WriteFile(inputFile, []byte(tc.input), 0644)
			if err != nil {
				t.Fatalf("failed to create test input file: %v", err)
			}

			// Encrypt
			err = encryptFile(ed, inputFile, encryptedFile)
			if err != nil {
				t.Fatalf("failed to encrypt test file: %v", err)
			}

			// Decrypt
			err = decryptFile(ed, encryptedFile, decryptedFile)
			if err != nil {
				t.Fatalf("failed to decrypt test file: %v", err)
			}

			// Verify output
			output, err := os.ReadFile(decryptedFile)
			if err != nil {
				t.Fatalf("failed to read decrypted file: %v", err)
			}

			if string(output) != tc.input {
				t.Fatalf("decryption output mismatch: got '%s', want '%s'", string(output), tc.input)
			}
		})
	}
}
