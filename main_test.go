package main

import (
	"crypto/rand"
	"os"
	"testing"
)

func TestEncryptDecryptWithPassword(t *testing.T) {
	password := "testpassword123"
	input := "hello world! This is a test file for encryption."

	err := os.WriteFile("test_input.txt", []byte(input), 0644)
	if err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}
	defer os.Remove("test_input.txt")

	// Test password-based encryption
	encryptErr := encryptFileWithPassword(password, "test_input.txt", "test_encrypted.bin")
	if encryptErr != nil {
		t.Fatalf("failed to encrypt test file: %v", encryptErr)
	}
	defer os.Remove("test_encrypted.bin")

	// Test password-based decryption
	decryptErr := decryptFileWithPassword(password, "test_encrypted.bin", "test_decrypted.txt")
	if decryptErr != nil {
		t.Fatalf("failed to decrypt test file: %v", decryptErr)
	}
	defer os.Remove("test_decrypted.txt")

	output, err := os.ReadFile("test_decrypted.txt")
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if string(output) != input {
		t.Fatalf("decryption output mismatch: got %s, want %s", output, input)
	}
}

func TestEncryptDecryptWithKey(t *testing.T) {
	input := "test data for key-based encryption!"

	// Create test input file
	err := os.WriteFile("test_key_input.txt", []byte(input), 0644)
	if err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}
	defer os.Remove("test_key_input.txt")

	// Create test key file (32 bytes for AES-256)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	err = os.WriteFile("test.key", key, 0600)
	if err != nil {
		t.Fatalf("failed to create test key file: %v", err)
	}
	defer os.Remove("test.key")

	// Test key-based encryption
	encryptErr := encryptFileWithKey("test.key", "test_key_input.txt", "test_key_encrypted.bin")
	if encryptErr != nil {
		t.Fatalf("failed to encrypt test file with key: %v", encryptErr)
	}
	defer os.Remove("test_key_encrypted.bin")

	// Test key-based decryption
	decryptErr := decryptFileWithKey("test.key", "test_key_encrypted.bin", "test_key_decrypted.txt")
	if decryptErr != nil {
		t.Fatalf("failed to decrypt test file with key: %v", decryptErr)
	}
	defer os.Remove("test_key_decrypted.txt")

	output, err := os.ReadFile("test_key_decrypted.txt")
	if err != nil {
		t.Fatalf("failed to read decrypted file: %v", err)
	}

	if string(output) != input {
		t.Fatalf("key-based decryption output mismatch: got %s, want %s", output, input)
	}
}

func TestWrongPassword(t *testing.T) {
	password := "correctpassword"
	wrongPassword := "wrongpassword"
	input := "secret data"

	err := os.WriteFile("test_wrong_pass.txt", []byte(input), 0644)
	if err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}
	defer os.Remove("test_wrong_pass.txt")

	// Encrypt with correct password
	encryptErr := encryptFileWithPassword(password, "test_wrong_pass.txt", "test_wrong_encrypted.bin")
	if encryptErr != nil {
		t.Fatalf("failed to encrypt test file: %v", encryptErr)
	}
	defer os.Remove("test_wrong_encrypted.bin")

	// Try to decrypt with wrong password - should fail
	decryptErr := decryptFileWithPassword(wrongPassword, "test_wrong_encrypted.bin", "test_wrong_decrypted.txt")
	if decryptErr == nil {
		t.Fatal("expected decryption to fail with wrong password, but it succeeded")
	}

	// Clean up in case file was created
	os.Remove("test_wrong_decrypted.txt")
}

func TestInvalidKeyLength(t *testing.T) {
	input := "test data"

	err := os.WriteFile("test_invalid_key.txt", []byte(input), 0644)
	if err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}
	defer os.Remove("test_invalid_key.txt")

	// Create invalid key file (wrong length)
	invalidKey := []byte("tooshort")
	err = os.WriteFile("invalid.key", invalidKey, 0600)
	if err != nil {
		t.Fatalf("failed to create invalid key file: %v", err)
	}
	defer os.Remove("invalid.key")

	// Try to encrypt with invalid key - should fail
	encryptErr := encryptFileWithKey("invalid.key", "test_invalid_key.txt", "test_invalid_encrypted.bin")
	if encryptErr == nil {
		t.Fatal("expected encryption to fail with invalid key length, but it succeeded")
	}

	// Clean up in case file was created
	os.Remove("test_invalid_encrypted.bin")
}

func TestValidateEncryptedFile(t *testing.T) {
	// Test with too short file
	shortData := []byte("short")
	err := os.WriteFile("short.bin", shortData, 0644)
	if err != nil {
		t.Fatalf("failed to create short test file: %v", err)
	}
	defer os.Remove("short.bin")

	err = validateEncryptedFile("short.bin")
	if err == nil {
		t.Fatal("expected validation to fail for short file, but it succeeded")
	}
}
