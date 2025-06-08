package main

import (
	"os"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	password := "testpassword123"
	input := "hello world!"

	err := os.WriteFile("hello_world.txt", []byte(input), 0644)
	if err != nil {
		t.Fatalf("failed to create test input file: %v", err)
	}

	defer os.Remove("hello_world.txt")

	encryptErr := encryptFile(password, "hello_world.txt", "encrypted.bin")
	if encryptErr != nil {
		t.Fatalf("failed to encrypt test file: %v", encryptErr)
	}
	defer os.Remove("encrypted.bin")

	decryptErr := decryptFile(password, "encrypted.bin", "decrypted_hello_world.txt")
	if decryptErr != nil {
		t.Fatalf("failed to decrypt test file: %v", decryptErr)
	}
	defer os.Remove("decrypted_hello_world.txt")

	output, err := os.ReadFile("decrypted_hello_world.txt")
	if err != nil {
		t.Fatalf("failed to read decrypted file")
	}

	if string(output) != input {
		t.Fatalf("decryption output mismatch: got %s, want %s", output, input)
	}
}
