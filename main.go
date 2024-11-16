package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
)

var (
	encrypt    bool
	decrypt    bool
	inputPath  string
	outputPath string
	inputKey   string
)

func init() {
	// Main flags
	flag.BoolVar(&encrypt, "encrypt", false, "Encrypt the file with a given password.")
	flag.BoolVar(&decrypt, "decrypt", false, "Decrypt the file with a given password.")
	flag.StringVar(&inputPath, "input", "", "Input file path.")
	flag.StringVar(&outputPath, "output", "", "Output file path.")
	flag.StringVar(&inputKey, "key", "", "Encryption/Decryption key. Must be 16, 24, or 32 bytes.")

	// Shorthand flags
	flag.BoolVar(&encrypt, "e", false, "Shorthand for -encrypt.")
	flag.BoolVar(&decrypt, "d", false, "Shorthand for -decrypt.")
	flag.StringVar(&inputPath, "i", "", "Shorthand for -input.")
	flag.StringVar(&outputPath, "o", "", "Shorthand for -output.")
	flag.StringVar(&inputKey, "k", "", "Shorthand for -key.")
}

func main() {
	flag.Parse()

	if len(os.Args) < 2{
		printUsage()
		return
	}

	// Validate input
	if !encrypt && !decrypt {
		log.Fatal("Error: Either -encrypt (-e) or -decrypt (-d) flag must be provided.")
	}
	if encrypt && decrypt {
		log.Fatal("Error: You cannot use -encrypt (-e) and -decrypt (-d) simultaneously.")
	}
	if inputPath == "" || outputPath == "" || inputKey == "" {
		log.Fatal("Error: -input (-i), -output (-o), and -key (-k) flags must be provided.")
	}

	// check filesize
	err := validateFileSize(inputPath, 100) // this can be modified as needed
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Validate key length
	key := []byte(inputKey)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		log.Fatal("Error: Key length must be 16, 24, or 32 bytes.")
	}

	// Perform encryption or decryption
	if encrypt {
		err := encryptFile(key, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error encrypting file: %v\n", err)
		}
		fmt.Println("File encrypted successfully.")
	} else if decrypt {
		err := decryptFile(key, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error decrypting file: %v\n", err)
		}
		fmt.Println("File decrypted successfully.")
	}
}

// encryptFile encrypts a file and writes the output to another file.
func encryptFile(key []byte, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	cipherText := gcm.Seal(nonce, nonce, inputData, nil)
	return writeFile(outputFilepath, cipherText)
}

// decryptFile decrypts a file and writes the output to another file.
func decryptFile(key []byte, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(inputData) < nonceSize {
		return errors.New("ciphertext is too short")
	}

	nonce, cipherText := inputData[:nonceSize], inputData[nonceSize:]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	return writeFile(outputFilepath, plainText)
}

// readFile reads the content of a file.
func readFile(filepath string) ([]byte, error) {
	return os.ReadFile(filepath)
}

// writeFile writes data to a file.
func writeFile(filepath string, data []byte) error {
	return os.WriteFile(filepath, data, 0644)
}

func printUsage() {
	fmt.Println(`
Simple file encryption tool.

Usage:
-encrypt, -e   Encrypt the file with a given key.
-decrypt, -d   Decrypt the file with a given key.
-input, -i     Input file path.
-output, -o    Output file path.
-key, -k       Encryption/Decryption key (16, 24, or 32 bytes).

Examples:
  Encrypt a file:
    ./app -e -i input.txt -o output.enc -k mysecretkey12345678

  Decrypt a file:
    ./app -d -i output.enc -o decrypted.txt -k mysecretkey12345678
	`)
}

func validateFileSize(inputFilepath string, maxSizeMB int64) error {
	info, err := os.Stat(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to get the file info: %w", err)
	}
	if info.Size() > maxSizeMB*1024*1024 {
		return fmt.Errorf("file too large. Must be less than %v MB", maxSizeMB)
	}
	return nil
}
