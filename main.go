package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

var (
	encrypt    bool
	decrypt    bool
	inputPath  string
	outputPath string
	password   string
	maxSize    int64
)

func init() {
	// Main flags
	flag.BoolVar(&encrypt, "encrypt", false, "Encrypt the file with a given password.")
	flag.BoolVar(&decrypt, "decrypt", false, "Decrypt the file with a given password.")
	flag.StringVar(&inputPath, "input", "", "Input file path.")
	flag.StringVar(&outputPath, "output", "", "Output file path.")
	flag.StringVar(&password, "password", "", "Password for encryption/decryption.")
	flag.Int64Var(&maxSize, "maxsize", 100, "Maximum file size in MB (default: 100).")

	// Shorthand flags
	flag.BoolVar(&encrypt, "e", false, "Shorthand for -encrypt.")
	flag.BoolVar(&decrypt, "d", false, "Shorthand for -decrypt.")
	flag.StringVar(&inputPath, "i", "", "Shorthand for -input.")
	flag.StringVar(&outputPath, "o", "", "Shorthand for -output.")
	flag.StringVar(&password, "p", "", "Shorthand for -password.")
	flag.Int64Var(&maxSize, "m", 100, "Shorthand for -maxsize.")
}

func main() {
	flag.Parse()

	if len(os.Args) < 2 {
		fmt.Println("Error: No arguments provided.")
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
	if inputPath == "" || outputPath == "" || password == "" {
		log.Fatal("Error: -input (-i), -output (-o), and -password (-p) flags must be provided.")
	}

	// check filesize
	err := validateFileSize(inputPath, maxSize)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Perform encryption or decryption
	if encrypt {
		err := encryptFile(password, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error encrypting file: %v\n", err)
		}
		fmt.Println("File encrypted successfully.")
	} else if decrypt {
		err := decryptFile(password, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error decrypting file: %v\n", err)
		}
		fmt.Println("File decrypted successfully.")
	}
}

// deriveKey derives a 32-byte key from password using PBKDF2
func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// encryptFile encrypts a file and writes the output to another file.
func encryptFile(password, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key := deriveKey(password, salt)

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
	
	// Prepend salt to the encrypted data
	result := append(salt, cipherText...)
	return writeFile(outputFilepath, result)
}

// decryptFile decrypts a file and writes the output to another file.
func decryptFile(password, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Extract salt from the beginning of the file
	if len(inputData) < 16 {
		return errors.New("encrypted file is too short to contain salt")
	}
	
	salt := inputData[:16]
	encryptedData := inputData[16:]

	// Derive key from password using the salt
	key := deriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return errors.New("ciphertext is too short")
	}

	nonce, cipherText := encryptedData[:nonceSize], encryptedData[nonceSize:]
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
-password, -p  Password for encryption/decryption.
-maxsize, -m   Maximum file size in MB (default: 100).

Examples:
  Encrypt a file:
    ./app -e -i input.txt -o output.enc -p mypassword

  Encrypt a large file with custom size limit:
    ./app -e -i largefile.txt -o output.enc -p mypassword -m 500

  Decrypt a file:
    ./app -d -i output.enc -o decrypted.txt -p mypassword
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
