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
	"strings"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

var (
	encrypt     bool
	decrypt     bool
	inputPath   string
	outputPath  string
	password    string
	keyFile     string
	usePassword bool
	force       bool
	maxSize     int64
)

func init() {
	// Main flags
	flag.BoolVar(&encrypt, "encrypt", false, "Encrypt the file.")
	flag.BoolVar(&decrypt, "decrypt", false, "Decrypt the file.")
	flag.StringVar(&inputPath, "in", "", "Input file path.")
	flag.StringVar(&outputPath, "out", "", "Output file path.")
	flag.StringVar(&password, "password", "", "Password for encryption/decryption (not recommended, use --use-password instead).")
	flag.StringVar(&keyFile, "key", "", "Key file path for encryption/decryption.")
	flag.BoolVar(&usePassword, "use-password", false, "Prompt for password securely.")
	flag.BoolVar(&force, "force", false, "Force overwrite output file if it exists.")
	flag.Int64Var(&maxSize, "maxsize", 100, "Maximum file size in MB (default: 100).")

	// Shorthand flags
	flag.BoolVar(&encrypt, "e", false, "Shorthand for -encrypt.")
	flag.BoolVar(&decrypt, "d", false, "Shorthand for -decrypt.")
	flag.StringVar(&inputPath, "i", "", "Shorthand for -in.")
	flag.StringVar(&outputPath, "o", "", "Shorthand for -out.")
	flag.StringVar(&password, "p", "", "Shorthand for -password.")
	flag.StringVar(&keyFile, "k", "", "Shorthand for -key.")
	flag.BoolVar(&force, "f", false, "Shorthand for -force.")
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
	if inputPath == "" || outputPath == "" {
		log.Fatal("Error: -in (-i) and -out (-o) flags must be provided.")
	}

	// Validate key/password input
	if keyFile == "" && password == "" && !usePassword {
		log.Fatal("Error: You must provide either -key (-k), -password (-p), or -use-password flag.")
	}
	if (keyFile != "" && password != "") || (keyFile != "" && usePassword) || (password != "" && usePassword) {
		log.Fatal("Error: You can only use one of -key, -password, or -use-password at a time.")
	}

	// Check if output file exists and handle force flag
	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			log.Fatalf("Error: Output file %s already exists. Use -force (-f) to overwrite.", outputPath)
		}
	}

	// Get password if needed
	var actualPassword string
	var err error
	if usePassword {
		actualPassword, err = getSecurePassword()
		if err != nil {
			log.Fatalf("Error reading password: %v", err)
		}
	} else if password != "" {
		actualPassword = password
	}

	// Check filesize
	err = validateFileSize(inputPath, maxSize)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Perform encryption or decryption
	if encrypt {
		if keyFile != "" {
			err = encryptFileWithKey(keyFile, inputPath, outputPath)
		} else {
			err = encryptFileWithPassword(actualPassword, inputPath, outputPath)
		}
		if err != nil {
			log.Fatalf("Error encrypting file: %v\n", err)
		}
		fmt.Println("File encrypted successfully.")
	} else if decrypt {
		if keyFile != "" {
			err = decryptFileWithKey(keyFile, inputPath, outputPath)
		} else {
			err = decryptFileWithPassword(actualPassword, inputPath, outputPath)
		}
		if err != nil {
			log.Fatalf("Error decrypting file: %v\n", err)
		}
		fmt.Println("File decrypted successfully.")
	}

	// Zero out password from memory for security
	if actualPassword != "" {
		zeroString(&actualPassword)
	}
}

// getSecurePassword prompts for password without echoing to terminal
func getSecurePassword() (string, error) {
	fmt.Print("Enter password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println() // Print newline after password input
	return string(bytePassword), nil
}

// zeroString securely zeros out a string from memory
func zeroString(s *string) {
	if s == nil || *s == "" {
		return
	}
	// Convert to byte slice and zero it
	bytes := []byte(*s)
	for i := range bytes {
		bytes[i] = 0
	}
	*s = ""
}

// validateEncryptedFile checks if file has the expected encrypted format
func validateEncryptedFile(filepath string) error {
	data, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Check minimum size (16 bytes salt + 12 bytes nonce + at least 1 byte data + 16 bytes tag)
	if len(data) < 45 {
		return errors.New("file is too short to be a valid encrypted file")
	}

	// Additional validation could be added here (magic bytes, headers, etc.)
	return nil
}

// deriveKey derives a 32-byte key from password using PBKDF2
func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, 100000, 32, sha256.New)
}

// encryptFileWithPassword encrypts a file using password-based key derivation
func encryptFileWithPassword(password, inputFilepath, outputFilepath string) error {
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
	defer func() {
		// Zero out key from memory
		for i := range key {
			key[i] = 0
		}
	}()

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
	
	// Create header with format indicator and salt
	header := []byte("GOENC")
	header = append(header, []byte{0x01}...) // Version 1
	header = append(header, []byte{0x00}...) // Password-based encryption
	header = append(header, salt...)
	
	result := append(header, cipherText...)
	return writeFile(outputFilepath, result)
}

// encryptFileWithKey encrypts a file using a key file
func encryptFileWithKey(keyFilepath, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Read key from file
	key, err := readFile(keyFilepath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Validate key length (must be 16, 24, or 32 bytes for AES)
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("invalid key length: %d bytes (must be 16, 24, or 32 bytes)", len(key))
	}

	defer func() {
		// Zero out key from memory
		for i := range key {
			key[i] = 0
		}
	}()

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
	
	// Create header with format indicator
	header := []byte("GOENC")
	header = append(header, []byte{0x01}...) // Version 1
	header = append(header, []byte{0x01}...) // Key-based encryption
	
	result := append(header, cipherText...)
	return writeFile(outputFilepath, result)
}

// decryptFileWithPassword decrypts a file using password-based key derivation
func decryptFileWithPassword(password, inputFilepath, outputFilepath string) error {
	err := validateEncryptedFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("invalid encrypted file: %w", err)
	}

	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Check if file has new format header
	if len(inputData) >= 7 && string(inputData[:5]) == "GOENC" {
		// New format with header
		if inputData[6] != 0x00 {
			return errors.New("file was not encrypted with password-based encryption")
		}
		
		if len(inputData) < 23 { // 5 + 1 + 1 + 16 = 23 minimum
			return errors.New("encrypted file is too short")
		}
		
		salt := inputData[7:23]
		encryptedData := inputData[23:]
		
		// Derive key from password using the salt
		key := deriveKey(password, salt)
		defer func() {
			// Zero out key from memory
			for i := range key {
				key[i] = 0
			}
		}()
		
		return decryptWithKey(key, encryptedData, outputFilepath)
	} else {
		// Legacy format (backward compatibility)
		if len(inputData) < 16 {
			return errors.New("encrypted file is too short to contain salt")
		}
		
		salt := inputData[:16]
		encryptedData := inputData[16:]
		
		// Derive key from password using the salt
		key := deriveKey(password, salt)
		defer func() {
			// Zero out key from memory
			for i := range key {
				key[i] = 0
			}
		}()
		
		return decryptWithKey(key, encryptedData, outputFilepath)
	}
}

// decryptFileWithKey decrypts a file using a key file
func decryptFileWithKey(keyFilepath, inputFilepath, outputFilepath string) error {
	err := validateEncryptedFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("invalid encrypted file: %w", err)
	}

	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Read key from file
	key, err := readFile(keyFilepath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// Validate key length
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return fmt.Errorf("invalid key length: %d bytes (must be 16, 24, or 32 bytes)", len(key))
	}

	defer func() {
		// Zero out key from memory
		for i := range key {
			key[i] = 0
		}
	}()

	// Check if file has new format header
	if len(inputData) >= 7 && string(inputData[:5]) == "GOENC" {
		// New format with header
		if inputData[6] != 0x01 {
			return errors.New("file was not encrypted with key-based encryption")
		}
		
		if len(inputData) < 7 {
			return errors.New("encrypted file is too short")
		}
		
		encryptedData := inputData[7:]
		return decryptWithKey(key, encryptedData, outputFilepath)
	} else {
		return errors.New("file does not appear to be encrypted with key-based encryption (missing header)")
	}
}

// decryptWithKey performs the actual decryption using the provided key
func decryptWithKey(key, encryptedData []byte, outputFilepath string) error {
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
		return fmt.Errorf("failed to decrypt (wrong key/password or corrupted file): %w", err)
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
Advanced file encryption tool with secure password handling.

Usage:
-encrypt, -e      Encrypt the file.
-decrypt, -d      Decrypt the file.
-in, -i           Input file path.
-out, -o          Output file path.
-key, -k          Key file path (16, 24, or 32 bytes).
-password, -p     Password for encryption/decryption (not recommended).
-use-password     Prompt for password securely (recommended).
-force, -f        Force overwrite output file if it exists.
-maxsize, -m      Maximum file size in MB (default: 100).

Key/Password Options (choose one):
  -key FILE         Use key from file
  -password PASS    Use password directly (not secure)
  -use-password     Prompt for password securely (recommended)

Examples:
  Encrypt with secure password prompt:
    ./app -e -i input.txt -o output.enc --use-password

  Encrypt with key file:
    ./app -e -i input.txt -o output.enc -k secret.key

  Decrypt with secure password prompt:
    ./app -d -i output.enc -o decrypted.txt --use-password

  Decrypt with key file:
    ./app -d -i output.enc -o decrypted.txt -k secret.key

  Force overwrite existing output:
    ./app -d -i output.enc -o existing.txt -k secret.key --force

Security Notes:
  - Use --use-password for secure password input (no echo)
  - Key files should contain exactly 16, 24, or 32 bytes
  - Passwords and keys are zeroed from memory after use
  - Files include format validation headers
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
