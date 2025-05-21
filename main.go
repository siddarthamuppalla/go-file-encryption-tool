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

	"golang.org/x/crypto/chacha20poly1305"
)

// EncrypterDecrypter defines the interface for encryption and decryption operations.
type EncrypterDecrypter interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// AESGCMEncrypterDecrypter implements the EncrypterDecrypter interface using AES-GCM.
type AESGCMEncrypterDecrypter struct {
	key []byte
}

// NewAESGCMEncrypterDecrypter creates a new AESGCMEncrypterDecrypter with the given key.
func NewAESGCMEncrypterDecrypter(key []byte) (*AESGCMEncrypterDecrypter, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("key length must be 16, 24, or 32 bytes")
	}
	return &AESGCMEncrypterDecrypter{key: key}, nil
}

// Encrypt encrypts plaintext using AES-GCM.
func (a *AESGCMEncrypterDecrypter) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-GCM.
func (a *AESGCMEncrypterDecrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext is too short")
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// ChaCha20EncrypterDecrypter implements the EncrypterDecrypter interface using ChaCha20-Poly1305.
type ChaCha20EncrypterDecrypter struct {
	key []byte
}

// NewChaCha20EncrypterDecrypter creates a new ChaCha20EncrypterDecrypter with the given key.
func NewChaCha20EncrypterDecrypter(key []byte) (*ChaCha20EncrypterDecrypter, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("key length must be %d bytes", chacha20poly1305.KeySize)
	}
	return &ChaCha20EncrypterDecrypter{key: key}, nil
}

// Encrypt encrypts plaintext using ChaCha20-Poly1305.
func (c *ChaCha20EncrypterDecrypter) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20Poly1305 cipher: %w", err)
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// Decrypt decrypts ciphertext using ChaCha20-Poly1305.
func (c *ChaCha20EncrypterDecrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20Poly1305 cipher: %w", err)
	}

	if len(ciphertext) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("ciphertext is too short")
	}

	nonce, actualCiphertext := ciphertext[:chacha20poly1305.NonceSizeX], ciphertext[chacha20poly1305.NonceSizeX:]
	plaintext, err := aead.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

var (
	encrypt    bool
	decrypt    bool
	inputPath  string
	outputPath string
	inputKey   string
	algorithm  string
)

func init() {
	// Main flags
	flag.BoolVar(&encrypt, "encrypt", false, "Encrypt the file with a given password.")
	flag.BoolVar(&decrypt, "decrypt", false, "Decrypt the file with a given password.")
	flag.StringVar(&inputPath, "input", "", "Input file path.")
	flag.StringVar(&outputPath, "output", "", "Output file path.")
	flag.StringVar(&inputKey, "key", "", "Encryption/Decryption key. Must be 16, 24, or 32 bytes.")
	flag.StringVar(&algorithm, "algo", "aes", "Encryption algorithm to use (aes, chacha20).")

	// Shorthand flags
	flag.BoolVar(&encrypt, "e", false, "Shorthand for -encrypt.")
	flag.BoolVar(&decrypt, "d", false, "Shorthand for -decrypt.")
	flag.StringVar(&inputPath, "i", "", "Shorthand for -input.")
	flag.StringVar(&outputPath, "o", "", "Shorthand for -output.")
	flag.StringVar(&inputKey, "k", "", "Shorthand for -key.")
	flag.StringVar(&algorithm, "a", "aes", "Shorthand for -algo.")
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

	var ed EncrypterDecrypter
	var errVal error // Renamed to avoid conflict with err from validateFileSize

	switch algorithm {
	case "aes":
		if len(key) != 16 && len(key) != 24 && len(key) != 32 {
			log.Fatal("Error: Key length for AES must be 16, 24, or 32 bytes.")
		}
		ed, errVal = NewAESGCMEncrypterDecrypter(key)
		if errVal != nil {
			log.Fatalf("Error initializing AES: %v", errVal)
		}
	case "chacha20":
		ed, errVal = NewChaCha20EncrypterDecrypter(key)
		if errVal != nil {
			log.Fatalf("Error initializing ChaCha20: %v", errVal)
		}
	default:
		log.Fatalf("Error: Unsupported algorithm '%s'. Supported algorithms are 'aes' and 'chacha20'.", algorithm)
	}

	// Perform encryption or decryption
	if encrypt {
		err := encryptFile(ed, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error encrypting file: %v\n", err)
		}
		fmt.Println("File encrypted successfully.")
	} else if decrypt {
		err := decryptFile(ed, inputPath, outputPath)
		if err != nil {
			log.Fatalf("Error decrypting file: %v\n", err)
		}
		fmt.Println("File decrypted successfully.")
	}
}

// encryptFile encrypts a file and writes the output to another file.
func encryptFile(ed EncrypterDecrypter, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	cipherText, err := ed.Encrypt(inputData)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	return writeFile(outputFilepath, cipherText)
}

// decryptFile decrypts a file and writes the output to another file.
func decryptFile(ed EncrypterDecrypter, inputFilepath, outputFilepath string) error {
	inputData, err := readFile(inputFilepath)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	plainText, err := ed.Decrypt(inputData)
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
-key, -k       Encryption/Decryption key.
               AES: 16, 24, or 32 bytes.
               ChaCha20: 32 bytes.
-algo, -a    Encryption algorithm to use (aes, chacha20). Default is "aes".

Examples:
  Encrypt a file using AES (default):
    ./app -e -i input.txt -o output.enc -k mysecretkey12345678

  Decrypt a file using AES (default):
    ./app -d -i output.enc -o decrypted.txt -k mysecretkey12345678

  Encrypt a file using ChaCha20:
    ./app -e -a chacha20 -i input.txt -o output.enc -k mysecretkeyforchacha20123456789

  Decrypt a file using ChaCha20:
    ./app -d -a chacha20 -i output.enc -o decrypted.txt -k mysecretkeyforchacha20123456789
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
