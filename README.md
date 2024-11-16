# Simple File Encryption Tool

-   Uses `crypto` package from Go's standard library to encrypt and decrypt the file.

## Usage

| Flag           | Description                                      |
| -------------- | ------------------------------------------------ |
| `encrypt`, `e` | Encrypt the file with a given key.               |
| `decrypt`, `d` | Decrypt the file with a given key.               |
| `input`, `i`   | Input file path.                                 |
| `output`, `o`  | Output file path.                                |
| `key`, `k`     | Encryption/Decryption key (16, 24, or 32 bytes). |

## Examples

-   Encrypt a file:

```bash
./app -e -i input.txt -o output.enc -k mysecretkey12345678
```

-   Decrypt a file:

```bash
./app -d -i output.enc -o decrypted.txt -k mysecretkey12345678
```
