# ecrypt

A lightweight encryption utility for securing files and messages using AES-GCM authenticated encryption.

## Installation

```bash
# Clone the repository
git clone https://github.com/msedzins/encrypt
cd ecrypt

# Build the binary
go build -o ecrypt

# Optional: move to a directory in your PATH
sudo mv ecrypt /usr/local/bin/
```

## Features

- Secure file encryption using AES-GCM authenticated encryption
- Command line interface for files or stdin/stdout
- Safe key handling with protected memory
- Environment variable-based key management for enhanced security
- Cross-platform compatibility

## Usage

### Encrypt

```bash
# Encrypt a file (generates a random key)
ecrypt encrypt -i myfile.txt -o myfile.encrypted

# Encrypt a file and save the output to stdout
ecrypt encrypt -i myfile.txt

# Encrypt from stdin
cat myfile.txt | ecrypt encrypt

# Use an existing key from an environment variable
export MY_SECRET_KEY="your-hex-encoded-key"
ecrypt encrypt -i myfile.txt -o myfile.encrypted -k MY_SECRET_KEY

# Encrypt text directly from echo (pipe input)
echo -n "secret message" | ecrypt encrypt
# Note: The -n flag is important to prevent newline characters
```

## Decrypt

```bash
# Decrypt a file (requires key and nonce from encryption)
export MY_SECRET_KEY="your-hex-encoded-key"
ecrypt decrypt -i myfile.encrypted -o myfile.decrypted -k MY_SECRET_KEY -n "hex-encoded-nonce"

# Decrypt from stdin
cat myfile.encrypted | ecrypt decrypt -k MY_SECRET_KEY -n "hex-encoded-nonce"

# Decrypt hex data directly from echo
echo -n "ff1fcb27861589b5022ee0239e9151aae14c908cbbfd" | ecrypt decrypt -k MY_SECRET_KEY -n "20de1a36772a6973b2ef8a10"
# Note: The -n flag with echo prevents newline characters that would cause hex decoding errors
```

## Security notes

- The key is stored in a secure memory area to prevent leakage
- For highest security, use environment variables rather than command line flags for keys
- The nonce should never be reused with the same key
- Always keep your encryption keys secure

## Example workflow


```bash
# Encrypt a message directly from echo
echo -n "This is a secret message" | ecrypt encrypt
# Output will include the ciphertext, key, and nonce

# Save the key and nonce
export SECRET_KEY="copied-key-value"
NONCE="copied-nonce-value"

# Decrypt the message
echo -n "copied-ciphertext-value" | ecrypt decrypt -k SECRET_KEY -n "$NONCE"
```

