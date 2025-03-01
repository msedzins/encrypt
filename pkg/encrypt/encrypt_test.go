package encrypt

import (
	"crypto/rand"
	"io"
	"testing"
)

func TestEncryptAndDecrypt(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
		key       []byte
		wantErr   bool
	}{
		{
			name:      "valid input and key",
			plaintext: []byte("This is some test data to encrypt and decrypt"),
			key:       []byte("example key 1234example key 1234"),
			wantErr:   false,
		},
		{
			name:      "invalid key length",
			plaintext: []byte("This won't work with a short key"),
			key:       []byte("short key"),
			wantErr:   true,
		},
		{
			name:      "empty input",
			plaintext: []byte(""),
			key:       []byte("example key 1234example key 1234"),
			wantErr:   false, // Empty input is valid for encryption/decryption
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip full test if we expect an error
			if tt.wantErr {
				_, _, err := Encrypt(tt.plaintext, tt.key)
				if err == nil {
					t.Errorf("Encrypt() expected error but got nil")
				}
				return
			}

			// Test encryption
			ciphertext, nonce, err := Encrypt(tt.plaintext, tt.key)
			if err != nil {
				t.Fatalf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify ciphertext is not the same as plaintext
			if len(tt.plaintext) > 0 && len(ciphertext) > 0 {
				// We can only compare if both have data
				if string(ciphertext) == string(tt.plaintext) {
					t.Error("Encrypt() did not change the input data")
				}
			}

			// Test decryption
			decrypted, err := Decrypt(ciphertext, nonce, tt.key)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify decrypted matches original plaintext
			if string(decrypted) != string(tt.plaintext) {
				t.Errorf("Decrypt() result doesn't match original plaintext.\nGot: %s\nWant: %s",
					string(decrypted), string(tt.plaintext))
			}
		})
	}
}

func TestDecryptWithWrongNonce(t *testing.T) {
	// Setup valid data for encryption
	plaintext := []byte("This is test data for nonce verification")
	key := []byte("example key 1234example key 1234")

	// First get valid encryption results
	ciphertext, nonce, err := Encrypt(plaintext, key)
	if err != nil {
		t.Fatalf("Failed to encrypt test data: %v", err)
	}

	t.Run("different nonce", func(t *testing.T) {
		differentNonce := make([]byte, len(nonce))
		if _, err := io.ReadFull(rand.Reader, differentNonce); err != nil {
			t.Fatalf("Failed to generate different nonce: %v", err)
		}

		// Attempt decryption with different nonce
		_, err := Decrypt(ciphertext, differentNonce, key)
		if err == nil {
			t.Error("Decrypt() succeeded with different nonce, but should have failed")
		}
	})

	t.Run("wrong length nonce", func(t *testing.T) {
		wrongLengthNonce := make([]byte, len(nonce)+1) // One byte too long

		// Attempt decryption with wrong length nonce
		_, err := Decrypt(ciphertext, wrongLengthNonce, key)
		if err == nil {
			t.Error("Decrypt() succeeded with wrong length nonce, but should have failed")
		} else if err != ErrInvalidNonceSize {
			t.Errorf("Decrypt() returned wrong error for invalid nonce size; got %v, want %v",
				err, ErrInvalidNonceSize)
		}
	})
}
