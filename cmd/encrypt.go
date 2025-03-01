/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"ecrypt/pkg/encrypt"
	"ecrypt/pkg/key"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt a file",
	Long: `Encrypt a file provided as input parameter or from stdin. By default, generates a new random key and prints it out. 

Key can be also provided as input parameter. 
In that case, for a security reasons, it is expected that key is not provided directly but through environment variable (to avoid reading the key via console history or by tracking the process input parameters)
	`,
	Run: func(cmd *cobra.Command, args []string) {

		// Get the input file path from flag
		input, _ := cmd.Flags().GetString("input")

		// Variable to store the data
		var data []byte
		var err error

		// If input file is specified, read from file
		if input != "" {
			fmt.Printf("Reading from file: %s\n", input)
			data, err = os.ReadFile(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				return
			}
		} else {
			// No input file specified, read from stdin
			fmt.Println("Reading from stdin...")
			data, err = io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				return
			}
		}

		// Get the encryption key (either from env var or generate new)
		key, err := getEncryptionKey(cmd)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting encryption key: %v\n", err)
			return
		}
		defer key.Destroy() // Ensure secure cleanup

		// Encrypt the data
		ciphertext, nonce, err := encrypt.Encrypt(data, key.Bytes())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encrypting data: %v\n", err)
			return
		}

		// Get the output file path from flag
		output, _ := cmd.Flags().GetString("output")

		// If output file is specified, write to file
		if output != "" {
			fmt.Printf("Writing to file: %s\n", output)
			err = os.WriteFile(output, ciphertext, 0600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
				return
			}
		} else {
			// No output file specified, write to stdout
			fmt.Printf("Ciphertext: %x\n", ciphertext)
		}

		// Print key and nonce (these are needed for decryption)
		fmt.Printf("Encryption key: %x\n", key.Bytes())
		fmt.Printf("Nonce: %x\n", nonce)

	},
}

// getEncryptionKey returns a key either from the environment variable or generates a new random key
func getEncryptionKey(cmd *cobra.Command) (*key.Key, error) {
	// Get the key parameter from flag
	keyEnvVar, _ := cmd.Flags().GetString("key")

	// If key environment variable is specified, use it instead of generating a random key
	if keyEnvVar != "" {
		// Read the key from the environment variable
		keyHex := os.Getenv(keyEnvVar)
		if keyHex == "" {
			return nil, fmt.Errorf("environment variable %s is not set or empty", keyEnvVar)
		}

		// Decode the hex-encoded key
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, fmt.Errorf("error decoding key from environment variable: %v", err)
		}

		// Validate key length
		if len(keyBytes) != int(key.KeySize256) &&
			len(keyBytes) != int(key.KeySize192) &&
			len(keyBytes) != int(key.KeySize128) {
			return nil, fmt.Errorf("invalid key length. Expected 16, 24, or 32 bytes, got %d", len(keyBytes))
		}

		// Create a new Key object from the decoded bytes
		keyObj, err := key.NewKeyFromBytes(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("error creating key from bytes: %v", err)
		}

		fmt.Printf("Using key from environment variable %s\n", keyEnvVar)
		return keyObj, nil
	}

	// Generate a random key
	keyObj, err := key.NewKey(key.KeySize256)
	if err != nil {
		return nil, fmt.Errorf("error generating random key: %v", err)
	}
	fmt.Println("Generated a new random key")
	return keyObj, nil
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	//encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	encryptCmd.Flags().StringP("input", "i", "", "input file")
	encryptCmd.Flags().StringP("output", "o", "", "output file")
	encryptCmd.Flags().StringP("key", "k", "", "variable with a key")
}
