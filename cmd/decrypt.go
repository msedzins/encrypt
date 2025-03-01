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

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file",
	Long:  `Decrypt a file provided as input parameter or from stdin`,
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
			stdinData, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading from stdin: %v\n", err)
				return
			}

			data, err = hex.DecodeString(string(stdinData))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding hex data: %v\n", err)
				return
			}
		}

		// Get the decryption key from environment variable
		keyEnvVar, _ := cmd.Flags().GetString("key")
		keyHex := os.Getenv(keyEnvVar)
		if keyHex == "" {
			fmt.Fprintf(os.Stderr, "Error: Environment variable %s is not set or empty\n", keyEnvVar)
			return
		}

		// Decode the hex-encoded key
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding key from environment variable: %v\n", err)
			return
		}

		// Create a key object from the decoded bytes
		key, err := key.NewKeyFromBytes(keyBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating key: %v\n", err)
			return
		}
		defer key.Destroy() // Ensure secure cleanup

		// Get the nonce from command-line flag
		nonceHex, _ := cmd.Flags().GetString("nonce")
		nonce, err := hex.DecodeString(nonceHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decoding nonce: %v\n", err)
			return
		}

		// Decrypt the data
		plaintext, err := encrypt.Decrypt(data, nonce, key.Bytes())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error decrypting data: %v\n", err)
			return
		}

		// Get the output file path from flag
		output, _ := cmd.Flags().GetString("output")

		// If output file is specified, write to file
		if output != "" {
			fmt.Printf("Writing to file: %s\n", output)
			err = os.WriteFile(output, plaintext, 0600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
				return
			}
		} else {
			// No output file specified, write to stdout
			fmt.Println("Decrypted data:")
			os.Stdout.Write(plaintext)
			// Add a newline for better formatting in terminal
			fmt.Println()
		}
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().StringP("input", "i", "", "Input file to decrypt (stdin if not specified)")
	decryptCmd.Flags().StringP("output", "o", "", "Output file for decrypted data (stdout if not specified)")
	decryptCmd.Flags().StringP("key", "k", "", "Environment variable containing the decryption key")
	decryptCmd.Flags().StringP("nonce", "n", "", "Hex-encoded nonce value used during encryption")

	// Mark key and nonce flags as required
	decryptCmd.MarkFlagRequired("key")
	decryptCmd.MarkFlagRequired("nonce")
}
