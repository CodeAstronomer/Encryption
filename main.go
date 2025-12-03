package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

// --- Configuration ---
const (
	Iterations = 500_000

	VirtualLanes = 16

	BlockSize = 64

	SaltSize = 16
)

// --- Padding Logic (PKCS#7) ---

func pad(src []byte, blockSize int) []byte {
	padding := blockSize - (len(src) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("input is empty")
	}
	unpadding := int(src[length-1])
	if unpadding > length || unpadding == 0 {
		return nil, errors.New("invalid padding")
	}
	for i := 0; i < unpadding; i++ {
		if src[length-1-i] != byte(unpadding) {
			return nil, errors.New("invalid padding bytes")
		}
	}
	return src[:length-unpadding], nil
}

// --- Encryption Logic (Deterministic Parallelism) ---

func parallelKeyStreamXor(text []byte, key []byte, salt []byte) []byte {
	numCPU := runtime.NumCPU()
	sem := make(chan struct{}, numCPU)
	var wg sync.WaitGroup

	laneMasks := make([][]byte, VirtualLanes)

	keyWithSalt := append(make([]byte, 0, len(key)+len(salt)), key...)
	keyWithSalt = append(keyWithSalt, salt...)
	hasher := sha256.Sum256(keyWithSalt)

	masterSeed := int64(binary.BigEndian.Uint64(hasher[:8]))

	iterPerLane := Iterations / VirtualLanes

	for i := 0; i < VirtualLanes; i++ {
		wg.Add(1)
		go func(laneID int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			src := rand.NewSource(masterSeed + int64(laneID*9999))
			rng := rand.New(src)

			localMask := make([]byte, len(text))
			tempBytes := make([]byte, len(text))

			for j := 0; j < iterPerLane; j++ {
				rng.Read(tempBytes)
				// XOR mixing
				for k := 0; k < len(localMask); k++ {
					localMask[k] ^= tempBytes[k]
				}
			}
			laneMasks[laneID] = localMask
		}(i)
	}

	wg.Wait()

	// Combine all virtual lanes into final mask
	finalMask := make([]byte, len(text))
	for _, laneMask := range laneMasks {
		for k := 0; k < len(finalMask); k++ {
			finalMask[k] ^= laneMask[k]
		}
	}

	// Apply mask
	output := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		output[i] = text[i] ^ finalMask[i]
	}

	return output
}

// --- CLI Handlers ---

func printHelp() {
	fmt.Println(`
	Deterministic Parallel Encryptor (Go)
	=====================================
	A tool that uses parallel processing to encrypt messages.
	It guarantees the same output regardless of how many CPU cores are used.
	Now includes automatic salt rotation (output changes every time).

	Usage:
	encryptor [flags] <key> <message>

	Flags:
	-e    Encrypt a plain text message.
	-d    Decrypt a hex-encoded string.
	-h    Show this help message.

	Examples:
	1. Encrypt a message:
		encryptor -e "mySecretKey" "Hello World"

	2. Decrypt a message:
		encryptor -d "mySecretKey" "4a1b3c..."

	Notes:
	* If your key or message contains spaces, you MUST wrap them in quotes.
	* The result is automatically copied to your clipboard.
	* Uses PKCS#7 padding to hide message length and verify keys.
	`)
}

func runCLI(mode string, key string, message string) {
	var processingBytes []byte
	var salt []byte
	var result string
	var err error

	if mode == "decrypt" {
		decoded, err := hex.DecodeString(message)
		if err != nil {
			fmt.Println("Error: Invalid hex string provided for decryption.")
			os.Exit(1)
		}
		if len(decoded) < SaltSize {
			fmt.Println("Error: Ciphertext too short to contain valid salt.")
			os.Exit(1)
		}
		salt = decoded[:SaltSize]
		processingBytes = decoded[SaltSize:]
	} else {
		processingBytes = pad([]byte(message), BlockSize)

		salt = make([]byte, SaltSize)
		if _, err := crand.Read(salt); err != nil {
			fmt.Println("Error: Failed to generate random salt.")
			os.Exit(1)
		}
	}

	start := time.Now()
	outputBytes := parallelKeyStreamXor(processingBytes, []byte(key), salt)
	duration := time.Since(start)

	if mode == "encrypt" {
		finalPayload := append(salt, outputBytes...)
		result = hex.EncodeToString(finalPayload)
	} else {
		unpadded, err := unpad(outputBytes)
		if err != nil {
			fmt.Println("\n[FAILED] Decryption Error: Invalid Padding.")
			fmt.Println("Cause: You likely used the WRONG KEY or the data is corrupted.")
			os.Exit(1)
		}
		result = string(unpadded)
	}

	err = clipboard.WriteAll(result)
	copiedText := "(Copied to clipboard)"
	if err != nil {
		copiedText = "(Clipboard write failed)"
	}

	fmt.Printf("\n--- %s Result ---\n", strings.Title(mode))
	fmt.Println(result)
	fmt.Printf("\nStats: %d Virtual Lanes on %d Physical Cores (%d ms)\n",
		VirtualLanes, runtime.NumCPU(), duration.Milliseconds())
	fmt.Println(copiedText)
}

// --- Main Entry ---

func main() {
	args := os.Args

	if len(args) < 2 {
		printHelp()
		return
	}

	modeFlag := args[1]

	if modeFlag == "-h" || modeFlag == "--help" {
		printHelp()
		return
	}

	if len(args) != 4 {
		fmt.Printf("Error: Incorrect number of arguments (Got %d, expected 3 after command).\n", len(args)-1)
		fmt.Println("Use -h for help.")
		os.Exit(1)
	}

	key := args[2]
	msg := args[3]
	mode := ""

	switch modeFlag {
	case "-e":
		mode = "encrypt"
	case "-d":
		mode = "decrypt"
	default:
		fmt.Printf("Error: Unknown flag '%s'\n", modeFlag)
		printHelp()
		os.Exit(1)
	}

	runCLI(mode, key, msg)
}
