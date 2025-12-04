package main

import (
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20"

	"github.com/atotto/clipboard"
)

// --- Configuration & Profiling ---
const maxProfiles = 10
const configFileName = ".encryptor_profiles.json"
const defaultProfileName = "default"

type ProfileConfig struct {
	Iterations   int `json:"iterations"`
	VirtualLanes int `json:"virtual_lanes"`
	BlockSize    int `json:"block_size"`
	SaltSize     int `json:"salt_size"`
}

type ExportProfilePayload struct {
	ProfileName string        `json:"profile_name"`
	Config      ProfileConfig `json:"config"`
}

type GlobalConfig struct {
	CurrentProfileName string                   `json:"current_profile"`
	Profiles           map[string]ProfileConfig `json:"profiles"`
}

var (
	globalConf     GlobalConfig
	currentProfile ProfileConfig
	configFilePath string
)

func initConfig() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		configFilePath = configFileName
	} else {
		configFilePath = filepath.Join(homeDir, configFileName)
	}

	defaultConf := ProfileConfig{
		Iterations:   500_000,
		VirtualLanes: 16,
		BlockSize:    64,
		SaltSize:     16,
	}

	globalConf = GlobalConfig{
		CurrentProfileName: defaultProfileName,
		Profiles:           make(map[string]ProfileConfig),
	}

	data, err := os.ReadFile(configFilePath)
	if err == nil {
		if err := json.Unmarshal(data, &globalConf); err != nil {
			fmt.Fprintf(os.Stderr, "Warnung: Konfigurationsdatei defekt, verwende Standardwerte: %v\n", err)
			globalConf.Profiles[defaultProfileName] = defaultConf
		}
	} else if os.IsNotExist(err) {
		globalConf.Profiles[defaultProfileName] = defaultConf
		if err := saveConfig(); err != nil {
			fmt.Fprintf(os.Stderr, "Warnung: Konfigurationsdatei konnte nicht initial gespeichert werden: %v\n", err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Warnung: Fehler beim Laden der Konfigurationsdatei, verwende Standardwerte: %v\n", err)
		globalConf.Profiles[defaultProfileName] = defaultConf
	}

	if conf, ok := globalConf.Profiles[globalConf.CurrentProfileName]; ok {
		currentProfile = conf
	} else {
		globalConf.CurrentProfileName = defaultProfileName
		currentProfile = globalConf.Profiles[defaultProfileName]
	}
}

func saveConfig() error {
	if len(globalConf.Profiles) > maxProfiles {
		return fmt.Errorf("maximale Anzahl von Profilen (%d) überschritten", maxProfiles)
	}

	data, err := json.MarshalIndent(globalConf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFilePath, data, 0600)
}

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
	saltSizeToUse := currentProfile.SaltSize
	if len(src) < saltSizeToUse {
		return nil, errors.New("input is too short")
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

	keyMaterial := append(make([]byte, 0, len(key)+len(salt)), key...)
	keyMaterial = append(keyMaterial, salt...)
	hashedKey := sha256.Sum256(keyMaterial)

	nonceHash := sha256.Sum256(append([]byte("nonce"), salt...))
	nonce := nonceHash[:12]

	chachaCipher, err := chacha20.NewUnauthenticatedCipher(hashedKey[:], nonce)
	if err != nil {
		panic(err)
	}

	secureChaChaMask := make([]byte, len(text))
	chachaCipher.XORKeyStream(secureChaChaMask, make([]byte, len(text)))

	seedHash := sha256.Sum256(append(key, salt...))
	masterSeed := int64(binary.BigEndian.Uint64(seedHash[:8]))

	laneMasks := make([][]byte, currentProfile.VirtualLanes)
	iterPerLane := currentProfile.Iterations / currentProfile.VirtualLanes

	if currentProfile.VirtualLanes == 0 {
		fmt.Fprintln(os.Stderr, "Fehler: VirtualLanes darf nicht Null sein. Abbruch.")
		os.Exit(1)
	}
	if iterPerLane == 0 {
		iterPerLane = 1
	}

	for i := 0; i < currentProfile.VirtualLanes; i++ {
		wg.Add(1)
		go func(laneID int) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			src := rand.NewSource(masterSeed + int64(laneID*9999))
			rng := rand.New(src)

			localMask := make([]byte, len(text))
			temp := make([]byte, len(text))

			for j := 0; j < iterPerLane; j++ {
				rng.Read(temp)
				for k := 0; k < len(localMask); k++ {
					localMask[k] ^= temp[k]
				}
			}

			laneMasks[laneID] = localMask
		}(i)
	}

	wg.Wait()

	finalMask := make([]byte, len(text))
	for i := 0; i < len(finalMask); i++ {
		finalMask[i] = secureChaChaMask[i]
	}

	for _, lm := range laneMasks {
		for i := 0; i < len(finalMask); i++ {
			finalMask[i] ^= lm[i]
		}
	}

	output := make([]byte, len(text))
	for i := 0; i < len(text); i++ {
		output[i] = text[i] ^ finalMask[i]
	}

	return output
}

// --- CLI Handlers (Anzeigefunktionen unverändert) ---

func printProfileInfo(p ProfileConfig) {
	fmt.Println("Parameter            | Wert")
	fmt.Println("---------------------+---------")
	fmt.Printf("Iterations           | %d\n", p.Iterations)
	fmt.Printf("Virtual Lanes        | %d\n", p.VirtualLanes)
	fmt.Printf("Block Size (Bytes)   | %d\n", p.BlockSize)
	fmt.Printf("Salt Size (Bytes)    | %d\n", p.SaltSize)
	fmt.Println("---------------------+---------")
}

func printProfileList() {
	fmt.Println("\n--- 📝 Gespeicherte Profile und Einstellungen ---")
	fmt.Printf("Konfigurationsdatei: %s\n", configFilePath)
	fmt.Printf("Maximal %d Profile können gespeichert werden.\n\n", maxProfiles)

	if len(globalConf.Profiles) == 0 {
		fmt.Println("   (Keine Profile gespeichert, das sollte nicht passieren!)")
		return
	}

	var profileNames []string
	for name := range globalConf.Profiles {
		profileNames = append(profileNames, name)
	}

	for _, name := range profileNames {
		config := globalConf.Profiles[name]
		status := ""
		if name == globalConf.CurrentProfileName {
			status = " (AKTIV)"
		}
		fmt.Printf("## Profil: **%s**%s\n", name, status)
		printProfileInfo(config)
		fmt.Println()
	}
}

func printConfig() {
	fmt.Println("\n--- ⚙️ Aktuelle Konfiguration ---")
	fmt.Printf("Konfigurationsdatei: %s\n", configFilePath)
	fmt.Printf("Aktives Profil: **%s**\n\n", globalConf.CurrentProfileName)

	fmt.Printf("Einstellungen für Profil **%s**:\n", globalConf.CurrentProfileName)
	printProfileInfo(currentProfile)
}

func printHelp() {
	fmt.Println(`
    Deterministic Parallel Encryptor (Go)
    =====================================

    Aktives Profil: ` + globalConf.CurrentProfileName + ` (kann mit -p temporär überschrieben werden)

    Usage (Run):
    encryptor [-p <profile>] -e <key> <message>
    encryptor [-p <profile>] -d <key> <ciphertext>

    Usage (Config/Profiles):
    encryptor -c
    encryptor --list-profiles
    encryptor --create-profile <name> [-iterations 500000 -lanes 16 ...]
    encryptor --edit-profile <name> [-iterations 2M]
    encryptor --change-profile <name>
    encryptor --delete-profile <name>
    
    Usage (Secure Profile Transfer):
    encryptor --export-profile <name> -key <passphrase>
    encryptor --import-profile <payload> -key <passphrase>

    Run Flags:
    -e    Encrypt a plain text message.
    -d    Decrypt a hex-encoded string.
    -p    Gibt das zu verwendende Profil für diesen einen Vorgang an (Standard: ` + defaultProfileName + `).
    -key  Passphrase für den sicheren Profil-Import/Export (MUSS verwendet werden).

    Config Flags:
    -c                 Zeigt die **aktuelle** Konfiguration (aktives Profil) an.
    --list-profiles    Zeigt **alle** Profile mit deren detaillierten Werten an.

    Profile Management:
    --create-profile <name> Erstellt ein neues Profil. Ohne weitere Flags werden die Werte des AKTUELLEN Profils kopiert.
    --edit-profile <name>   Ändert die Werte eines existierenden Profils mit den angegebenen Konfigurations-Flags.
    --change-profile <name> Legt das angegebene Profil als neues Standardprofil fest.
    --delete-profile <name> Löscht ein existierendes Profil (kann nicht das aktive oder letzte Profil löschen).
    
    Secure Profile Transfer:
    --export-profile <name> Verschlüsselt das Profil mit -key und gibt die Hex-Zeichenkette aus.
    --import-profile <payload> Entschlüsselt die Hex-Zeichenkette mit -key und speichert das Profil.

    Konfigurations-Flags (nur in Kombination mit --create-profile oder --edit-profile):
    -iterations <int>      Setzt die Gesamtzahl der Iterationen.
    -lanes <int>           Setzt die Anzahl der virtuellen Lanes.
    -blocksize <int>       Setzt die Blockgröße für Padding.
    -saltsize <int>        Setzt die Größe des Salts in Bytes.

    Examples:
    1. Profil 'fast' sicher exportieren:
        encryptor --export-profile fast -key "MeinSichererSchluessel"

    2. Profil aus Payload importieren:
        encryptor --import-profile 5fa0c4...d8 -key "MeinSichererSchluessel"
    `)
}

func runCLI(key, message, mode, usedProfileName string) {
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
		if len(decoded) < currentProfile.SaltSize {
			fmt.Println("Error: Ciphertext too short to contain valid salt.")
			os.Exit(1)
		}
		salt = decoded[:currentProfile.SaltSize]
		processingBytes = decoded[currentProfile.SaltSize:]
	} else {
		processingBytes = pad([]byte(message), currentProfile.BlockSize)

		salt = make([]byte, currentProfile.SaltSize)
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

	fmt.Printf("\n--- %s Result (Profile: %s) ---\n", strings.Title(mode), usedProfileName)
	fmt.Println(result)
	fmt.Printf("\nStats: %d Virtual Lanes on %d Physical Cores (%d ms)\n",
		currentProfile.VirtualLanes, runtime.NumCPU(), duration.Milliseconds())
	fmt.Println(copiedText)
}

// --- Main Entry ---

func main() {
	initConfig()

	var encryptFlag bool
	var decryptFlag bool
	var showConfigFlag bool
	var listProfilesFlag bool

	var profileName string
	var createProfileName string
	var changeProfileName string
	var exportProfileName string
	var importProfilePayload string
	var editProfileName string
	var deleteProfileName string
	var customKey string

	newIterations := currentProfile.Iterations
	newVirtualLanes := currentProfile.VirtualLanes
	newBlockSize := currentProfile.BlockSize
	newSaltSize := currentProfile.SaltSize

	defaultIterations := currentProfile.Iterations
	defaultLanes := currentProfile.VirtualLanes
	defaultBlockSize := currentProfile.BlockSize
	defaultSaltSize := currentProfile.SaltSize

	flag.BoolVar(&encryptFlag, "e", false, "Encrypt a plain text message.")
	flag.BoolVar(&decryptFlag, "d", false, "Decrypt a hex-encoded string.")
	flag.BoolVar(&showConfigFlag, "c", false, "Displays the current configuration.")
	flag.BoolVar(&listProfilesFlag, "list-profiles", false, "Zeigt alle Profile mit deren detaillierten Werten an.")

	flag.StringVar(&profileName, "p", globalConf.CurrentProfileName, "Gibt das zu verwendende Profil an.")
	flag.StringVar(&createProfileName, "create-profile", "", "Erstellt ein neues Profil mit den angegebenen Werten.")
	flag.StringVar(&editProfileName, "edit-profile", "", "Ändert die Werte eines existierenden Profils.")
	flag.StringVar(&changeProfileName, "change-profile", "", "Legt das angegebene Profil als Standard fest.")
	flag.StringVar(&deleteProfileName, "delete-profile", "", "Löscht ein existierendes Profil.")
	flag.StringVar(&exportProfileName, "export-profile", "", "Verschlüsselt das Profil mit -key und gibt die Hex-Zeichenkette aus.")
	flag.StringVar(&importProfilePayload, "import-profile", "", "Entschlüsselt die Hex-Zeichenkette mit -key und speichert das Profil.")
	flag.StringVar(&customKey, "key", "", "Passphrase für den sicheren Profil-Import/Export.")

	flag.IntVar(&newIterations, "iterations", currentProfile.Iterations, "Total number of iterations.")
	flag.IntVar(&newVirtualLanes, "lanes", currentProfile.VirtualLanes, "Number of virtual lanes.")
	flag.IntVar(&newBlockSize, "blocksize", currentProfile.BlockSize, "Block size for padding.")
	flag.IntVar(&newSaltSize, "saltsize", currentProfile.SaltSize, "Size of the salt in bytes.")

	flag.Usage = printHelp

	flag.Parse()

	validateProfile := func(p ProfileConfig) error {
		if p.Iterations <= 0 || p.VirtualLanes <= 0 || p.BlockSize <= 0 || p.SaltSize <= 0 {
			return errors.New("alle Konfigurationswerte müssen größer als Null sein")
		}
		return nil
	}

	// --- Profilverwaltung (Priorität) ---

	if listProfilesFlag {
		printProfileList()
		return
	}

	if showConfigFlag {
		printConfig()
		return
	}

	// --- Sichere Profilübertragung (NEUE Logik) ---

	if exportProfileName != "" {
		if customKey == "" {
			fmt.Println("Fehler: Für den Profil-Export muss der -key (Passphrase) angegeben werden.")
			os.Exit(1)
		}

		profileToExport, ok := globalConf.Profiles[exportProfileName]
		if !ok {
			fmt.Printf("Fehler: Profil '%s' existiert nicht.\n", exportProfileName)
			os.Exit(1)
		}

		payload := ExportProfilePayload{
			ProfileName: exportProfileName,
			Config:      profileToExport,
		}
		payloadJSON, _ := json.Marshal(payload)

		paddedPayload := pad(payloadJSON, currentProfile.BlockSize)
		salt := make([]byte, currentProfile.SaltSize)
		if _, err := crand.Read(salt); err != nil {
			fmt.Println("Error: Failed to generate random salt for export.")
			os.Exit(1)
		}

		outputBytes := parallelKeyStreamXor(paddedPayload, []byte(customKey), salt)
		finalPayload := append(salt, outputBytes...)
		result := hex.EncodeToString(finalPayload)

		fmt.Printf("\n--- ✅ Sicher exportiertes Profil: **%s** ---\n", exportProfileName)
		fmt.Println("Payload:")
		fmt.Println(result)

		err := clipboard.WriteAll(result)
		if err == nil {
			fmt.Println("(Payload in die Zwischenablage kopiert)")
		} else {
			fmt.Println("(Kopieren in die Zwischenablage fehlgeschlagen)")
		}
		return
	}

	if importProfilePayload != "" {
		if customKey == "" {
			fmt.Println("Fehler: Für den Profil-Import muss der -key (Passphrase) angegeben werden.")
			os.Exit(1)
		}

		if len(globalConf.Profiles) >= maxProfiles {
			fmt.Printf("Fehler: Maximale Anzahl von Profilen (%d) erreicht. Import abgebrochen.\n", maxProfiles)
			os.Exit(1)
		}

		decoded, err := hex.DecodeString(importProfilePayload)
		if err != nil {
			fmt.Println("Fehler: Ungültige Hex-Zeichenkette für den Import.")
			os.Exit(1)
		}

		saltSize := currentProfile.SaltSize
		if len(decoded) < saltSize {
			fmt.Println("Fehler: Import-Payload zu kurz (fehlt Salt oder Daten).")
			os.Exit(1)
		}

		salt := decoded[:saltSize]
		ciphertext := decoded[saltSize:]

		decryptedBytes := parallelKeyStreamXor(ciphertext, []byte(customKey), salt)

		unpaddedBytes, err := unpad(decryptedBytes)
		if err != nil {
			fmt.Println("\n[FAILED] Import-Fehler: Entschlüsselung fehlgeschlagen (Falscher Key oder falsche Konfiguration beim Export).")
			os.Exit(1)
		}

		var importedPayload ExportProfilePayload
		if err := json.Unmarshal(unpaddedBytes, &importedPayload); err != nil {
			fmt.Printf("Fehler: Ungültiges JSON-Format im entschlüsselten Payload: %v\n", err)
			os.Exit(1)
		}

		profileName := importedPayload.ProfileName
		newProfile := importedPayload.Config

		if err := validateProfile(newProfile); err != nil {
			fmt.Printf("Fehler: Importiertes Profil '%s' ist ungültig: %v\n", profileName, err)
			os.Exit(1)
		}

		if _, ok := globalConf.Profiles[profileName]; ok {
			fmt.Printf("Warnung: Profilname '%s' existiert bereits und wird überschrieben.\n", profileName)
		}

		globalConf.Profiles[profileName] = newProfile
		if err := saveConfig(); err != nil {
			fmt.Printf("Fehler beim Speichern des importierten Profils: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Profil **%s** erfolgreich importiert und gespeichert.\n", profileName)
		fmt.Println("Importierte Einstellungen:")
		printProfileInfo(newProfile)
		return
	}

	// --- Standard Profil-Management (Unverändert) ---

	if deleteProfileName != "" {
		if _, ok := globalConf.Profiles[deleteProfileName]; !ok {
			fmt.Printf("Fehler: Profil '%s' existiert nicht.\n", deleteProfileName)
			os.Exit(1)
		}
		if len(globalConf.Profiles) == 1 {
			fmt.Printf("Fehler: Das letzte verbleibende Profil ('%s') kann nicht gelöscht werden.\n", deleteProfileName)
			os.Exit(1)
		}
		if deleteProfileName == globalConf.CurrentProfileName {
			fmt.Printf("Fehler: Das aktuell aktive Profil '%s' kann nicht gelöscht werden. Wechseln Sie zuerst das Profil.\n", deleteProfileName)
			os.Exit(1)
		}

		delete(globalConf.Profiles, deleteProfileName)

		if err := saveConfig(); err != nil {
			fmt.Printf("Fehler beim Speichern der Konfiguration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Profil **%s** erfolgreich gelöscht.\n", deleteProfileName)
		return
	}

	configFlagWasSet := func() bool {
		return newIterations != defaultIterations ||
			newVirtualLanes != defaultLanes ||
			newBlockSize != defaultBlockSize ||
			newSaltSize != defaultSaltSize
	}

	if editProfileName != "" {
		targetProfile, ok := globalConf.Profiles[editProfileName]
		if !ok {
			fmt.Printf("Fehler: Profil '%s' existiert nicht. Verwenden Sie --create-profile.\n", editProfileName)
			os.Exit(1)
		}

		if !configFlagWasSet() {
			fmt.Printf("Hinweis: Keine Konfigurations-Flags angegeben. Profil '%s' wurde nicht geändert.\n", editProfileName)
			return
		}

		newProfile := targetProfile

		if newIterations != defaultIterations {
			newProfile.Iterations = newIterations
		}
		if newVirtualLanes != defaultLanes {
			newProfile.VirtualLanes = newVirtualLanes
		}
		if newBlockSize != defaultBlockSize {
			newProfile.BlockSize = newBlockSize
		}
		if newSaltSize != defaultSaltSize {
			newProfile.SaltSize = newSaltSize
		}

		if err := validateProfile(newProfile); err != nil {
			fmt.Printf("Fehler beim Bearbeiten des Profils: %v\n", err)
			os.Exit(1)
		}

		globalConf.Profiles[editProfileName] = newProfile
		if err := saveConfig(); err != nil {
			fmt.Printf("Fehler beim Speichern der Konfiguration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Profil **%s** erfolgreich bearbeitet.\n", editProfileName)
		fmt.Println("Neue Einstellungen:")
		printProfileInfo(newProfile)

		if editProfileName == globalConf.CurrentProfileName {
			currentProfile = newProfile
		}
		return
	}

	if createProfileName != "" {
		if len(globalConf.Profiles) >= maxProfiles {
			fmt.Printf("Fehler: Maximale Anzahl von Profilen (%d) erreicht.\n", maxProfiles)
			os.Exit(1)
		}
		if _, ok := globalConf.Profiles[createProfileName]; ok {
			fmt.Printf("Fehler: Profil '%s' existiert bereits. Verwenden Sie --edit-profile.\n", createProfileName)
			os.Exit(1)
		}

		newProfile := ProfileConfig{
			Iterations:   newIterations,
			VirtualLanes: newVirtualLanes,
			BlockSize:    newBlockSize,
			SaltSize:     newSaltSize,
		}

		if err := validateProfile(newProfile); err != nil {
			fmt.Printf("Fehler beim Erstellen des Profils: %v\n", err)
			os.Exit(1)
		}

		globalConf.Profiles[createProfileName] = newProfile
		if err := saveConfig(); err != nil {
			fmt.Printf("Fehler beim Speichern der Konfiguration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Profil **%s** erfolgreich erstellt.\n", createProfileName)
		fmt.Println("Erstellte Einstellungen:")
		printProfileInfo(newProfile)
		return
	}

	if changeProfileName != "" {
		if _, ok := globalConf.Profiles[changeProfileName]; !ok {
			fmt.Printf("Fehler: Profil '%s' existiert nicht.\n", changeProfileName)
			os.Exit(1)
		}
		globalConf.CurrentProfileName = changeProfileName
		if err := saveConfig(); err != nil {
			fmt.Printf("Fehler beim Speichern der Konfiguration: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Aktuelles Profil erfolgreich auf **%s** geändert.\n", changeProfileName)
		return
	}

	// --- Verschlüsselungs-/Entschlüsselungsmodus (-e oder -d) ---

	var mode string
	if encryptFlag && decryptFlag {
		fmt.Println("Error: Cannot use both -e and -d flags simultaneously.")
		printHelp()
		os.Exit(1)
	} else if encryptFlag {
		mode = "encrypt"
	} else if decryptFlag {
		mode = "decrypt"
	} else {
		printHelp()
		return
	}

	if profileName != "" && profileName != globalConf.CurrentProfileName {
		if conf, ok := globalConf.Profiles[profileName]; ok {
			currentProfile = conf
		} else {
			fmt.Printf("Fehler: Angegebenes Profil '%s' existiert nicht. Verwende das Standardprofil **%s**.\n", profileName, globalConf.CurrentProfileName)
		}
	}

	args := flag.Args()
	if len(args) != 2 {
		fmt.Printf("Error: Incorrect number of arguments for %s mode (Got %d, expected 2).\n", mode, len(args))
		fmt.Println("Use -h for help.")
		os.Exit(1)
	}

	key := args[0]
	msg := args[1]

	var usedProfileName string = globalConf.CurrentProfileName

	if profileName != "" && profileName != globalConf.CurrentProfileName {
		if conf, ok := globalConf.Profiles[profileName]; ok {
			currentProfile = conf
			usedProfileName = profileName
		} else {
			fmt.Printf("Fehler: Angegebenes Profil '%s' existiert nicht. Verwende das Standardprofil **%s**.\n", profileName, globalConf.CurrentProfileName)
		}
	}

	runCLI(key, msg, mode, usedProfileName)
}
