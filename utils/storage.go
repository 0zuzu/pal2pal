package utils

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"

	crypto "github.com/libp2p/go-libp2p/core/crypto"
)

const (
	AppFolderName    = "Pal2Pal.exe"
	SettingsFileName = "settings.json"
)

var configDir string

type IdentityJSON struct {
	PeerID string `json:"id"`
	Alias  string `json:"alias"`
	Birth  int64  `json:"birth"`
}

func init() {
	configDir, _ = os.UserConfigDir()

}

// Check if a file or folder exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Read contents of a file (as string)
func ReadFile(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// Write to a file (overwrites if exists)
func WriteFile(filePath string, content string) error {
	return os.WriteFile(filePath, []byte(content), 0644)
}

func CreateFolder(folderPath string) error {
	return os.MkdirAll(folderPath, os.ModePerm)
}

// Get list of files in a folder
func ListFilesInFolder(folderPath string) ([]string, error) {
	entries, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, entry := range entries {
		files = append(files, entry.Name())
	}
	return files, nil
}

func LoadSettings() (string, error) {
	configPath := filepath.Join(configDir, AppFolderName, SettingsFileName)
	return ReadFile(configPath)
}

func SaveSettings(content string) error {
	configPath := filepath.Join(configDir, AppFolderName, SettingsFileName)
	return WriteFile(configPath, content)
}

func SaveIdentity(identity Identity) error {
	identityPath := filepath.Join(configDir, AppFolderName, "identity")
	// Create temporary identityJson to marshal PeerID as string
	var identityJson IdentityJSON
	identityJson.Alias = identity.Alias
	identityJson.Birth = identity.Birth
	privKeyBytes, err := crypto.MarshalPrivateKey(identity.PeerID)
	if err != nil {
		return err
	}
	identityJson.PeerID = base64.StdEncoding.EncodeToString(privKeyBytes)
	// Marshal to JSON
	outputJson, err := json.Marshal(identityJson)
	if err != nil {
		return err
	}
	return WriteFile(identityPath, string(outputJson))
}

func ReadIdentity() (Identity, error) {
	identityPath := filepath.Join(configDir, AppFolderName, "identity")
	content, err := ReadFile(identityPath)
	if err != nil {
		return Identity{}, err
	}
	var identityJson IdentityJSON
	err = json.Unmarshal([]byte(content), &identityJson)
	if err != nil {
		return Identity{}, err
	}
	var identity Identity
	identity.Alias = identityJson.Alias
	identity.Birth = identityJson.Birth
	var decoded []byte
	decoded, err = base64.StdEncoding.DecodeString(identityJson.PeerID)
	if err != nil {
		return Identity{}, err
	}
	identity.PeerID, err = crypto.UnmarshalPrivateKey(decoded)
	if err != nil {
		return Identity{}, err
	}
	return identity, nil
}
