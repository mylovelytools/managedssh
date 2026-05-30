package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/mylovelytools/managedssh/internal/fsutil"
	"github.com/mylovelytools/managedssh/internal/vault"
)

const (
	bundleVersion = 1
	bundleName    = "managedssh-export.json"
)

type bundle struct {
	Version   int             `json:"version"`
	CreatedAt string          `json:"created_at"`
	VaultJSON json.RawMessage `json:"vault_json"`
	HostsJSON json.RawMessage `json:"hosts_json"`
}

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, bundleName), nil
}

func ExportPathForDir(dir string) string {
	return filepath.Join(dir, bundleName)
}

func Export(path string) error {
	dir, err := vault.Dir()
	if err != nil {
		return err
	}

	vaultPath := filepath.Join(dir, "vault.json")
	hostsPath := filepath.Join(dir, "hosts.json")

	vaultData, err := os.ReadFile(vaultPath)
	if err != nil {
		return fmt.Errorf("reading vault metadata: %w", err)
	}

	hostsData, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("reading hosts data: %w", err)
	}

	b := bundle{
		Version:   bundleVersion,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		VaultJSON: json.RawMessage(vaultData),
		HostsJSON: json.RawMessage(hostsData),
	}

	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding export bundle: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating export directory: %w", err)
	}
	if err := fsutil.AtomicWrite(path, out, 0600); err != nil {
		return fmt.Errorf("writing export bundle: %w", err)
	}
	return nil
}

func Import(path string) error {
	b, err := loadBundle(path)
	if err != nil {
		return err
	}

	dir, err := vault.Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	if err := fsutil.AtomicWrite(filepath.Join(dir, "vault.json"), b.VaultJSON, 0600); err != nil {
		return fmt.Errorf("writing vault metadata: %w", err)
	}
	if err := fsutil.AtomicWrite(filepath.Join(dir, "hosts.json"), b.HostsJSON, 0600); err != nil {
		return fmt.Errorf("writing hosts data: %w", err)
	}

	return nil
}

func VerifyMasterPassword(path, password string) error {
	b, err := loadBundle(path)
	if err != nil {
		return err
	}

	key, err := vault.UnlockWithMetaJSON(password, b.VaultJSON)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassword) {
			return vault.ErrWrongPassword
		}
		return fmt.Errorf("verifying backup master key: %w", err)
	}
	vault.ZeroKey(key)
	return nil
}

func loadBundle(path string) (*bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading import bundle: %w", err)
	}

	var b bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding import bundle: %w", err)
	}
	if b.Version != bundleVersion {
		return nil, fmt.Errorf("unsupported bundle version: %d", b.Version)
	}
	if len(b.VaultJSON) == 0 {
		return nil, fmt.Errorf("import bundle is missing vault data")
	}
	if len(b.HostsJSON) == 0 {
		return nil, fmt.Errorf("import bundle is missing hosts data")
	}

	var vaultDoc map[string]any
	if err := json.Unmarshal(b.VaultJSON, &vaultDoc); err != nil {
		return nil, fmt.Errorf("invalid vault data in import bundle: %w", err)
	}
	var hostsDoc map[string]any
	if err := json.Unmarshal(b.HostsJSON, &hostsDoc); err != nil {
		return nil, fmt.Errorf("invalid hosts data in import bundle: %w", err)
	}

	return &b, nil
}

