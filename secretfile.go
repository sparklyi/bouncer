package bouncer

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// secretFileSize is the length of a generated master secret.
const secretFileSize = 32

// LoadOrCreateSecret reads a master secret from path, generating it with 0600
// permissions on first use. It exists so that callers do not have to invent
// their own key management just to get started.
func LoadOrCreateSecret(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("bouncer: secret file path must not be empty")
	}
	raw, err := os.ReadFile(path)
	if err == nil {
		key := bytes.TrimSpace(raw)
		if len(key) < keyLen {
			return nil, fmt.Errorf("bouncer: secret file %s is shorter than %d bytes", path, keyLen)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("bouncer: read secret file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("bouncer: create secret directory: %w", err)
	}
	key := make([]byte, secretFileSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("bouncer: generate secret: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return LoadOrCreateSecret(path)
	}
	if err != nil {
		return nil, fmt.Errorf("bouncer: create secret file: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("bouncer: write secret file: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("bouncer: close secret file: %w", err)
	}
	return key, nil
}
