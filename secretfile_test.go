package bouncer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sparklyi/bouncer"
)

func TestLoadOrCreateSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "bouncer.key")

	first, err := bouncer.LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(first) < 32 {
		t.Fatalf("key length = %d", len(first))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("mode = %o, want 600", mode)
	}

	second, err := bouncer.LoadOrCreateSecret(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("the second call must reuse the existing key")
	}
}

func TestLoadOrCreateSecretRejectsShortFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "short.key")
	if err := os.WriteFile(path, []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bouncer.LoadOrCreateSecret(path); err == nil {
		t.Fatal("short key must be rejected")
	}
}
