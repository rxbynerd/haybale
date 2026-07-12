package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNewFileKeySource covers newFileKeySource's error paths, none of
// which the happy-path callers in jwt_test.go exercise: a missing file, a
// malformed JSON body, and a well-formed-but-empty key set. Each must fail
// at construction (fail-fast), never yield a source that rejects every
// token at request time.
func TestNewFileKeySource(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		_, err := newFileKeySource(filepath.Join(t.TempDir(), "nope.json"))
		if err == nil || !strings.Contains(err.Error(), "read jwksFile") {
			t.Fatalf("err = %v, want a read error", err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.json")
		if err := os.WriteFile(path, []byte("{not valid json"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := newFileKeySource(path)
		if err == nil {
			t.Fatal("newFileKeySource succeeded on malformed JSON, want error")
		}
	})

	t.Run("empty key set", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.json")
		if err := os.WriteFile(path, []byte(`{"keys":[]}`), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := newFileKeySource(path)
		if err == nil || !strings.Contains(err.Error(), "no keys") {
			t.Fatalf("err = %v, want a 'no keys' error", err)
		}
	})

	t.Run("valid file", func(t *testing.T) {
		s := newES256Signer(t, "k1")
		if _, err := newFileKeySource(jwksFile(t, s)); err != nil {
			t.Fatalf("newFileKeySource on a valid file: %v", err)
		}
	})
}
