package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// digestFor returns the "sha256:<hex>" identities.yaml form of token's
// digest, so tests can build fixtures without duplicating the hashing
// logic Authenticate itself exercises.
func digestFor(token string) string {
	sum := sha256.Sum256([]byte(token))
	return digestPrefix + hex.EncodeToString(sum[:])
}

func TestNewToken(t *testing.T) {
	token, digestHex, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("NewToken() returned an empty token")
	}
	// base64.RawURLEncoding of 32 bytes is 43 characters, and must
	// contain no characters that would require percent-encoding in a
	// URL (the whole point of using this encoding for a Basic-auth
	// password embedded directly in a git remote URL).
	if len(token) != 43 {
		t.Errorf("len(token) = %d, want 43 (32 bytes base64url-encoded)", len(token))
	}
	for _, r := range token {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
			t.Errorf("token contains non-URL-safe rune %q", r)
		}
	}

	sum := sha256.Sum256([]byte(token))
	if want := hex.EncodeToString(sum[:]); digestHex != want {
		t.Errorf("digestHex = %q, want %q (sha256 of the returned token)", digestHex, want)
	}

	token2, _, err := NewToken()
	if err != nil {
		t.Fatalf("NewToken() second call error = %v", err)
	}
	if token2 == token {
		t.Error("two calls to NewToken() returned the same token")
	}
}

func TestNewStaticTokenAuthenticator(t *testing.T) {
	validDigest := digestFor("some-token")

	tests := []struct {
		name    string
		digests map[string]string
		wantErr string
	}{
		{
			name:    "valid single identity",
			digests: map[string]string{"run-1": validDigest},
		},
		{
			name:    "no identities",
			digests: map[string]string{},
			wantErr: "at least one identity",
		},
		{
			name:    "missing sha256 prefix",
			digests: map[string]string{"run-1": strings.TrimPrefix(validDigest, digestPrefix)},
			wantErr: "must be prefixed",
		},
		{
			name:    "not valid hex",
			digests: map[string]string{"run-1": "sha256:not-hex!!"},
			wantErr: "not valid hex",
		},
		{
			name:    "wrong digest length",
			digests: map[string]string{"run-1": "sha256:deadbeef"},
			wantErr: "must be a sha256 digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewStaticTokenAuthenticator(tt.digests)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewStaticTokenAuthenticator() unexpected error: %v", err)
				}
				if auth == nil {
					t.Fatal("NewStaticTokenAuthenticator() = nil authenticator with no error")
				}
				return
			}
			if err == nil {
				t.Fatalf("NewStaticTokenAuthenticator() = nil error, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewStaticTokenAuthenticator() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadStaticTokenAuthenticator(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "identities.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		return path
	}

	t.Run("valid file authenticates its token", func(t *testing.T) {
		path := write(t, "identities:\n  - id: run-1\n    tokenDigest: "+digestFor("tok-1")+"\n")
		auth, err := LoadStaticTokenAuthenticator(path)
		if err != nil {
			t.Fatalf("LoadStaticTokenAuthenticator() error = %v", err)
		}

		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.SetBasicAuth("ignored-username", "tok-1")
		id, err := auth.Authenticate(context.Background(), r)
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if id.ID != "run-1" {
			t.Errorf("Authenticate() id = %q, want %q", id.ID, "run-1")
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadStaticTokenAuthenticator(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		if err == nil {
			t.Fatal("LoadStaticTokenAuthenticator() = nil error, want error for a missing file")
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		path := write(t, "identities: [this is not valid\n")
		_, err := LoadStaticTokenAuthenticator(path)
		if err == nil {
			t.Fatal("LoadStaticTokenAuthenticator() = nil error, want error for malformed YAML")
		}
	})

	t.Run("empty identity list", func(t *testing.T) {
		path := write(t, "identities: []\n")
		_, err := LoadStaticTokenAuthenticator(path)
		if err == nil || !strings.Contains(err.Error(), "at least one identity") {
			t.Fatalf("LoadStaticTokenAuthenticator() error = %v, want substring %q", err, "at least one identity")
		}
	})

	t.Run("empty id", func(t *testing.T) {
		path := write(t, "identities:\n  - id: \"\"\n    tokenDigest: "+digestFor("tok-1")+"\n")
		_, err := LoadStaticTokenAuthenticator(path)
		if err == nil || !strings.Contains(err.Error(), "id is required") {
			t.Fatalf("LoadStaticTokenAuthenticator() error = %v, want substring %q", err, "id is required")
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		path := write(t, "identities:\n  - id: run-1\n    tokenDigest: "+digestFor("tok-1")+
			"\n  - id: run-1\n    tokenDigest: "+digestFor("tok-2")+"\n")
		_, err := LoadStaticTokenAuthenticator(path)
		if err == nil || !strings.Contains(err.Error(), "duplicate id") {
			t.Fatalf("LoadStaticTokenAuthenticator() error = %v, want substring %q", err, "duplicate id")
		}
	})

	t.Run("bad tokenDigest surfaces decode error", func(t *testing.T) {
		path := write(t, "identities:\n  - id: run-1\n    tokenDigest: not-a-digest\n")
		_, err := LoadStaticTokenAuthenticator(path)
		if err == nil || !strings.Contains(err.Error(), "must be prefixed") {
			t.Fatalf("LoadStaticTokenAuthenticator() error = %v, want substring %q", err, "must be prefixed")
		}
	})
}

func TestAuthenticate(t *testing.T) {
	auth, err := NewStaticTokenAuthenticator(map[string]string{
		"run-1": digestFor("correct-token"),
	})
	if err != nil {
		t.Fatalf("NewStaticTokenAuthenticator() error = %v", err)
	}

	tests := []struct {
		name    string
		request func() *http.Request
		wantID  string
		wantErr bool
	}{
		{
			name: "valid basic auth password",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.SetBasicAuth("any-username-is-ignored", "correct-token")
				return r
			},
			wantID: "run-1",
		},
		{
			name: "valid bearer header",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearer correct-token")
				return r
			},
			wantID: "run-1",
		},
		{
			name: "wrong token via basic auth",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.SetBasicAuth("x", "wrong-token")
				return r
			},
			wantErr: true,
		},
		{
			name: "no credentials at all",
			request: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/", nil)
			},
			wantErr: true,
		},
		{
			name: "empty basic auth password",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.SetBasicAuth("x", "")
				return r
			},
			wantErr: true,
		},
		{
			name: "malformed bearer header (no space)",
			request: func() *http.Request {
				r := httptest.NewRequest(http.MethodGet, "/", nil)
				r.Header.Set("Authorization", "Bearercorrect-token")
				return r
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := auth.Authenticate(context.Background(), tt.request())
			if tt.wantErr {
				if err == nil {
					t.Fatal("Authenticate() = nil error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Authenticate() unexpected error: %v", err)
			}
			if id.ID != tt.wantID {
				t.Errorf("Authenticate() id = %q, want %q", id.ID, tt.wantID)
			}
		})
	}
}
