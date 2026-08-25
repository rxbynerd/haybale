package upstream

import (
	"context"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

func TestNewStaticSource(t *testing.T) {
	tests := []struct {
		name               string
		username, password string
		wantErr            string
	}{
		{name: "valid", username: "x-access-token", password: "secret-token"},
		{name: "empty username", username: "", password: "secret-token", wantErr: "username is required"},
		{name: "empty password", username: "x-access-token", password: "", wantErr: "password is required"},
		{name: "both empty", username: "", password: "", wantErr: "username is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src, err := NewStaticSource(tt.username, tt.password)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewStaticSource() unexpected error: %v", err)
				}
				if src == nil {
					t.Fatal("NewStaticSource() = nil, want non-nil")
				}
				return
			}
			if err == nil {
				t.Fatal("NewStaticSource() = nil error, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewStaticSource() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestStaticSourceCredentialsIsFixed asserts the core StaticSource
// contract: the same configured username/password comes back regardless
// of which repo or verb is asked about — there is no per-repo/per-verb
// behaviour to a static credential, unlike GitHubAppSource.
func TestStaticSourceCredentialsIsFixed(t *testing.T) {
	src, err := NewStaticSource("x-access-token", "secret-token")
	if err != nil {
		t.Fatalf("NewStaticSource() unexpected error: %v", err)
	}

	repos := []gitproto.Repo{
		{Host: "github.com", Owner: "acme", Name: "widgets"},
		{Host: "git.internal.example", Owner: "other", Name: "thing"},
	}
	verbs := []gitproto.Verb{gitproto.Read, gitproto.Write}

	for _, repo := range repos {
		for _, verb := range verbs {
			cred, err := src.Credentials(context.Background(), repo, verb)
			if err != nil {
				t.Fatalf("Credentials(%+v, %v) unexpected error: %v", repo, verb, err)
			}
			if cred.Username != "x-access-token" || cred.Password != "secret-token" {
				t.Errorf("Credentials(%+v, %v) = %+v, want fixed {x-access-token secret-token}", repo, verb, cred)
			}
		}
	}
}
