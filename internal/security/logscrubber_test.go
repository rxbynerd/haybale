package security

import (
	"strings"
	"testing"
)

func TestScrub(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantGone []string // substrings that must NOT survive scrubbing
		wantKept []string // substrings that must survive unchanged
	}{
		{
			name:     "basic auth header",
			input:    `Authorization: Basic eC1hY2Nlc3MtdG9rZW46c2VjcmV0`,
			wantGone: []string{"eC1hY2Nlc3MtdG9rZW46c2VjcmV0"},
			wantKept: []string{"Authorization:"},
		},
		{
			name:     "bearer token header",
			input:    `Authorization: Bearer haybale-secret-token-value`,
			wantGone: []string{"haybale-secret-token-value"},
			wantKept: []string{"Authorization:"},
		},
		{ //nolint:gosec // G101: fake test fixture exercising Scrub's url_userinfo pattern, not a real credential
			name:     "url with embedded userinfo",
			input:    `cloning https://x-access-token:ghs_supersecrettoken@github.com/acme/widgets.git`,
			wantGone: []string{"ghs_supersecrettoken", "x-access-token:ghs_supersecrettoken@"},
			wantKept: []string{"cloning", "github.com/acme/widgets.git"},
		},
		{
			name:     "github personal access token",
			input:    `token ghp_1234567890abcdefghijklmnopqrstuvwx leaked`,
			wantGone: []string{"ghp_1234567890abcdefghijklmnopqrstuvwx"},
			wantKept: []string{"token", "leaked"},
		},
		{
			name:     "github app installation token",
			input:    `minted ghs_abcdEFGH1234567890 for repo`,
			wantGone: []string{"ghs_abcdEFGH1234567890"},
			wantKept: []string{"minted", "for repo"},
		},
		{
			name:     "github oauth token",
			input:    `token gho_1234567890abcdefghijklmnopqrstuvwx leaked`,
			wantGone: []string{"gho_1234567890abcdefghijklmnopqrstuvwx"},
			wantKept: []string{"token", "leaked"},
		},
		{
			name:     "github user-to-server token",
			input:    `token ghu_1234567890abcdefghijklmnopqrstuvwx leaked`,
			wantGone: []string{"ghu_1234567890abcdefghijklmnopqrstuvwx"},
			wantKept: []string{"token", "leaked"},
		},
		{
			name:     "github refresh token",
			input:    `token ghr_1234567890abcdefghijklmnopqrstuvwx leaked`,
			wantGone: []string{"ghr_1234567890abcdefghijklmnopqrstuvwx"},
			wantKept: []string{"token", "leaked"},
		},
		{
			name:     "github fine-grained personal access token",
			input:    `token github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789 leaked`,
			wantGone: []string{"github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789"},
			wantKept: []string{"token", "leaked"},
		},
		{ //nolint:gosec // G101: fake test fixture exercising Scrub's pem_private_key pattern, not a real key
			name:     "pem private key",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJ...\n-----END RSA PRIVATE KEY-----",
			wantGone: []string{"-----BEGIN RSA PRIVATE KEY-----"},
		},
		{
			name:     "no secret material",
			input:    "proxied request identity=run-1 host=github.com owner=acme repo=widgets verb=read status=200",
			wantKept: []string{"proxied request identity=run-1 host=github.com owner=acme repo=widgets verb=read status=200"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scrub(tt.input)
			for _, gone := range tt.wantGone {
				if strings.Contains(got, gone) {
					t.Errorf("Scrub(%q) = %q, must not contain %q", tt.input, got, gone)
				}
			}
			for _, kept := range tt.wantKept {
				if !strings.Contains(got, kept) {
					t.Errorf("Scrub(%q) = %q, want it to still contain %q", tt.input, got, kept)
				}
			}
		})
	}
}

func TestScrubIsIdempotentOnCleanInput(t *testing.T) {
	const clean = "identity=run-1 host=github.com owner=acme repo=widgets"
	if got := Scrub(clean); got != clean {
		t.Errorf("Scrub(%q) = %q, want unchanged", clean, got)
	}
}
