package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTokenNewCommand(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"token", "new", "--id", "run-abc123"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error: %v", err)
	}

	out := buf.String()

	tokenRe := regexp.MustCompile(`token \(save this now[^\n]*\):\n([A-Za-z0-9_-]+)\n`)
	m := tokenRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("output %q did not contain a token line matching %s", out, tokenRe)
	}
	token := m[1]

	if !strings.Contains(out, "id: run-abc123") {
		t.Errorf("output = %q, want it to contain the identities.yaml id stanza", out)
	}

	sum := sha256.Sum256([]byte(token))
	wantDigest := "tokenDigest: sha256:" + hex.EncodeToString(sum[:])
	if !strings.Contains(out, wantDigest) {
		t.Errorf("output = %q, want it to contain %q (the sha256 digest of the printed token)", out, wantDigest)
	}
}

// TestTokenNewCommandRequiresID exercises runTokenNew directly rather
// than through rootCmd.Execute(): tokenNewCmd's --id flag is a
// package-level pflag.FlagSet whose "Changed" bit, once set by an
// earlier Execute() call in this test binary, never resets — so
// asserting cobra's MarkFlagRequired behavior via repeated Execute()
// calls on the shared rootCmd would be order-dependent. runTokenNew's
// own id == "" check (the authoritative validation — MarkFlagRequired
// only catches an omitted flag, not an explicitly empty one) is what
// this test pins.
func TestTokenNewCommandRequiresID(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if err := runTokenNew(cmd, ""); err == nil {
		t.Fatal("runTokenNew(_, \"\") = nil error, want error for an empty id")
	}
}

func TestTokenNewCommandMintsDistinctTokens(t *testing.T) {
	run := func() string {
		buf := &bytes.Buffer{}
		rootCmd.SetOut(buf)
		rootCmd.SetArgs([]string{"token", "new", "--id", "run-1"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("Execute() error: %v", err)
		}
		return buf.String()
	}

	first := run()
	second := run()
	if first == second {
		t.Error("two invocations of `token new` produced identical output; want distinct tokens")
	}
}
