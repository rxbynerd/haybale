package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/identity"
)

// TestMatchesAny table-tests the glob semantics matchesAny's doc comment
// promises: path.Match applied to the joined "{host}/{owner}/{repo}"
// key, where "*" never crosses a "/" boundary.
func TestMatchesAny(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		s        string
		want     bool
	}{
		{
			name:     "exact match",
			patterns: []string{"github.com/acme/widgets"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "exact mismatch",
			patterns: []string{"github.com/acme/widgets"},
			s:        "github.com/acme/gadgets",
			want:     false,
		},
		{
			name:     "single-segment wildcard matches repo name",
			patterns: []string{"github.com/acme/*"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "single-segment wildcard does not cross owner boundary",
			patterns: []string{"github.com/acme/*"},
			s:        "github.com/other-owner/widgets",
			want:     false,
		},
		{
			name:     "host wildcard",
			patterns: []string{"*/acme/*"},
			s:        "gitlab.example/acme/widgets",
			want:     true,
		},
		{
			name:     "owner wildcard",
			patterns: []string{"github.com/*/*"},
			s:        "github.com/anyone/widgets",
			want:     true,
		},
		{
			name:     "all wildcard matches everything",
			patterns: []string{"*/*/*"},
			s:        "gitlab.example/anyone/anything",
			want:     true,
		},
		{
			name:     "two-segment pattern never matches a three-segment key",
			patterns: []string{"acme/*"},
			s:        "github.com/acme/widgets",
			want:     false,
		},
		{
			name:     "two-segment pattern never matches even a two-segment-shaped owner/repo substring",
			patterns: []string{"acme/*"},
			s:        "acme/widgets",
			want:     true, // sanity check: it DOES match a genuinely two-segment string
		},
		{
			name:     "single wildcard segment does not match multiple segments",
			patterns: []string{"github.com/*"},
			s:        "github.com/acme/widgets",
			want:     false,
		},
		{
			name:     "double star has no special cross-segment meaning",
			patterns: []string{"**"},
			s:        "github.com/acme/widgets",
			want:     false,
		},
		{
			name:     "character class",
			patterns: []string{"github.com/acme/widget[s]"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "single-char wildcard",
			patterns: []string{"github.com/acme/widget?"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "first pattern in list matches",
			patterns: []string{"github.com/acme/widgets", "github.com/acme/other"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "second pattern in list matches",
			patterns: []string{"github.com/acme/other", "github.com/acme/widgets"},
			s:        "github.com/acme/widgets",
			want:     true,
		},
		{
			name:     "no pattern matches",
			patterns: []string{"github.com/acme/other"},
			s:        "github.com/acme/widgets",
			want:     false,
		},
		{
			name:     "empty pattern list never matches",
			patterns: nil,
			s:        "github.com/acme/widgets",
			want:     false,
		},
		{
			name:     "identity pattern prefix-style glob",
			patterns: []string{"run-*"},
			s:        "run-abc123",
			want:     true,
		},
		{
			name:     "identity pattern exact",
			patterns: []string{"run-abc123"},
			s:        "run-abc123",
			want:     true,
		},
		{
			name:     "identity pattern mismatch",
			patterns: []string{"run-abc123"},
			s:        "run-xyz789",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchesAny(tt.patterns, tt.s); got != tt.want {
				t.Errorf("matchesAny(%v, %q) = %v, want %v", tt.patterns, tt.s, got, tt.want)
			}
		})
	}
}

func TestNewGlobEngine(t *testing.T) {
	tests := []struct {
		name    string
		rules   []Rule
		wantErr string
	}{
		{
			name:  "empty rules is valid (deny everything)",
			rules: nil,
		},
		{
			name: "valid rule",
			rules: []Rule{
				{Identities: []string{"run-*"}, Repos: []string{"github.com/acme/*"}, Permissions: []Permission{PermissionRead, PermissionWrite}},
			},
		},
		{
			name: "no identity patterns",
			rules: []Rule{
				{Repos: []string{"github.com/acme/*"}, Permissions: []Permission{PermissionRead}},
			},
			wantErr: "at least one identity pattern",
		},
		{
			name: "no repo patterns",
			rules: []Rule{
				{Identities: []string{"run-*"}, Permissions: []Permission{PermissionRead}},
			},
			wantErr: "at least one repo pattern",
		},
		{
			name: "no permissions",
			rules: []Rule{
				{Identities: []string{"run-*"}, Repos: []string{"github.com/acme/*"}},
			},
			wantErr: "at least one permission",
		},
		{
			name: "unknown permission",
			rules: []Rule{
				{Identities: []string{"run-*"}, Repos: []string{"github.com/acme/*"}, Permissions: []Permission{"admin"}},
			},
			wantErr: `must be "read" or "write"`,
		},
		{
			name: "malformed identity pattern",
			rules: []Rule{
				{Identities: []string{"run-["}, Repos: []string{"github.com/acme/*"}, Permissions: []Permission{PermissionRead}},
			},
			wantErr: "identity pattern",
		},
		{
			name: "malformed repo pattern",
			rules: []Rule{
				{Identities: []string{"run-*"}, Repos: []string{"github.com/acme/["}, Permissions: []Permission{PermissionRead}},
			},
			wantErr: "repo pattern",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine, err := NewGlobEngine(tt.rules)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("NewGlobEngine() unexpected error: %v", err)
				}
				if engine == nil {
					t.Fatal("NewGlobEngine() = nil engine with no error")
				}
				return
			}
			if err == nil {
				t.Fatalf("NewGlobEngine() = nil error, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewGlobEngine() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoadGlobEngine(t *testing.T) {
	write := func(t *testing.T, content string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "policy.yaml")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		return path
	}

	t.Run("valid file", func(t *testing.T) {
		path := write(t, "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [read, write]\n")
		engine, err := LoadGlobEngine(path)
		if err != nil {
			t.Fatalf("LoadGlobEngine() error = %v", err)
		}
		decision := engine.Authorize(identity.Identity{ID: "run-1"}, gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
		if !decision.Allowed {
			t.Errorf("Authorize() = %+v, want Allowed", decision)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := LoadGlobEngine(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
		if err == nil {
			t.Fatal("LoadGlobEngine() = nil error, want error for a missing file")
		}
	})

	t.Run("malformed YAML", func(t *testing.T) {
		path := write(t, "rules: [this is not valid\n")
		_, err := LoadGlobEngine(path)
		if err == nil {
			t.Fatal("LoadGlobEngine() = nil error, want error for malformed YAML")
		}
	})

	t.Run("empty rules file is valid", func(t *testing.T) {
		path := write(t, "rules: []\n")
		engine, err := LoadGlobEngine(path)
		if err != nil {
			t.Fatalf("LoadGlobEngine() error = %v", err)
		}
		decision := engine.Authorize(identity.Identity{ID: "run-1"}, gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}, gitproto.Read)
		if decision.Allowed {
			t.Error("Authorize() with no rules = Allowed, want denied")
		}
	})

	t.Run("invalid rule surfaces validation error", func(t *testing.T) {
		path := write(t, "rules:\n  - identities: [\"run-*\"]\n    repos: [\"github.com/acme/*\"]\n    permissions: [admin]\n")
		_, err := LoadGlobEngine(path)
		if err == nil || !strings.Contains(err.Error(), `must be "read" or "write"`) {
			t.Fatalf("LoadGlobEngine() error = %v, want validation error", err)
		}
	})
}

func TestAuthorize(t *testing.T) {
	rules := []Rule{
		// First rule (checked first): read-only identity, read+write for
		// the acme org.
		{
			Identities:  []string{"run-readonly-*"},
			Repos:       []string{"github.com/acme/*"},
			Permissions: []Permission{PermissionRead},
		},
		// Second rule: read+write identity, same repos.
		{
			Identities:  []string{"run-readwrite-*"},
			Repos:       []string{"github.com/acme/*"},
			Permissions: []Permission{PermissionRead, PermissionWrite},
		},
		// Third rule: write-only identity — does NOT imply read.
		{
			Identities:  []string{"run-writeonly-*"},
			Repos:       []string{"github.com/acme/*"},
			Permissions: []Permission{PermissionWrite},
		},
	}
	engine, err := NewGlobEngine(rules)
	if err != nil {
		t.Fatalf("NewGlobEngine() error = %v", err)
	}

	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	otherRepo := gitproto.Repo{Host: "github.com", Owner: "other-org", Name: "widgets"}

	tests := []struct {
		name       string
		id         string
		repo       gitproto.Repo
		verb       gitproto.Verb
		wantAllow  bool
		wantRuleIs *Rule // nil means Decision.Rule must be nil (no match at all)
	}{
		{
			name:       "read-only identity can read",
			id:         "run-readonly-1",
			repo:       repo,
			verb:       gitproto.Read,
			wantAllow:  true,
			wantRuleIs: &rules[0],
		},
		{
			name:       "read-only identity cannot write",
			id:         "run-readonly-1",
			repo:       repo,
			verb:       gitproto.Write,
			wantAllow:  false,
			wantRuleIs: &rules[0], // matched, but doesn't grant write
		},
		{
			name:       "read-write identity can read",
			id:         "run-readwrite-1",
			repo:       repo,
			verb:       gitproto.Read,
			wantAllow:  true,
			wantRuleIs: &rules[1],
		},
		{
			name:       "read-write identity can write",
			id:         "run-readwrite-1",
			repo:       repo,
			verb:       gitproto.Write,
			wantAllow:  true,
			wantRuleIs: &rules[1],
		},
		{
			name:       "write-only identity can write",
			id:         "run-writeonly-1",
			repo:       repo,
			verb:       gitproto.Write,
			wantAllow:  true,
			wantRuleIs: &rules[2],
		},
		{
			name:       "write-only identity cannot read (write does not imply read)",
			id:         "run-writeonly-1",
			repo:       repo,
			verb:       gitproto.Read,
			wantAllow:  false,
			wantRuleIs: &rules[2],
		},
		{
			name:      "unknown identity: no matching rule at all",
			id:        "run-unknown-1",
			repo:      repo,
			verb:      gitproto.Read,
			wantAllow: false,
			// no rule matches the identity, so Rule must be nil
			wantRuleIs: nil,
		},
		{
			name:       "known identity, repo outside policy: no matching rule at all",
			id:         "run-readwrite-1",
			repo:       otherRepo,
			verb:       gitproto.Read,
			wantAllow:  false,
			wantRuleIs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := engine.Authorize(identity.Identity{ID: tt.id}, tt.repo, tt.verb)
			if decision.Allowed != tt.wantAllow {
				t.Errorf("Authorize().Allowed = %v, want %v (decision: %+v)", decision.Allowed, tt.wantAllow, decision)
			}
			if tt.wantRuleIs == nil {
				if decision.Rule != nil {
					t.Errorf("Authorize().Rule = %v, want nil (no matching rule)", decision.Rule)
				}
				return
			}
			if decision.Rule == nil {
				t.Fatalf("Authorize().Rule = nil, want a matched rule")
			}
			if decision.Rule.String() != tt.wantRuleIs.String() {
				t.Errorf("Authorize().Rule = %v, want %v", decision.Rule, tt.wantRuleIs)
			}
			if decision.Reason == "" {
				t.Error("Authorize().Reason is empty, want a human-readable explanation")
			}
		})
	}
}

func TestAuthorizeFirstMatchWins(t *testing.T) {
	// Two rules both match the same identity+repo: a broad deny-by-omission
	// first rule (read only) should win over a later, more permissive rule
	// for the same identity/repo pattern — first-match-wins, not
	// most-permissive-wins.
	rules := []Rule{
		{Identities: []string{"run-1"}, Repos: []string{"github.com/acme/widgets"}, Permissions: []Permission{PermissionRead}},
		{Identities: []string{"run-1"}, Repos: []string{"github.com/acme/widgets"}, Permissions: []Permission{PermissionRead, PermissionWrite}},
	}
	engine, err := NewGlobEngine(rules)
	if err != nil {
		t.Fatalf("NewGlobEngine() error = %v", err)
	}

	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	decision := engine.Authorize(identity.Identity{ID: "run-1"}, repo, gitproto.Write)
	if decision.Allowed {
		t.Error("Authorize() = Allowed, want denied: the first matching rule (read-only) should win over the later permissive rule")
	}
	if decision.Rule == nil || decision.Rule.String() != rules[0].String() {
		t.Errorf("Authorize().Rule = %v, want the first rule %v", decision.Rule, rules[0])
	}
}

func TestRuleString(t *testing.T) {
	r := Rule{Identities: []string{"run-*"}, Repos: []string{"github.com/acme/*"}, Permissions: []Permission{PermissionRead}}
	s := r.String()
	for _, want := range []string{"run-*", "github.com/acme/*", "read"} {
		if !strings.Contains(s, want) {
			t.Errorf("Rule.String() = %q, want it to contain %q", s, want)
		}
	}
}
