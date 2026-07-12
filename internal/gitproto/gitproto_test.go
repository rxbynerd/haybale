package gitproto

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		name      string
		method    string
		target    string
		wantRepo  Repo
		wantVerb  Verb
		wantErr   bool
		wantErrIs error // checked with errors.Is when set
	}{
		// --- valid shapes ---
		{
			name:     "read via info/refs upload-pack",
			method:   "GET",
			target:   "/github.com/acme/widgets.git/info/refs?service=git-upload-pack",
			wantRepo: Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
			wantVerb: Read,
		},
		{
			name:     "write via info/refs receive-pack counts as write",
			method:   "GET",
			target:   "/github.com/acme/widgets.git/info/refs?service=git-receive-pack",
			wantRepo: Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
			wantVerb: Write,
		},
		{
			name:     "read via POST git-upload-pack",
			method:   "POST",
			target:   "/github.com/acme/widgets.git/git-upload-pack",
			wantRepo: Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
			wantVerb: Read,
		},
		{
			name:     "write via POST git-receive-pack",
			method:   "POST",
			target:   "/github.com/acme/widgets.git/git-receive-pack",
			wantRepo: Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
			wantVerb: Write,
		},
		{
			name:     "repo name without .git suffix",
			method:   "POST",
			target:   "/github.com/acme/widgets/git-upload-pack",
			wantRepo: Repo{Host: "github.com", Owner: "acme", Name: "widgets"},
			wantVerb: Read,
		},

		// --- malformed paths ---
		{
			name:      "too few segments",
			method:    "GET",
			target:    "/github.com/acme/info/refs?service=git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "empty owner segment",
			method:    "GET",
			target:    "/github.com//widgets.git/info/refs?service=git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "empty repo segment",
			method:    "POST",
			target:    "/github.com/acme//git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "repo segment is bare .git",
			method:    "POST",
			target:    "/github.com/acme/.git/git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "only host segment",
			method:    "GET",
			target:    "/github.com",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},

		// --- path traversal ---
		{
			name:      "literal .. in owner segment",
			method:    "POST",
			target:    "/github.com/../widgets.git/git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "literal .. in repo segment",
			method:    "POST",
			target:    "/github.com/acme/../git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "percent-encoded .. traversal",
			method:    "POST",
			target:    "/github.com/acme/%2e%2e/git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "single dot segment",
			method:    "POST",
			target:    "/github.com/acme/./git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "traversal attempting to escape via endpoint",
			method:    "POST",
			target:    "/github.com/acme/widgets.git/../../../etc/passwd",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},

		// --- dumb protocol rejection ---
		{
			name:      "dumb protocol object fetch",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/objects/ab/cdef0123456789",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "dumb protocol raw HEAD fetch",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/HEAD",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "dumb protocol info/packs",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/info/packs",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},

		// --- service= validation ---
		{
			name:      "info/refs missing service parameter",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/info/refs",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "info/refs unknown service value",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/info/refs?service=git-upload-archive",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},

		// --- method mismatches ---
		{
			name:      "info/refs via POST is rejected",
			method:    "POST",
			target:    "/github.com/acme/widgets.git/info/refs?service=git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "git-upload-pack via GET is rejected",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/git-upload-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
		{
			name:      "git-receive-pack via GET is rejected",
			method:    "GET",
			target:    "/github.com/acme/widgets.git/git-receive-pack",
			wantErr:   true,
			wantErrIs: ErrInvalidRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.target, nil)
			repo, verb, err := ParseRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParseRequest(%s %s) = nil error, want error", tt.method, tt.target)
				}
				if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
					t.Fatalf("ParseRequest(%s %s) error = %v, want errors.Is(_, %v)", tt.method, tt.target, err, tt.wantErrIs)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseRequest(%s %s) unexpected error: %v", tt.method, tt.target, err)
			}
			if repo != tt.wantRepo {
				t.Errorf("ParseRequest(%s %s) repo = %+v, want %+v", tt.method, tt.target, repo, tt.wantRepo)
			}
			if verb != tt.wantVerb {
				t.Errorf("ParseRequest(%s %s) verb = %v, want %v", tt.method, tt.target, verb, tt.wantVerb)
			}
		})
	}
}

// TestInvalidSingleLine pins the R2 fix: invalid()'s .Error() must never
// contain a newline, or every rejection log line that includes it would
// break in half. errors.Join (the prior implementation) violated this;
// fmt.Errorf("%w: %s", ...) does not.
func TestInvalidSingleLine(t *testing.T) {
	err := invalid("some reason")
	if strings.Contains(err.Error(), "\n") {
		t.Errorf("invalid(%q).Error() = %q, contains a newline", "some reason", err.Error())
	}
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("invalid(%q) does not satisfy errors.Is(_, ErrInvalidRequest)", "some reason")
	}
}

func TestVerbString(t *testing.T) {
	tests := []struct {
		verb Verb
		want string
	}{
		{Read, "read"},
		{Write, "write"},
		{Verb(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.verb.String(); got != tt.want {
			t.Errorf("Verb(%d).String() = %q, want %q", tt.verb, got, tt.want)
		}
	}
}
