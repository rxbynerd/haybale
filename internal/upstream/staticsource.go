package upstream

import (
	"context"
	"fmt"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

// StaticSource is a CredentialSource that always returns the same fixed
// Basic-auth credential, regardless of repo or verb. It is the simplest
// possible CredentialSource — a single shared upstream token (e.g. a
// deploy token for git.internal.example) rather than a per-repo GitHub
// App installation token (GitHubAppSource, M4).
type StaticSource struct {
	credential BasicAuth
}

// NewStaticSource builds a StaticSource that returns username/password
// on every call. Both must be non-empty: an empty password in
// particular would silently authenticate as no credential at all, which
// is worse than failing fast at construction time — this is the
// fail-fast check internal/config's Validate() relies on when building a
// StaticSource from a "type: static" credential block.
func NewStaticSource(username, password string) (*StaticSource, error) {
	if username == "" {
		return nil, fmt.Errorf("upstream: static source username is required")
	}
	if password == "" {
		return nil, fmt.Errorf("upstream: static source password is required")
	}
	return &StaticSource{credential: BasicAuth{Username: username, Password: password}}, nil
}

// Credentials implements CredentialSource. It never fails once
// constructed (NewStaticSource already validated both fields) and
// ignores repo/verb entirely — every request gets the same fixed
// credential.
func (s *StaticSource) Credentials(context.Context, gitproto.Repo, gitproto.Verb) (BasicAuth, error) {
	return s.credential, nil
}
