package upstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"golang.org/x/sync/singleflight"

	"github.com/rxbynerd/haybale/internal/gitproto"
	"github.com/rxbynerd/haybale/internal/security"
)

// defaultGitHubAPIBaseURL is the GitHub API host GitHubAppSource talks to
// when GitHubAppConfig.APIBaseURL is left empty — GitHub.com's own API,
// as opposed to a GitHub Enterprise Server instance's
// https://ghe.example.com/api/v3.
const defaultGitHubAPIBaseURL = "https://api.github.com"

// installationCacheTTL is how long a resolved installation ID is cached.
// Which installation a repo belongs to essentially never changes, so
// this is a long-lived, low-risk cache compared to the short-lived
// tokenCache — see GitHubAppSource's doc comment.
const installationCacheTTL = time.Hour

// GitHubAppConfig configures a GitHubAppSource.
type GitHubAppConfig struct {
	// AppID is the GitHub App's ID, used to sign the JWT GitHubAppSource
	// authenticates to the GitHub API with.
	AppID int64
	// PrivateKeyPEM is the GitHub App's PEM-encoded RSA private key.
	// GitHubAppSource never writes this anywhere; it is held only long
	// enough to build the JWT-signing transport in NewGitHubAppSource.
	PrivateKeyPEM []byte
	// APIBaseURL overrides the GitHub API base URL, e.g.
	// "https://ghe.example.com/api/v3" for GitHub Enterprise Server.
	// Defaults to defaultGitHubAPIBaseURL when empty.
	APIBaseURL string
}

// GitHubAppSource is a CredentialSource that mints GitHub App
// installation tokens scoped to exactly the one repo and the minimal
// permission (read or write to contents) a request needs — the
// least-privilege guarantee this type exists to enforce. It authenticates
// to the GitHub API as the App itself (a JWT signed with AppID's private
// key, handled by ghinstallation.AppsTransport) to:
//
//  1. resolve which installation owns a given repo
//     (GET /repos/{owner}/{repo}/installation, cached for
//     installationCacheTTL — this mapping is stable);
//  2. mint an installation access token scoped to that one repo and verb
//     (POST /app/installations/{id}/access_tokens with a repositories
//     and permissions body — see mint), cached and refreshed by the
//     embedded tokenCache.
//
// The minted token is presented to the upstream git host as HTTP Basic
// "x-access-token:<token>", GitHub's own convention for a token-as-password
// credential.
//
// GitHubAppSource is safe for concurrent use: tokenCache and
// installationLookup each hold their own mutex plus a singleflight.Group
// that collapses concurrent mint/lookup calls for the same key into one
// upstream call.
type GitHubAppSource struct {
	appID      int64
	apiBaseURL string
	httpClient *http.Client

	installations *installationLookup
	cache         *tokenCache

	// logger is where GitHubAppSource emits security.EventTokenMinted.
	// It defaults to slog.Default() at construction time (see
	// NewGitHubAppSource) because construction happens inside
	// config.Validate(), before internal/config's caller (serve.go) has
	// built its own ScrubHandler-wrapped logger. SetLogger lets that
	// caller install the real logger once it exists, before the server
	// starts accepting traffic. An atomic.Pointer, rather than a plain
	// field, so a concurrent SetLogger (which production code never
	// actually does more than once, but a test might) can't race with a
	// concurrent Credentials() call reading it.
	logger atomic.Pointer[slog.Logger]
}

// NewGitHubAppSource builds a GitHubAppSource from cfg. It fails fast if
// AppID is unset or PrivateKeyPEM is missing, empty, or does not parse as
// an RSA private key — exactly the checks internal/config's Validate()
// relies on to reject a broken github-app credential block at startup
// rather than on the first mint attempt.
func NewGitHubAppSource(cfg GitHubAppConfig) (*GitHubAppSource, error) {
	if cfg.AppID == 0 {
		return nil, fmt.Errorf("upstream: github app source: appID is required")
	}
	if len(cfg.PrivateKeyPEM) == 0 {
		return nil, fmt.Errorf("upstream: github app source: private key is required")
	}

	apiBaseURL := cfg.APIBaseURL
	if apiBaseURL == "" {
		apiBaseURL = defaultGitHubAPIBaseURL
	}

	// NewAppsTransport parses PrivateKeyPEM (jwt.ParseRSAPrivateKeyFromPEM
	// under the hood) and returns an error for anything that isn't a
	// valid RSA private key — this is the fail-fast-at-construction check
	// a malformed or non-RSA privateKeyPath file must hit.
	appsTransport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, cfg.AppID, cfg.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("upstream: github app source: parse private key: %w", err)
	}
	appsTransport.BaseURL = apiBaseURL

	src := &GitHubAppSource{
		appID:         cfg.AppID,
		apiBaseURL:    strings.TrimRight(apiBaseURL, "/"),
		httpClient:    &http.Client{Transport: appsTransport},
		installations: newInstallationLookup(time.Now),
		cache:         newTokenCache(time.Now),
	}
	src.logger.Store(slog.Default())
	return src, nil
}

// SetLogger installs logger as the destination for
// security.EventTokenMinted events. Intended to be called once, during
// startup wiring (see cmd/haybale/cmd/serve.go), before the proxy starts
// serving traffic — see the logger field's doc comment for why this
// exists as a post-construction setter rather than a NewGitHubAppSource
// parameter. A nil logger is ignored (the slog.Default() fallback from
// construction is kept) rather than installed, matching internal/proxy.New's
// own "a nil logger falls back to slog.Default()" convention.
func (s *GitHubAppSource) SetLogger(logger *slog.Logger) {
	if logger == nil {
		return
	}
	s.logger.Store(logger)
}

// Credentials implements CredentialSource. It returns a cached, still-valid
// credential when one exists (tokenCache.get, including its
// write-satisfies-read rule) or mints a fresh one scoped to repo and verb.
//
// ctx is passed through unmodified to every network call this makes (the
// installation lookup and the mint POST both use
// http.NewRequestWithContext), honoring whatever deadline the caller set
// — see the CredentialSource interface doc comment for why that matters
// here: the proxy imposes no timeout of its own.
func (s *GitHubAppSource) Credentials(ctx context.Context, repo gitproto.Repo, verb gitproto.Verb) (BasicAuth, error) {
	return s.cache.get(ctx, repo, verb, s.mint)
}

// mint resolves repo's installation ID and mints a fresh installation
// access token scoped to exactly repo and the minimal permission verb
// needs — read gets "contents": "read", write gets "contents": "write",
// and the token is scoped to this one repository via the request's
// repositories field. This is the least-privilege guarantee GitHubAppSource
// exists to enforce: a compromised token from this mint call can act on
// nothing but the single repo/permission it was requested for.
//
// On success it emits security.EventTokenMinted with host/owner/repo/verb
// and the installation ID — never the token itself, in the event or in
// any error this returns.
func (s *GitHubAppSource) mint(ctx context.Context, repo gitproto.Repo, verb gitproto.Verb) (BasicAuth, time.Time, error) {
	installationID, err := s.installations.get(ctx, s.httpClient, s.apiBaseURL, repo.Owner, repo.Name)
	if err != nil {
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: resolve installation for %s/%s: %w", repo.Owner, repo.Name, err)
	}

	permission := "read"
	if verb == gitproto.Write {
		permission = "write"
	}
	reqBody, err := json.Marshal(mintRequest{
		Repositories: []string{repo.Name},
		Permissions:  mintPermissions{Contents: permission},
	})
	if err != nil {
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: encode mint request: %w", err)
	}

	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", s.apiBaseURL, installationID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: build mint request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: mint token: %w", err)
	}
	defer drain(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		// Deliberately not including the response body here: this is an
		// error path an operator will see in logs, and while a real
		// GitHub error body is just a JSON message (never a token), this
		// keeps that guarantee by construction rather than by trusting
		// GitHub's API shape never to change.
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: mint token: unexpected status %d", resp.StatusCode)
	}

	var tokenResp mintResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return BasicAuth{}, time.Time{}, fmt.Errorf("upstream: github app source: decode mint response: %w", err)
	}

	security.Log(s.logger.Load(), security.EventTokenMinted,
		"host", repo.Host, "owner", repo.Owner, "repo", repo.Name, "verb", verb.String(),
		"appID", s.appID, "installationID", installationID)

	return BasicAuth{Username: "x-access-token", Password: tokenResp.Token}, tokenResp.ExpiresAt, nil
}

// mintRequest is the POST /app/installations/{id}/access_tokens request
// body: scoping the minted token to exactly one repository and the
// minimal permission verb needs is the least-privilege guarantee this
// package exists to enforce.
type mintRequest struct {
	Repositories []string        `json:"repositories"`
	Permissions  mintPermissions `json:"permissions"`
}

// mintPermissions is deliberately narrow — only "contents" — since a git
// smart-HTTP clone/push needs nothing else. Requesting a broader
// permission set than this would undermine the whole point of a
// per-request scoped mint.
type mintPermissions struct {
	Contents string `json:"contents"`
}

// mintResponse is the subset of GitHub's installation access token
// response GitHubAppSource needs: the token itself and when it expires.
// Deliberately omits the permissions/repositories fields GitHub also
// echoes back — GitHubAppSource already knows what it asked for and has
// no use for GitHub's copy of it.
type mintResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// installationLookupResponse is the subset of GitHub's "get a repository
// installation" response installationLookup needs.
type installationLookupResponse struct {
	ID int64 `json:"id"`
}

// installationKey identifies the (host, owner, repo) an installation ID
// was resolved for. host is included even though a single
// GitHubAppSource is only ever constructed for one upstream host in
// production (config.go builds one per Upstream) — it costs nothing and
// keeps this cache correct if that ever changes.
type installationKey struct {
	host, owner, repo string
}

// installationEntry is one resolved installation ID plus when that
// resolution should be treated as stale.
type installationEntry struct {
	id        int64
	expiresAt time.Time
}

// installationLookup caches the GET /repos/{owner}/{repo}/installation
// -> installation ID mapping for installationCacheTTL: which
// installation owns a repo is stable, so this is a much longer-lived,
// lower-risk cache than tokenCache's minted tokens. Concurrent lookups
// for the same repo collapse into a single upstream call via
// singleflight, the same pattern tokenCache uses for mints.
type installationLookup struct {
	now func() time.Time

	mu      sync.Mutex
	entries map[installationKey]installationEntry

	group singleflight.Group
}

// newInstallationLookup builds an empty installationLookup using now as
// its clock.
func newInstallationLookup(now func() time.Time) *installationLookup {
	return &installationLookup{
		now:     now,
		entries: make(map[installationKey]installationEntry),
	}
}

// get returns the cached installation ID for (host is implicit in
// client/apiBaseURL, owner, repo) if still fresh, otherwise resolves and
// caches it via a single upstream GET, shared across any concurrent get
// call for the same owner/repo.
func (l *installationLookup) get(ctx context.Context, client *http.Client, apiBaseURL, owner, repo string) (int64, error) {
	key := installationKey{host: apiBaseURL, owner: owner, repo: repo}
	now := l.now()

	l.mu.Lock()
	if e, ok := l.entries[key]; ok && now.Before(e.expiresAt) {
		l.mu.Unlock()
		return e.id, nil
	}
	l.mu.Unlock()

	sfKey := owner + "/" + repo
	v, err, _ := l.group.Do(sfKey, func() (any, error) {
		id, fetchErr := fetchInstallationID(ctx, client, apiBaseURL, owner, repo)
		if fetchErr != nil {
			return int64(0), fetchErr
		}
		l.mu.Lock()
		l.entries[key] = installationEntry{id: id, expiresAt: l.now().Add(installationCacheTTL)}
		l.mu.Unlock()
		return id, nil
	})
	if err != nil {
		return 0, err
	}
	return v.(int64), nil
}

// fetchInstallationID performs the GET /repos/{owner}/{repo}/installation
// call and returns the resolved installation ID.
func fetchInstallationID(ctx context.Context, client *http.Client, apiBaseURL, owner, repo string) (int64, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/installation", apiBaseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("build installation lookup request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("installation lookup: %w", err)
	}
	defer drain(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("installation lookup: unexpected status %d", resp.StatusCode)
	}

	var lookup installationLookupResponse
	if err := json.NewDecoder(resp.Body).Decode(&lookup); err != nil {
		return 0, fmt.Errorf("installation lookup: decode response: %w", err)
	}
	return lookup.ID, nil
}

// drain reads body to EOF and closes it, letting the Transport reuse the
// underlying connection instead of discarding it — the same
// drain-before-close reasoning internal/proxy's modifyResponse already
// documents for the upstream leg of a proxied request.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	_ = body.Close()
}
