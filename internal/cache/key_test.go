package cache

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/rxbynerd/haybale/internal/gitproto"
)

func TestClassGroup(t *testing.T) {
	tests := []struct {
		class Class
		want  Group
	}{
		{ClassAdvertisement, GroupRefs},
		{ClassLsRefs, GroupRefs},
		{ClassFetch, GroupPack},
		{Class("object-info"), ""},
	}
	for _, tt := range tests {
		if got := tt.class.Group(); got != tt.want {
			t.Errorf("Class(%q).Group() = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestKeyPath(t *testing.T) {
	k := Key{Group: GroupPack, RepoHash: [32]byte{0xab}, KeyHash: [32]byte{31: 0x01}}
	want := "v1/pack/ab" + strings.Repeat("0", 62) + "/" + strings.Repeat("0", 62) + "01"
	if got := k.Path(); got != want {
		t.Errorf("Path() = %q, want %q", got, want)
	}
	pattern := regexp.MustCompile(`^v1/(refs|pack)/[0-9a-f]{64}/[0-9a-f]{64}$`)
	if !pattern.MatchString(Key{Group: GroupRefs}.Path()) {
		t.Errorf("Path() = %q does not match the entry pattern", Key{Group: GroupRefs}.Path())
	}
}

func TestRepoHash(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	github := mustURL(t, "https://github.com")
	repo := gitproto.Repo{Host: "github.com", Owner: "acme", Name: "widgets"}
	base := RepoHash(key, github, repo)

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("https://github.com\nacme/widgets"))
	if want := mac.Sum(nil); !bytes.Equal(base[:], want) {
		t.Errorf("RepoHash() = %x, want HMAC-SHA256 over base URL, newline, owner/name = %x", base, want)
	}
	if again := RepoHash(key, github, repo); again != base {
		t.Error("RepoHash() is not deterministic")
	}
	differs := map[string][32]byte{
		"other cache key":   RepoHash([]byte("another key"), github, repo),
		"other base URL":    RepoHash(key, mustURL(t, "https://ghe.example.com"), repo),
		"base URL path":     RepoHash(key, mustURL(t, "https://github.com/api"), repo),
		"other owner":       RepoHash(key, github, gitproto.Repo{Host: "github.com", Owner: "other", Name: "widgets"}),
		"owner case":        RepoHash(key, github, gitproto.Repo{Host: "github.com", Owner: "Acme", Name: "widgets"}),
		"other repo name":   RepoHash(key, github, gitproto.Repo{Host: "github.com", Owner: "acme", Name: "gadgets"}),
		"name case differs": RepoHash(key, github, gitproto.Repo{Host: "github.com", Owner: "acme", Name: "Widgets"}),
	}
	for name, h := range differs {
		if h == base {
			t.Errorf("%s: same repoHash as the base repository", name)
		}
	}
	if RepoHash(key, github, gitproto.Repo{Host: "alias", Owner: "acme", Name: "widgets"}) != base {
		t.Error("the host key changed the repoHash; only the base URL identifies the upstream")
	}
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", s, err)
	}
	return u
}
