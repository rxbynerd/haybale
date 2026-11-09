package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/pktline"
)

// proxyPath is one of the two ways a read reaches upstream: the
// passthrough reverse proxy, or the response cache's fetcher.
type proxyPath struct {
	name    string
	options func(t *testing.T) []Option
}

// proxyPaths lists both paths so that every credential-boundary invariant
// is asserted on each.
func proxyPaths() []proxyPath {
	return []proxyPath{
		{name: "passthrough", options: func(*testing.T) []Option { return nil }},
		{name: "cache", options: func(t *testing.T) []Option { return []Option{WithCache(newProxyCache(t, false))} }},
	}
}

// newProxyCache opens a small response cache on a fresh directory with an
// ephemeral key. refsMaxAge is set so that a repeated advertisement can
// be served as a hit.
func newProxyCache(t *testing.T, exposeStatus bool) *cache.Cache {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kr, err := cache.EphemeralKeyring()
	if err != nil {
		t.Fatal(err)
	}
	c, err := cache.New(cache.Options{
		Dir:                dir,
		Keyring:            kr,
		MaxDiskSize:        16 << 20,
		MaxEntrySize:       4 << 20,
		MaxConcurrentFills: 2,
		MaxRequestBody:     1 << 20,
		Retention:          time.Hour,
		RefsMaxAge:         time.Minute,
		ExposeStatus:       exposeStatus,
	})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Close(ctx); err != nil {
			t.Errorf("cache.Close: %v", err)
		}
	})
	return c
}

// pkt encodes parts as a pkt-line stream: a string becomes a data packet
// and a pktline.Kind the corresponding special packet.
func pkt(t *testing.T, parts ...any) string {
	t.Helper()
	var out []byte
	var err error
	for _, part := range parts {
		switch v := part.(type) {
		case string:
			out, err = pktline.AppendData(out, []byte(v))
		case pktline.Kind:
			out, err = pktline.AppendPacket(out, pktline.Packet{Kind: v})
		default:
			t.Fatalf("pkt: unsupported part %T", part)
		}
		if err != nil {
			t.Fatalf("pkt: %v", err)
		}
	}
	return string(out)
}

// TestClientXForwardedHeadersAreSuppressed pins the intentional security
// posture documented on rewrite(): haybale must never inject client
// IP/host/proto upstream, on either path. A client-supplied
// X-Forwarded-For (or X-Forwarded-Host/X-Forwarded-Proto) must not reach
// the upstream — neither the client's original value nor a
// haybale-originated replacement.
func TestClientXForwardedHeadersAreSuppressed(t *testing.T) {
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			up := &recordingUpstream{}
			upstreamSrv := httptest.NewServer(up.handler())
			defer upstreamSrv.Close()

			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), path.options(t)...)
			srv := httptest.NewServer(p)
			defer srv.Close()

			req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("X-Forwarded-For", "203.0.113.7")
			req.Header.Set("X-Forwarded-Host", "attacker.example")
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("Forwarded", "for=203.0.113.7")

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}

			_, _, _, headers, _ := up.snapshot()
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded"} {
				if got := headers.Get(h); got != "" {
					t.Errorf("upstream saw %s = %q, want it absent", h, got)
				}
			}
		})
	}
}

// TestInboundAuthorizationHeaderIsReplacedByInjectedCredential confirms
// the client's inbound Authorization header — whether presented as HTTP
// Basic or as an `Authorization: Bearer <token>` header — never reaches
// the upstream on either path. httputil.ReverseProxy only strips the RFC
// hop-by-hop header set by default, and Authorization is end-to-end, not
// hop-by-hop, so without an explicit strip it clones straight through,
// letting anything with visibility into the upstream leg replay the
// haybale credential directly against haybale itself. The cache's
// fetcher builds its request from scratch and must inject the same
// credential.
func TestInboundAuthorizationHeaderIsReplacedByInjectedCredential(t *testing.T) {
	auths := []struct {
		name    string
		setAuth func(*http.Request)
	}{
		{
			name: "basic auth",
			setAuth: func(r *http.Request) {
				r.SetBasicAuth("ignored-username", "haybale-secret-token")
			},
		},
		{
			name: "bearer token",
			setAuth: func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer haybale-secret-token")
			},
		},
	}

	for _, path := range proxyPaths() {
		for _, tt := range auths {
			t.Run(path.name+"/"+tt.name, func(t *testing.T) {
				up := &recordingUpstream{}
				upstreamSrv := httptest.NewServer(up.handler())
				defer upstreamSrv.Close()

				p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), path.options(t)...)
				srv := httptest.NewServer(p)
				defer srv.Close()

				req, err := http.NewRequest(http.MethodGet, srv.URL+"/testhost/acme/widgets.git/info/refs?service=git-upload-pack", nil)
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				tt.setAuth(req)

				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				_, _ = io.Copy(io.Discard, resp.Body)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d, want 200", resp.StatusCode)
				}

				_, _, _, headers, _ := up.snapshot()
				if got := headers.Values("Authorization"); len(got) != 1 {
					t.Fatalf("upstream saw %d Authorization headers, want exactly one: %q", len(got), got)
				}
				got := headers.Get("Authorization")
				if strings.Contains(got, "haybale-secret-token") {
					t.Errorf("upstream saw Authorization = %q, must never contain the client's haybale token", got)
				}
				wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(defaultTestCredential.Username+":"+defaultTestCredential.Password))
				if got != wantAuth {
					t.Errorf("upstream saw Authorization = %q, want the injected credential %q", got, wantAuth)
				}
			})
		}
	}
}

// TestPostInjectionUpstreamRejectionMaps502 confirms that a 401 or 403
// from upstream — which arrives strictly after haybale's own credential
// was injected, so it means the upstream rejected that credential, not
// something the client did — becomes a 502 on both paths. It must never
// surface as an ordinary 401 (which would make git re-prompt for a
// credential the sandbox has no way to supply), and the response headers
// must be reset wholesale rather than selectively deleted: a compromised,
// misconfigured or lookalike upstream could set Set-Cookie or any other
// header on its 401/403 page, and none of it may survive onto the
// synthetic 502. The upstream_auth_failed security event is logged with
// the upstream's status and never with the injected credential.
func TestPostInjectionUpstreamRejectionMaps502(t *testing.T) {
	for _, path := range proxyPaths() {
		for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			t.Run(path.name+"/"+strconv.Itoa(status), func(t *testing.T) {
				upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("WWW-Authenticate", `Basic realm="upstream"`)
					w.Header().Set("Set-Cookie", "session=upstream-secret-cookie; Path=/")
					w.Header().Set("X-Upstream-Custom", "must-not-leak")
					w.WriteHeader(status)
					_, _ = w.Write([]byte("upstream error body containing details that must never reach the client"))
				}))
				defer upstreamSrv.Close()

				buf := &syncBuffer{}
				logger := slog.New(slog.NewJSONHandler(buf, nil))
				p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, logger, path.options(t)...)
				srv := httptest.NewServer(p)
				defer srv.Close()

				resp, err := http.Get(srv.URL + "/testhost/acme/widgets.git/info/refs?service=git-upload-pack")
				if err != nil {
					t.Fatalf("GET: %v", err)
				}
				defer func() { _ = resp.Body.Close() }()
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}

				if resp.StatusCode != http.StatusBadGateway {
					t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
				}
				for _, h := range []string{"WWW-Authenticate", "Set-Cookie", "X-Upstream-Custom"} {
					if got := resp.Header.Get(h); got != "" {
						t.Errorf("%s = %q, want it stripped from the synthetic 502", h, got)
					}
				}
				if strings.Contains(string(body), "upstream error body") || strings.Contains(string(body), "must-not-leak") {
					t.Errorf("response body = %q, must not contain any upstream-controlled content", body)
				}

				line := strings.Join(waitForLogLines(t, buf, 1), "\n")
				for _, want := range []string{
					`"event":"upstream_auth_failed"`,
					`"host":"testhost"`,
					`"owner":"acme"`,
					`"repo":"widgets"`,
					`"verb":"read"`,
					`"upstreamStatus":` + strconv.Itoa(status),
				} {
					if !strings.Contains(line, want) {
						t.Errorf("log output = %q, want it to contain %q", line, want)
					}
				}
				if strings.Contains(line, defaultTestCredential.Password) {
					t.Errorf("log output = %q, must never contain the injected credential", line)
				}
			})
		}
	}
}

// TestPostInjectionUpstream401DrainsBodyForConnectionReuse confirms the
// discarded upstream 401 body is drained to EOF before its reader is
// closed on both paths, so the shared Transport can return the
// proxy->upstream connection to its keep-alive pool. net/http treats a
// response body that is closed before being read to completion as
// unreusable and redials on the next request — a bad or expired
// credential is a sustained failure mode (every request to this upstream
// repeats it), so this matters most exactly when it's least convenient.
// Verified indirectly: the upstream's ConnState hook counts how many
// distinct TCP connections it accepts across two sequential requests
// through the same Proxy (and therefore the same underlying Transport).
func TestPostInjectionUpstream401DrainsBodyForConnectionReuse(t *testing.T) {
	for _, path := range proxyPaths() {
		t.Run(path.name, func(t *testing.T) {
			var newConns atomic.Int32
			upstreamSrv := httptest.NewUnstartedServer(respondingUpstreamHandler(http.StatusUnauthorized, true))
			upstreamSrv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
				if state == http.StateNew {
					newConns.Add(1)
				}
			}
			upstreamSrv.Start()
			defer upstreamSrv.Close()

			p := mustNew(t, newUpstreamMap(t, map[string]string{"testhost": upstreamSrv.URL}), allowAllAuthenticator{}, allowAllPolicy{}, discardLogger(), path.options(t)...)
			srv := httptest.NewServer(p)
			defer srv.Close()

			// Two different repositories, so the cache path cannot serve
			// the second from the first's shared response.
			for i, repo := range []string{"widgets", "gadgets"} {
				resp, err := http.Get(srv.URL + "/testhost/acme/" + repo + ".git/info/refs?service=git-upload-pack")
				if err != nil {
					t.Fatalf("GET %d: %v", i, err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusBadGateway {
					t.Fatalf("request %d status = %d, want %d", i, resp.StatusCode, http.StatusBadGateway)
				}
			}

			if got := newConns.Load(); got != 1 {
				t.Errorf("upstream accepted %d new TCP connections for 2 sequential requests, want 1 — the discarded 401 body must be drained so the shared Transport can reuse the connection", got)
			}
		})
	}
}
