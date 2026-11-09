package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rxbynerd/haybale/internal/cache"
	"github.com/rxbynerd/haybale/internal/observability"
)

// testCacheKeyEnv is the environment variable BuildCache tests point
// keyEnv at.
const testCacheKeyEnv = "HAYBALE_CONFIG_TEST_CACHE_KEY" //nolint:gosec // G101: an environment-variable name, not a credential value

// enabledCacheConfig returns a validated, enabled block on a fresh
// directory under t.TempDir.
func enabledCacheConfig(t *testing.T) CacheConfig {
	t.Helper()
	c := CacheConfig{Enabled: true, Dir: filepath.Join(t.TempDir(), "cache")}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return c
}

func closeCache(t *testing.T, c *cache.Cache) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestBuildCacheDisabledReturnsNil(t *testing.T) {
	c := CacheConfig{}
	got, err := c.BuildCache(slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err != nil || got != nil {
		t.Fatalf("BuildCache on a disabled block = %v, %v; want nil, nil", got, err)
	}
}

// TestBuildCacheEphemeralKeyLogsThatEntriesDoNotSurviveRestart confirms a
// block without keyEnv builds a working cache under a generated key and
// says so at Info level.
func TestBuildCacheEphemeralKeyLogsThatEntriesDoNotSurviveRestart(t *testing.T) {
	c := enabledCacheConfig(t)
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	got, err := c.BuildCache(logger, observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if got == nil {
		t.Fatal("BuildCache returned a nil cache for an enabled block")
	}
	if log := buf.String(); !strings.Contains(log, "level=INFO") || !strings.Contains(log, "will not survive a restart") {
		t.Errorf("log = %q, want an Info line saying the cache will not survive a restart", log)
	}
	if info, err := os.Stat(c.Dir); err != nil || !info.IsDir() {
		t.Errorf("cache directory was not created: %v", err)
	}
}

func TestBuildCacheReadsTheKeyFromTheEnvironment(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, cache.KeySize)
	t.Setenv(testCacheKeyEnv, base64.StdEncoding.EncodeToString(key))
	c := enabledCacheConfig(t)
	c.KeyEnv = testCacheKeyEnv
	var buf bytes.Buffer
	got, err := c.BuildCache(slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if strings.Contains(buf.String(), "ephemeral") {
		t.Errorf("log = %q, want no ephemeral-key notice when keyEnv is set", buf.String())
	}
}

func TestBuildCacheRejectsBadKeys(t *testing.T) {
	const secret = "not-a-valid-key-value" //nolint:gosec // G101: an invalid value the test asserts is never echoed
	cases := map[string]struct {
		set     bool
		value   string
		wantErr string
	}{
		"unset":  {false, "", "is unset or empty"},
		"empty":  {true, "", "is unset or empty"},
		"short":  {true, base64.StdEncoding.EncodeToString([]byte("too short")), "must decode to 32 bytes"},
		"garble": {true, secret, "not valid base64"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.set {
				t.Setenv(testCacheKeyEnv, tc.value)
			} else if _, ok := os.LookupEnv(testCacheKeyEnv); ok {
				t.Fatalf("%s is set in the test environment", testCacheKeyEnv)
			}
			c := enabledCacheConfig(t)
			c.KeyEnv = testCacheKeyEnv
			got, err := c.BuildCache(slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
			if err == nil {
				closeCache(t, got)
				t.Fatalf("BuildCache succeeded, want an error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) || !strings.Contains(err.Error(), testCacheKeyEnv) {
				t.Errorf("error = %q, want it to name %s and contain %q", err, testCacheKeyEnv, tc.wantErr)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error = %q, must never include the variable's value", err)
			}
		})
	}
}

func TestBuildCacheRejectsAnUnusableDirectory(t *testing.T) {
	c := enabledCacheConfig(t)
	c.Dir = filepath.Join(c.Dir, "missing-parent", "cache")
	got, err := c.BuildCache(slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err == nil {
		closeCache(t, got)
		t.Fatal("BuildCache succeeded with a missing parent directory")
	}
	if !strings.Contains(err.Error(), "cache: create dir") {
		t.Errorf("error = %q, want a create-dir error", err)
	}
}
