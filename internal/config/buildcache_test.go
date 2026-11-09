package config

import (
	"bytes"
	"context"
	"encoding/base64"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
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
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
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
	got, err := c.BuildCache(context.Background(), logger, observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if got == nil {
		t.Fatal("BuildCache returned a nil cache for an enabled block")
	}
	line := logLine(t, buf.String(), "ephemeral key")
	if !strings.Contains(line, "level=INFO") || !strings.Contains(line, "does not survive a restart") {
		t.Errorf("line = %q, want an Info line saying the cache does not survive a restart", line)
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
	got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if strings.Contains(buf.String(), "ephemeral key") {
		t.Errorf("log = %q, want no ephemeral-key notice when keyEnv is set", buf.String())
	}
	line := logLine(t, buf.String(), "response cache enabled")
	if !strings.Contains(line, "keyMode=configured") {
		t.Errorf("line = %q, want keyMode=configured", line)
	}
	// Neither the variable's value nor its base64 form may reach the log.
	for _, secret := range []string{base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key), string(key)} {
		if strings.Contains(buf.String(), secret) {
			t.Errorf("log contains the cache key value %q", secret)
		}
	}
}

// TestBuildCacheLogsTheEffectiveConfiguration confirms a built cache is
// announced at Info with its location, key mode and limits, in both key
// modes.
func TestBuildCacheLogsTheEffectiveConfiguration(t *testing.T) {
	cases := map[string]struct {
		keyEnv  bool
		keyMode string
	}{
		"ephemeral key":  {false, "keyMode=ephemeral"},
		"configured key": {true, "keyMode=configured"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x3c}, cache.KeySize))
			c := enabledCacheConfig(t)
			if tc.keyEnv {
				t.Setenv(testCacheKeyEnv, key)
				c.KeyEnv = testCacheKeyEnv
			}
			var buf bytes.Buffer
			got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
			if err != nil {
				t.Fatalf("BuildCache: %v", err)
			}
			defer closeCache(t, got)

			line := logLine(t, buf.String(), "response cache enabled")
			for _, want := range []string{
				"level=INFO",
				"dir=" + c.Dir,
				tc.keyMode,
				"maxDiskSize=10GiB",
				"maxEntrySize=1GiB",
				"maxConcurrentFills=4",
				"staleIfErrorFor=0s",
			} {
				if !strings.Contains(line, want) {
					t.Errorf("line = %q, want it to contain %q", line, want)
				}
			}
			for _, secret := range []string{key, testCacheKeyEnv} {
				if strings.Contains(buf.String(), secret) {
					t.Errorf("log contains %q, which must never be logged", secret)
				}
			}
		})
	}
}

// TestBuildCacheAnnouncesStaleIfError confirms an enabled stale-if-error
// age reaches the built cache's startup line.
func TestBuildCacheAnnouncesStaleIfError(t *testing.T) {
	c := enabledCacheConfig(t)
	c.StaleIfErrorFor = "2h"
	if err := c.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	var buf bytes.Buffer
	got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
	if err != nil {
		t.Fatalf("BuildCache: %v", err)
	}
	defer closeCache(t, got)
	if line := logLine(t, buf.String(), "response cache enabled"); !strings.Contains(line, "staleIfErrorFor=2h0m0s") {
		t.Errorf("line = %q, want staleIfErrorFor=2h0m0s", line)
	}
}

// TestBuildCacheWarnsWhenFillsCanOutgrowTheDiskBudget confirms the
// oversubscription warning appears when concurrent fills can reserve more
// than the disk budget, and not for the defaults.
func TestBuildCacheWarnsWhenFillsCanOutgrowTheDiskBudget(t *testing.T) {
	const warning = "concurrent fills can reserve more than the disk budget"
	cases := map[string]struct {
		mutate   func(c *CacheConfig)
		wantWarn bool
	}{
		"defaults":                        {func(c *CacheConfig) {}, false},
		"fills exactly fill the budget":   {func(c *CacheConfig) { c.MaxDiskSize, c.MaxEntrySize, c.MaxConcurrentFills = 64*mib, 8*mib, 8 }, false},
		"fills one entry over the budget": {func(c *CacheConfig) { c.MaxDiskSize, c.MaxEntrySize, c.MaxConcurrentFills = 64*mib, 8*mib, 9 }, true},
		"many fills of the default entry": {func(c *CacheConfig) { c.MaxConcurrentFills = 16 }, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := enabledCacheConfig(t)
			tc.mutate(&c)
			if err := c.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			var buf bytes.Buffer
			got, err := c.BuildCache(context.Background(), slog.New(slog.NewTextHandler(&buf, nil)), observability.NewNoopMetrics())
			if err != nil {
				t.Fatalf("BuildCache: %v", err)
			}
			defer closeCache(t, got)

			if !tc.wantWarn {
				if strings.Contains(buf.String(), warning) {
					t.Errorf("log = %q, want no oversubscription warning", buf.String())
				}
				return
			}
			line := logLine(t, buf.String(), warning)
			for _, want := range []string{
				"level=WARN",
				"maxConcurrentFills=" + strconv.Itoa(c.MaxConcurrentFills),
				"maxEntrySize=" + c.MaxEntrySize.String(),
				"maxDiskSize=" + c.MaxDiskSize.String(),
			} {
				if !strings.Contains(line, want) {
					t.Errorf("line = %q, want it to contain %q", line, want)
				}
			}
		})
	}
}

// logLine returns the line of a text-handler log containing substr, and
// fails the test when none does.
func logLine(t *testing.T, log, substr string) string {
	t.Helper()
	for line := range strings.SplitSeq(log, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	t.Fatalf("log = %q, want a line containing %q", log, substr)
	return ""
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
			got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
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
	got, err := c.BuildCache(context.Background(), slog.New(slog.DiscardHandler), observability.NewNoopMetrics())
	if err == nil {
		closeCache(t, got)
		t.Fatal("BuildCache succeeded with a missing parent directory")
	}
	if !strings.Contains(err.Error(), "cache: create dir") {
		t.Errorf("error = %q, want a create-dir error", err)
	}
}
