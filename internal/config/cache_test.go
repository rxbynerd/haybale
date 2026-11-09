package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestByteSizeUnmarshalYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    ByteSize
		wantErr string // substring expected in the error; "" means no error
	}{
		{name: "KiB", in: "4KiB", want: 4 * kib},
		{name: "MiB", in: "512MiB", want: 512 * mib},
		{name: "GiB", in: "10GiB", want: 10 * gib},
		{name: "TiB", in: "2TiB", want: 2 * tib},
		{name: "decimal", in: "1.5GiB", want: 3 * gib / 2},
		{name: "decimal KiB", in: "0.5KiB", want: 512},
		{name: "single space before unit", in: "10 GiB", want: 10 * gib},
		{name: "zero", in: "0GiB", want: 0},
		{name: "overflow", in: "8388608TiB", wantErr: "too large"},
		{name: "fraction that is not whole bytes", in: "1.0001KiB", wantErr: "whole number of bytes"},

		{name: "bare integer", in: "1073741824", wantErr: "want <number><unit>"},
		{name: "bare zero", in: "0", wantErr: "want <number><unit>"},
		{name: "SI KB", in: "10KB", wantErr: "want <number><unit>"},
		{name: "SI MB", in: "10MB", wantErr: "want <number><unit>"},
		{name: "SI GB", in: "10GB", wantErr: "want <number><unit>"},
		{name: "byte unit", in: "100B", wantErr: "want <number><unit>"},
		{name: "lowercase unit", in: "10gib", wantErr: "want <number><unit>"},
		{name: "mixed case unit", in: "10Gib", wantErr: "want <number><unit>"},
		{name: "negative", in: "-1GiB", wantErr: "want <number><unit>"},
		{name: "explicit plus", in: "+1GiB", wantErr: "want <number><unit>"},
		{name: "two spaces", in: "10  GiB", wantErr: "want <number><unit>"},
		{name: "leading space", in: `" 10GiB"`, wantErr: "want <number><unit>"},
		{name: "trailing space", in: `"10GiB "`, wantErr: "want <number><unit>"},
		{name: "exponent", in: "1e3MiB", wantErr: "want <number><unit>"},
		{name: "no number", in: "GiB", wantErr: "want <number><unit>"},
		{name: "trailing dot", in: "1.GiB", wantErr: "want <number><unit>"},
		{name: "leading dot", in: ".5GiB", wantErr: "want <number><unit>"},
		{name: "empty", in: `""`, wantErr: "want <number><unit>"},
		{name: "words", in: "lots", wantErr: "want <number><unit>"},
		{name: "sequence", in: "[10GiB]", wantErr: "must be a string"},
		{name: "mapping", in: "{a: 1}", wantErr: "must be a string"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got ByteSize
			err := yaml.Unmarshal([]byte(tt.in), &got)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Unmarshal(%q) error = %v, want nil", tt.in, err)
				}
				if got != tt.want {
					t.Errorf("Unmarshal(%q) = %d, want %d", tt.in, got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatalf("Unmarshal(%q) = %d, want an error containing %q", tt.in, got, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Unmarshal(%q) error = %q, want it to contain %q", tt.in, err.Error(), tt.wantErr)
			}
		})
	}
}

func TestByteSizeLargestRepresentable(t *testing.T) {
	t.Parallel()
	var got ByteSize
	if err := yaml.Unmarshal([]byte("8388607TiB"), &got); err != nil {
		t.Fatalf("Unmarshal(8388607TiB) error = %v, want nil", err)
	}
	if want := 8388607 * tib; got != want {
		t.Errorf("Unmarshal(8388607TiB) = %d, want %d", got, want)
	}
}

func TestByteSizeString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   ByteSize
		want string
	}{
		{0, "0B"},
		{1, "1B"},
		{1500, "1500B"},
		{kib, "1KiB"},
		{1536, "1536B"},
		{2 * kib, "2KiB"},
		{mib, "1MiB"},
		{1536 * kib, "1536KiB"},
		{gib, "1GiB"},
		{10 * gib, "10GiB"},
		{1536 * mib, "1536MiB"},
		{tib, "1TiB"},
		{3 * tib, "3TiB"},
		{-1, "-1B"},
	}
	for _, tt := range tests {
		if got := tt.in.String(); got != tt.want {
			t.Errorf("ByteSize(%d).String() = %q, want %q", int64(tt.in), got, tt.want)
		}
	}
}

// TestByteSizeStringRoundTrips confirms String's output for any whole
// number of KiB parses back to the same value.
func TestByteSizeStringRoundTrips(t *testing.T) {
	t.Parallel()
	for _, in := range []ByteSize{kib, 3 * kib, mib, 1536 * kib, gib, 10 * gib, 1536 * mib, tib, 5 * tib} {
		var got ByteSize
		if err := yaml.Unmarshal([]byte(in.String()), &got); err != nil {
			t.Fatalf("Unmarshal(%q) error = %v", in.String(), err)
		}
		if got != in {
			t.Errorf("round trip of %d via %q = %d", int64(in), in.String(), got)
		}
	}
}

// validCacheConfig returns an enabled CacheConfig that validate accepts,
// with defaults already applied.
func validCacheConfig() CacheConfig {
	c := CacheConfig{Enabled: true, Dir: "/var/cache/haybale"}
	c.applyDefaults()
	return c
}

func TestCacheConfigApplyDefaults(t *testing.T) {
	t.Parallel()
	c := CacheConfig{Enabled: true, Dir: "/var/cache/haybale"}
	c.applyDefaults()

	if c.MaxDiskSize != 10*gib {
		t.Errorf("MaxDiskSize = %s, want 10GiB", c.MaxDiskSize)
	}
	if c.MaxEntrySize != gib {
		t.Errorf("MaxEntrySize = %s, want 1GiB", c.MaxEntrySize)
	}
	if c.MaxConcurrentFills != 32 {
		t.Errorf("MaxConcurrentFills = %d, want 32", c.MaxConcurrentFills)
	}
	if c.MaxRequestBody != mib {
		t.Errorf("MaxRequestBody = %s, want 1MiB", c.MaxRequestBody)
	}
	if c.Retention != "24h" {
		t.Errorf("Retention = %q, want 24h", c.Retention)
	}
	if c.RefsMaxAge != "0s" {
		t.Errorf("RefsMaxAge = %q, want 0s", c.RefsMaxAge)
	}
	if c.AccessRecheck != "5m" {
		t.Errorf("AccessRecheck = %q, want 5m", c.AccessRecheck)
	}
	if c.ResponseHeaderTimeout != "0s" {
		t.Errorf("ResponseHeaderTimeout = %q, want 0s", c.ResponseHeaderTimeout)
	}
	if c.ExposeStatus {
		t.Error("ExposeStatus = true, want false")
	}
	if err := c.validate(); err != nil {
		t.Fatalf("validate() on defaulted block error = %v, want nil", err)
	}
	if got := c.ParsedRetention(); got != 24*time.Hour {
		t.Errorf("ParsedRetention() = %v, want 24h", got)
	}
	if got := c.ParsedRefsMaxAge(); got != 0 {
		t.Errorf("ParsedRefsMaxAge() = %v, want 0", got)
	}
	if got := c.ParsedAccessRecheck(); got != 5*time.Minute {
		t.Errorf("ParsedAccessRecheck() = %v, want 5m", got)
	}
	if got := c.ParsedResponseHeaderTimeout(); got != 0 {
		t.Errorf("ParsedResponseHeaderTimeout() = %v, want 0", got)
	}
}

func TestCacheConfigApplyDefaultsKeepsExplicitValues(t *testing.T) {
	t.Parallel()
	c := CacheConfig{
		Enabled:               true,
		Dir:                   "/c",
		MaxDiskSize:           2 * gib,
		MaxEntrySize:          512 * mib,
		MaxConcurrentFills:    4,
		MaxRequestBody:        64 * kib,
		Retention:             "1h",
		RefsMaxAge:            "10s",
		AccessRecheck:         "1m",
		ResponseHeaderTimeout: "60s",
	}
	want := c
	c.applyDefaults()
	if c != want {
		t.Errorf("applyDefaults changed explicit values:\n got  %+v\n want %+v", c, want)
	}
}

func TestCacheConfigDisabledStaysInert(t *testing.T) {
	t.Parallel()
	c := CacheConfig{}
	c.applyDefaults()
	if c != (CacheConfig{}) {
		t.Errorf("applyDefaults on a disabled block changed it: %+v", c)
	}

	// A disabled block is valid whatever else it holds, including values
	// an enabled block would reject.
	junk := CacheConfig{
		Retention:          "nonsense",
		MaxConcurrentFills: -1,
		Remote:             RemoteCacheConfig{Type: "s3"},
		StaleIfErrorFor:    "1h",
	}
	if err := junk.validate(); err != nil {
		t.Errorf("validate() on a disabled block error = %v, want nil", err)
	}
}

func TestCacheConfigValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(c *CacheConfig)
		wantErr string // substring expected in the error; "" means no error
	}{
		{name: "defaults are valid", mutate: func(c *CacheConfig) {}},
		{
			name: "fully specified",
			mutate: func(c *CacheConfig) {
				c.KeyEnv = "HAYBALE_CACHE_KEY"
				c.MaxDiskSize = 20 * gib
				c.MaxEntrySize = 2 * gib
				c.MaxConcurrentFills = 8
				c.MaxRequestBody = 256 * kib
				c.Retention = "48h"
				c.RefsMaxAge = "30s"
				c.AccessRecheck = "10m"
				c.ResponseHeaderTimeout = "60s"
				c.ExposeStatus = true
				c.StaleIfErrorFor = "0s"
			},
		},
		{name: "empty staleIfErrorFor", mutate: func(c *CacheConfig) { c.StaleIfErrorFor = "" }},
		{name: "empty durations accepted as zero", mutate: func(c *CacheConfig) {
			c.Retention, c.RefsMaxAge, c.AccessRecheck, c.ResponseHeaderTimeout = "", "", "", ""
		}},
		{name: "entry size equal to disk size", mutate: func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize }},
		{name: "dir required", mutate: func(c *CacheConfig) { c.Dir = "" }, wantErr: "cache: dir is required"},
		{name: "retention unparseable", mutate: func(c *CacheConfig) { c.Retention = "a day" }, wantErr: "cache: retention"},
		{name: "retention negative", mutate: func(c *CacheConfig) { c.Retention = "-1h" }, wantErr: "cache: retention"},
		{name: "refsMaxAge unparseable", mutate: func(c *CacheConfig) { c.RefsMaxAge = "1d" }, wantErr: "cache: refsMaxAge"},
		{name: "refsMaxAge negative", mutate: func(c *CacheConfig) { c.RefsMaxAge = "-1s" }, wantErr: "cache: refsMaxAge"},
		{name: "accessRecheck unparseable", mutate: func(c *CacheConfig) { c.AccessRecheck = "five" }, wantErr: "cache: accessRecheck"},
		{name: "accessRecheck negative", mutate: func(c *CacheConfig) { c.AccessRecheck = "-5m" }, wantErr: "cache: accessRecheck"},
		{name: "responseHeaderTimeout unparseable", mutate: func(c *CacheConfig) { c.ResponseHeaderTimeout = "60" }, wantErr: "cache: responseHeaderTimeout"},
		{name: "responseHeaderTimeout negative", mutate: func(c *CacheConfig) { c.ResponseHeaderTimeout = "-60s" }, wantErr: "cache: responseHeaderTimeout"},
		{
			name:    "entry size above disk size",
			mutate:  func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize + 1 },
			wantErr: "cache: maxEntrySize",
		},
		{name: "no concurrent fills", mutate: func(c *CacheConfig) { c.MaxConcurrentFills = 0 }, wantErr: "cache: maxConcurrentFills"},
		{name: "negative concurrent fills", mutate: func(c *CacheConfig) { c.MaxConcurrentFills = -3 }, wantErr: "cache: maxConcurrentFills"},
		{name: "zero request body", mutate: func(c *CacheConfig) { c.MaxRequestBody = 0 }, wantErr: "cache: maxRequestBody"},
		{name: "negative request body", mutate: func(c *CacheConfig) { c.MaxRequestBody = -1 }, wantErr: "cache: maxRequestBody"},
		{
			name:    "remote type set",
			mutate:  func(c *CacheConfig) { c.Remote.Type = "s3" },
			wantErr: "cache.remote is not supported in this release",
		},
		{
			name:    "remote bucket set",
			mutate:  func(c *CacheConfig) { c.Remote.Bucket = "haybale-cache" },
			wantErr: "cache.remote is not supported in this release",
		},
		{
			name:    "remote forcePathStyle set",
			mutate:  func(c *CacheConfig) { c.Remote.ForcePathStyle = true },
			wantErr: "cache.remote is not supported in this release",
		},
		{
			name:    "remote kmsKeyID set",
			mutate:  func(c *CacheConfig) { c.Remote.KMSKeyID = "alias/haybale" },
			wantErr: "cache.remote is not supported in this release",
		},
		{
			name:    "staleIfErrorFor enabled",
			mutate:  func(c *CacheConfig) { c.StaleIfErrorFor = "1h" },
			wantErr: "cache.staleIfErrorFor is not supported in this release",
		},
		{
			name:    "staleIfErrorFor other zero spelling",
			mutate:  func(c *CacheConfig) { c.StaleIfErrorFor = "0" },
			wantErr: "cache.staleIfErrorFor is not supported in this release",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c := validCacheConfig()
			tt.mutate(&c)
			err := c.validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate() error = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validate() error = nil, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCacheConfigValidatePopulatesParsedDurations(t *testing.T) {
	t.Parallel()
	c := validCacheConfig()
	c.Retention = "36h"
	c.RefsMaxAge = "45s"
	c.AccessRecheck = "90s"
	c.ResponseHeaderTimeout = "2m"
	if err := c.validate(); err != nil {
		t.Fatalf("validate() error = %v, want nil", err)
	}
	if got := c.ParsedRetention(); got != 36*time.Hour {
		t.Errorf("ParsedRetention() = %v, want 36h", got)
	}
	if got := c.ParsedRefsMaxAge(); got != 45*time.Second {
		t.Errorf("ParsedRefsMaxAge() = %v, want 45s", got)
	}
	if got := c.ParsedAccessRecheck(); got != 90*time.Second {
		t.Errorf("ParsedAccessRecheck() = %v, want 90s", got)
	}
	if got := c.ParsedResponseHeaderTimeout(); got != 2*time.Minute {
		t.Errorf("ParsedResponseHeaderTimeout() = %v, want 2m", got)
	}
}

// loadWithCacheBlock writes a minimal valid haybale.yaml with cacheYAML
// appended as top-level content and loads it through Load, the path
// `haybale policy check` and `haybale serve` share.
func loadWithCacheBlock(t *testing.T, cacheYAML string) (*Config, error) {
	t.Helper()
	t.Setenv(testTokenEnv, testTokenEnvValue)
	identityPath, policyPath := writeValidIdentityAndPolicyFiles(t)
	path := filepath.Join(t.TempDir(), "haybale.yaml")
	content := `
identity:
  type: jwt
  issuers:
    - issuer: https://issuer.example
      jwksFile: ` + identityPath + `
      audiences: [https://haybale.internal]
      identityTemplate: "{sub}"
policy:
  path: ` + policyPath + `
upstreams:
  - host: github.com
    baseURL: https://github.com
    credential: { type: static, tokenEnv: ` + testTokenEnv + ` }
` + cacheYAML
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}
	return Load(path)
}

func TestLoadCacheFullBlock(t *testing.T) {
	cfg, err := loadWithCacheBlock(t, `
cache:
  enabled: true
  dir: /var/cache/haybale
  keyEnv: HAYBALE_CACHE_KEY
  maxDiskSize: 20GiB
  maxEntrySize: 2GiB
  maxConcurrentFills: 16
  maxRequestBody: 512KiB
  retention: 48h
  refsMaxAge: 15s
  accessRecheck: 10m
  responseHeaderTimeout: 60s
  exposeStatus: true
  staleIfErrorFor: 0s
`)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	c := cfg.Cache
	if !c.Enabled || c.Dir != "/var/cache/haybale" || c.KeyEnv != "HAYBALE_CACHE_KEY" || !c.ExposeStatus {
		t.Errorf("Cache = %+v, want enabled with dir, keyEnv and exposeStatus", c)
	}
	if c.MaxDiskSize != 20*gib || c.MaxEntrySize != 2*gib || c.MaxRequestBody != 512*kib {
		t.Errorf("sizes = %s/%s/%s, want 20GiB/2GiB/512KiB", c.MaxDiskSize, c.MaxEntrySize, c.MaxRequestBody)
	}
	if c.MaxConcurrentFills != 16 {
		t.Errorf("MaxConcurrentFills = %d, want 16", c.MaxConcurrentFills)
	}
	if c.ParsedRetention() != 48*time.Hour || c.ParsedRefsMaxAge() != 15*time.Second ||
		c.ParsedAccessRecheck() != 10*time.Minute || c.ParsedResponseHeaderTimeout() != time.Minute {
		t.Errorf("parsed durations = %v/%v/%v/%v, want 48h/15s/10m/1m",
			c.ParsedRetention(), c.ParsedRefsMaxAge(), c.ParsedAccessRecheck(), c.ParsedResponseHeaderTimeout())
	}
}

func TestLoadCacheAppliesDefaults(t *testing.T) {
	cfg, err := loadWithCacheBlock(t, "cache:\n  enabled: true\n  dir: /var/cache/haybale\n")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	c := cfg.Cache
	if c.MaxDiskSize != 10*gib || c.MaxEntrySize != gib || c.MaxConcurrentFills != 32 || c.MaxRequestBody != mib {
		t.Errorf("defaults = %s/%s/%d/%s, want 10GiB/1GiB/32/1MiB", c.MaxDiskSize, c.MaxEntrySize, c.MaxConcurrentFills, c.MaxRequestBody)
	}
	if c.ParsedRetention() != 24*time.Hour || c.ParsedAccessRecheck() != 5*time.Minute {
		t.Errorf("parsed retention/accessRecheck = %v/%v, want 24h/5m", c.ParsedRetention(), c.ParsedAccessRecheck())
	}
}

// TestLoadCacheIsOffByDefault confirms a config with no cache block, and
// one with enabled: false, load with an inert, undefaulted cache.
func TestLoadCacheIsOffByDefault(t *testing.T) {
	for name, block := range map[string]string{
		"absent":          "",
		"explicitly off":  "cache:\n  enabled: false\n  maxDiskSize: 1GiB\n",
		"off with a stub": "cache:\n  dir: /nowhere\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := loadWithCacheBlock(t, block)
			if err != nil {
				t.Fatalf("Load() error = %v, want nil", err)
			}
			if cfg.Cache.Enabled {
				t.Error("Cache.Enabled = true, want false")
			}
			if cfg.Cache.MaxConcurrentFills != 0 || cfg.Cache.Retention != "" {
				t.Errorf("disabled Cache received defaults: %+v", cfg.Cache)
			}
		})
	}
}

// TestLoadCacheNeedsNoEnvironmentOrFilesystem confirms Load, the path
// `haybale policy check` uses, succeeds with a cache block whose key
// variable is unset and whose directory does not exist.
func TestLoadCacheNeedsNoEnvironmentOrFilesystem(t *testing.T) {
	const keyEnv = "HAYBALE_CONFIG_TEST_CACHE_KEY_UNSET"
	if _, ok := os.LookupEnv(keyEnv); ok {
		t.Fatalf("%s is set in the test environment", keyEnv)
	}
	missingDir := filepath.Join(t.TempDir(), "does", "not", "exist")
	if _, err := loadWithCacheBlock(t, "cache:\n  enabled: true\n  dir: "+missingDir+"\n  keyEnv: "+keyEnv+"\n"); err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
}

func TestLoadCacheRejections(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string
	}{
		{"bare integer size", "cache:\n  enabled: true\n  dir: /c\n  maxDiskSize: 1073741824\n", `size "1073741824" is invalid`},
		{"SI size", "cache:\n  enabled: true\n  dir: /c\n  maxEntrySize: 1GB\n", `size "1GB" is invalid`},
		{"missing dir", "cache:\n  enabled: true\n", "cache: dir is required"},
		{"remote block", "cache:\n  enabled: true\n  dir: /c\n  remote:\n    type: s3\n    bucket: b\n", "cache.remote is not supported in this release"},
		{"staleIfErrorFor", "cache:\n  enabled: true\n  dir: /c\n  staleIfErrorFor: 1h\n", "cache.staleIfErrorFor is not supported in this release"},
		{"entry above disk", "cache:\n  enabled: true\n  dir: /c\n  maxDiskSize: 1GiB\n  maxEntrySize: 2GiB\n", "cache: maxEntrySize"},
		{"negative retention", "cache:\n  enabled: true\n  dir: /c\n  retention: -1h\n", "cache: retention"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadWithCacheBlock(t, tt.block)
			if err == nil {
				t.Fatalf("Load() error = nil, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestCacheConfigRejectsZeroRetention(t *testing.T) {
	cfg := CacheConfig{Enabled: true, Dir: t.TempDir(), Retention: "0s"}
	cfg.applyDefaults()
	err := cfg.validate()
	if err == nil || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("validate() error = %v, want a retention error", err)
	}
}
