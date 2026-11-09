package config

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
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
	if c.MaxConcurrentFills != 4 {
		t.Errorf("MaxConcurrentFills = %d, want 4", c.MaxConcurrentFills)
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
	if c.ResponseHeaderTimeout != "60s" {
		t.Errorf("ResponseHeaderTimeout = %q, want 60s", c.ResponseHeaderTimeout)
	}
	if c.IdleTimeout != "2m" {
		t.Errorf("IdleTimeout = %q, want 2m", c.IdleTimeout)
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
	if got := c.ParsedResponseHeaderTimeout(); got != time.Minute {
		t.Errorf("ParsedResponseHeaderTimeout() = %v, want 1m", got)
	}
	if got := c.ParsedIdleTimeout(); got != 2*time.Minute {
		t.Errorf("ParsedIdleTimeout() = %v, want 2m", got)
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
		IdleTimeout:           "30s",
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
				c.IdleTimeout = "0s"
				c.ExposeStatus = true
				c.StaleIfErrorFor = "0s"
			},
		},
		{name: "refsMaxAge with accessRecheck disabled", mutate: func(c *CacheConfig) { c.RefsMaxAge = "1h"; c.AccessRecheck = "0s" }},
		{name: "refsMaxAge below accessRecheck", mutate: func(c *CacheConfig) { c.RefsMaxAge = "4m59s"; c.AccessRecheck = "5m" }},
		{
			name:    "refsMaxAge equal to accessRecheck",
			mutate:  func(c *CacheConfig) { c.RefsMaxAge = "5m"; c.AccessRecheck = "5m" },
			wantErr: "cache: refsMaxAge \"5m\" must be less than accessRecheck",
		},
		{
			name:    "refsMaxAge above accessRecheck",
			mutate:  func(c *CacheConfig) { c.RefsMaxAge = "10m" },
			wantErr: "cache: refsMaxAge \"10m\" must be less than accessRecheck",
		},
		{name: "idleTimeout unparseable", mutate: func(c *CacheConfig) { c.IdleTimeout = "2" }, wantErr: "cache: idleTimeout"},
		{name: "idleTimeout negative", mutate: func(c *CacheConfig) { c.IdleTimeout = "-2m" }, wantErr: "cache: idleTimeout"},
		{name: "empty staleIfErrorFor", mutate: func(c *CacheConfig) { c.StaleIfErrorFor = "" }},
		{name: "empty durations accepted as zero", mutate: func(c *CacheConfig) {
			c.Retention, c.RefsMaxAge, c.AccessRecheck, c.ResponseHeaderTimeout, c.IdleTimeout = "", "", "", "", ""
		}},
		{
			name:    "entry size equal to disk size",
			mutate:  func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize },
			wantErr: "cache: maxEntrySize 10GiB must not exceed half of maxDiskSize 10GiB",
		},
		{
			name:    "entry size just above half the disk size",
			mutate:  func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize/2 + 1 },
			wantErr: "cache: maxEntrySize 5368709121B must not exceed half of maxDiskSize 10GiB",
		},
		{name: "entry size exactly half the disk size", mutate: func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize / 2 }},
		{name: "entry size just below half the disk size", mutate: func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize/2 - 1 }},
		{name: "entry size well below half the disk size", mutate: func(c *CacheConfig) { c.MaxEntrySize = c.MaxDiskSize / 10 }},
		{
			name:    "odd disk size halves rounding down",
			mutate:  func(c *CacheConfig) { c.MaxDiskSize, c.MaxEntrySize = 2*gib+1, gib+1 },
			wantErr: "cache: maxEntrySize 1073741825B must not exceed half of maxDiskSize 2147483649B",
		},
		{name: "odd disk size accepts the rounded-down half", mutate: func(c *CacheConfig) { c.MaxDiskSize, c.MaxEntrySize = 2*gib+1, gib }},
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
		{
			name:    "disk size so large that doubling the entry size would overflow",
			mutate:  func(c *CacheConfig) { c.MaxDiskSize, c.MaxEntrySize = math.MaxInt64, math.MaxInt64/2+1 },
			wantErr: "cache: maxEntrySize",
		},
		{name: "no concurrent fills", mutate: func(c *CacheConfig) { c.MaxConcurrentFills = 0 }, wantErr: "cache: maxConcurrentFills"},
		{name: "negative concurrent fills", mutate: func(c *CacheConfig) { c.MaxConcurrentFills = -3 }, wantErr: "cache: maxConcurrentFills"},
		{name: "zero request body", mutate: func(c *CacheConfig) { c.MaxRequestBody = 0 }, wantErr: "cache: maxRequestBody"},
		{name: "negative request body", mutate: func(c *CacheConfig) { c.MaxRequestBody = -1 }, wantErr: "cache: maxRequestBody"},
		{
			name:    "remote type set",
			mutate:  func(c *CacheConfig) { c.Remote.Type = "s3" },
			wantErr: "cache: remote is not supported in this release",
		},
		{
			name:    "remote bucket set",
			mutate:  func(c *CacheConfig) { c.Remote.Bucket = "haybale-cache" },
			wantErr: "cache: remote is not supported in this release",
		},
		{
			name:    "remote forcePathStyle set",
			mutate:  func(c *CacheConfig) { c.Remote.ForcePathStyle = true },
			wantErr: "cache: remote is not supported in this release",
		},
		{
			name:    "remote kmsKeyID set",
			mutate:  func(c *CacheConfig) { c.Remote.KMSKeyID = "alias/haybale" },
			wantErr: "cache: remote is not supported in this release",
		},
		{
			name:    "staleIfErrorFor enabled",
			mutate:  func(c *CacheConfig) { c.StaleIfErrorFor = "1h" },
			wantErr: "cache: staleIfErrorFor is not supported in this release",
		},
		{name: "staleIfErrorFor zero spelled 0", mutate: func(c *CacheConfig) { c.StaleIfErrorFor = "0" }},
		{name: "staleIfErrorFor zero spelled 0m", mutate: func(c *CacheConfig) { c.StaleIfErrorFor = "0m" }},
		{
			name:    "staleIfErrorFor unparseable",
			mutate:  func(c *CacheConfig) { c.StaleIfErrorFor = "soon" },
			wantErr: "cache: staleIfErrorFor is not supported in this release",
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
  idleTimeout: 45s
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
		c.ParsedAccessRecheck() != 10*time.Minute || c.ParsedResponseHeaderTimeout() != time.Minute ||
		c.ParsedIdleTimeout() != 45*time.Second {
		t.Errorf("parsed durations = %v/%v/%v/%v/%v, want 48h/15s/10m/1m/45s",
			c.ParsedRetention(), c.ParsedRefsMaxAge(), c.ParsedAccessRecheck(), c.ParsedResponseHeaderTimeout(), c.ParsedIdleTimeout())
	}
}

func TestLoadCacheAppliesDefaults(t *testing.T) {
	cfg, err := loadWithCacheBlock(t, "cache:\n  enabled: true\n  dir: /var/cache/haybale\n")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	c := cfg.Cache
	if c.MaxDiskSize != 10*gib || c.MaxEntrySize != gib || c.MaxConcurrentFills != 4 || c.MaxRequestBody != mib {
		t.Errorf("defaults = %s/%s/%d/%s, want 10GiB/1GiB/4/1MiB", c.MaxDiskSize, c.MaxEntrySize, c.MaxConcurrentFills, c.MaxRequestBody)
	}
	if c.ParsedRetention() != 24*time.Hour || c.ParsedAccessRecheck() != 5*time.Minute ||
		c.ParsedResponseHeaderTimeout() != time.Minute || c.ParsedIdleTimeout() != 2*time.Minute {
		t.Errorf("parsed defaults = %v/%v/%v/%v, want 24h/5m/1m/2m",
			c.ParsedRetention(), c.ParsedAccessRecheck(), c.ParsedResponseHeaderTimeout(), c.ParsedIdleTimeout())
	}
}

// TestLoadCacheTreatsZeroSizesAndCountsAsUnset confirms an explicit zero
// selects the default, the same as omitting the field.
func TestLoadCacheTreatsZeroSizesAndCountsAsUnset(t *testing.T) {
	cfg, err := loadWithCacheBlock(t, `
cache:
  enabled: true
  dir: /var/cache/haybale
  maxConcurrentFills: 0
  maxRequestBody: 0MiB
  maxDiskSize: 0GiB
  maxEntrySize: 0GiB
`)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	c := cfg.Cache
	if c.MaxDiskSize != 10*gib || c.MaxEntrySize != gib || c.MaxConcurrentFills != 4 || c.MaxRequestBody != mib {
		t.Errorf("defaults = %s/%s/%d/%s, want 10GiB/1GiB/4/1MiB", c.MaxDiskSize, c.MaxEntrySize, c.MaxConcurrentFills, c.MaxRequestBody)
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
		{"remote block", "cache:\n  enabled: true\n  dir: /c\n  remote:\n    type: s3\n    bucket: b\n", "cache: remote is not supported in this release"},
		{"staleIfErrorFor", "cache:\n  enabled: true\n  dir: /c\n  staleIfErrorFor: 1h\n", "cache: staleIfErrorFor is not supported in this release"},
		{"entry above disk", "cache:\n  enabled: true\n  dir: /c\n  maxDiskSize: 1GiB\n  maxEntrySize: 2GiB\n", "cache: maxEntrySize"},
		{"entry above half of disk", "cache:\n  enabled: true\n  dir: /c\n  maxDiskSize: 2GiB\n  maxEntrySize: 1.5GiB\n", "cache: maxEntrySize 1536MiB must not exceed half of maxDiskSize 2GiB"},
		{"negative retention", "cache:\n  enabled: true\n  dir: /c\n  retention: -1h\n", "cache: retention"},
		{"refsMaxAge not below accessRecheck", "cache:\n  enabled: true\n  dir: /c\n  refsMaxAge: 5m\n", "cache: refsMaxAge"},
		{"unknown key", "cache:\n  enabled: true\n  dir: /c\n  maxDiskSiez: 1GiB\n", `cache: unknown field "maxDiskSiez" (line`},
		{"renamed key", "cache:\n  enabled: true\n  dir: /c\n  timeout: 10s\n", `cache: unknown field "timeout"`},
		{"unknown remote key", "cache:\n  enabled: false\n  remote:\n    timeout: 10s\n", `cache.remote: unknown field "timeout"`},
		{"unknown key in a disabled block", "cache:\n  enabled: false\n  retentoin: 1h\n", `cache: unknown field "retentoin"`},
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

// TestLoadCacheKeyWalkFollowsAliases confirms the unknown-key check sees
// through aliases, merge keys and aliased keys, so no spelling of the
// cache block escapes it.
func TestLoadCacheKeyWalkFollowsAliases(t *testing.T) {
	tests := []struct {
		name    string
		block   string
		wantErr string // substring expected in the error; "" means Load succeeds
		enabled bool   // expected Cache.Enabled on success
	}{
		{
			name: "alias to a mapping with a typo",
			block: `
x-cache: &c
  enabled: true
  dir: /c
  maxDiskSiez: 1GiB
cache: *c
`,
			wantErr: `cache: unknown field "maxDiskSiez" (line`,
		},
		{
			name: "alias to a valid mapping",
			block: `
x-cache: &c
  enabled: true
  dir: /c
cache: *c
`,
			enabled: true,
		},
		{
			name: "anchor nested under another key and reused",
			block: `
shared:
  block: &c
    enabled: true
    dir: /c
    retentoin: 1h
cache: *c
`,
			wantErr: `cache: unknown field "retentoin" (line`,
		},
		{
			name: "anchor nested under another key and reused without a typo",
			block: `
shared:
  block: &c
    enabled: true
    dir: /c
    retention: 1h
cache: *c
`,
			enabled: true,
		},
		{
			name: "aliased remote with an unknown key",
			block: `
x-remote: &r
  timeout: 10s
cache:
  enabled: false
  remote: *r
`,
			wantErr: `cache.remote: unknown field "timeout" (line`,
		},
		{
			name: "aliased remote with known keys in a disabled block",
			block: `
x-remote: &r
  type: s3
cache:
  enabled: false
  remote: *r
`,
		},
		{
			name: "aliased cache block holding an aliased remote with an unknown key",
			block: `
x-remote: &r
  timeout: 10s
x-cache: &c
  enabled: false
  remote: *r
cache: *c
`,
			wantErr: `cache.remote: unknown field "timeout" (line`,
		},
		{
			name: "merge key inside the block",
			block: `
x-base: &base
  enabled: true
  dir: /c
cache:
  <<: *base
  retention: 1h
`,
			wantErr: `cache: unknown field "<<" (line`,
		},
		{
			name: "aliased key naming an unknown field",
			block: `
x-key: &k maxDiskSiez
cache:
  enabled: true
  dir: /c
  *k : 1GiB
`,
			wantErr: `cache: unknown field "maxDiskSiez" (line`,
		},
		{
			name:  "null cache block is disabled",
			block: "cache:\n",
		},
		{
			name:  "explicit null cache block is disabled",
			block: "cache: ~\n",
		},
		{
			name:    "scalar cache block",
			block:   "cache: enabled\n",
			wantErr: "cannot unmarshal",
		},
		{
			name:    "alias to a scalar",
			block:   "x-cache: &c enabled\ncache: *c\n",
			wantErr: "cannot unmarshal",
		},
		{
			name:    "sequence cache block",
			block:   "cache: [enabled]\n",
			wantErr: "cannot unmarshal",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadWithCacheBlock(t, tt.block)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Load() error = %v, want nil", err)
				}
				if cfg.Cache.Enabled != tt.enabled {
					t.Errorf("Cache.Enabled = %v, want %v", cfg.Cache.Enabled, tt.enabled)
				}
				return
			}
			if err == nil {
				t.Fatalf("Load() error = nil, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestResolveAliasStopsAtACycle confirms an alias that refers back to
// itself neither hangs the key walk nor counts as a mapping.
func TestResolveAliasStopsAtACycle(t *testing.T) {
	t.Parallel()
	loop := &yaml.Node{Kind: yaml.AliasNode, Value: "loop"}
	loop.Alias = loop
	if got := resolveAlias(loop); got.Kind != yaml.AliasNode {
		t.Errorf("resolveAlias(cycle).Kind = %v, want the alias node returned unresolved", got.Kind)
	}
	if err := checkKnownKeys(loop, reflect.TypeFor[CacheConfig](), "cache"); err != nil {
		t.Errorf("checkKnownKeys(cycle) error = %v, want nil so the decoder reports it", err)
	}
	if got := mappingValue(loop, "cache"); got != nil {
		t.Errorf("mappingValue(cycle) = %v, want nil", got)
	}
}
